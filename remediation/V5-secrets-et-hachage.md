# V5 — Secrets codés en dur et hachage de mots de passe insuffisant

| Champ | Valeur |
|---|---|
| **Identifiant** | V5 |
| **Composant** | `lib/insecurity.ts` — clé de signature JWT et fonction `hash()` |
| **CWE** | CWE-798 — *Use of Hard-coded Credentials* ; CWE-916 — *Use of Password Hash With Insufficient Computational Effort* ; CWE-321 — *Use of Hard-coded Cryptographic Key* |
| **OWASP Top 10** | A02:2021 — Cryptographic Failures ; A07:2021 — Identification and Authentication Failures |
| **Sévérité** | **Critical** (CVSS 3.1 : 9.1) |
| **Détecté par** | Secret Detection (Gitleaks — règles `jwt-signing-secret`, `weak-hash-md5`) + SAST Semgrep |

## 1. Cause

Deux faiblesses cryptographiques cumulées dans le même fichier :

1. **Clé privée RSA / secret de signature JWT versionnés dans le dépôt Git.** Toute
   personne ayant accès au code — ou à l'historique Git, même après suppression du
   fichier — peut **forger un JWT valide** pour n'importe quel compte, y compris
   `admin`, sans jamais connaître de mot de passe.
2. **Mots de passe hachés en MD5 sans sel.** MD5 est rapide (plusieurs milliards de
   condensats par seconde sur GPU) et sans sel : un mot de passe courant est retrouvé
   instantanément par table arc-en-ciel, et deux utilisateurs ayant le même mot de passe
   produisent le même condensat.

```typescript
// CODE VULNÉRABLE — lib/insecurity.ts
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDNwqL...'

export const hash = (data: string) =>
  crypto.createHash('md5').update(data).digest('hex')

export const authorize = (user = {}) =>
  jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
```

## 2. Correction proposée

**a) Externaliser les secrets** — aucun secret dans le code ni dans l'historique :

```typescript
// CODE CORRIGÉ — lib/insecurity.ts
const privateKey = process.env.JWT_PRIVATE_KEY
if (!privateKey) {
  throw new Error('JWT_PRIVATE_KEY manquante : demarrage refuse')  // fail-fast
}
```

```bash
# .env  (ajoute au .gitignore, jamais versionne)
JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----..."
```

En production : gestionnaire de secrets (HashiCorp Vault, AWS Secrets Manager,
Azure Key Vault) + **rotation** de la clé, puisque l'ancienne doit être considérée
comme compromise dès lors qu'elle a été publiée.

**b) Remplacer MD5 par un algorithme de dérivation lent et salé :**

```typescript
import bcrypt from 'bcrypt'
const SALT_ROUNDS = 12                       // ~250 ms par calcul

export const hashPassword = (password: string) =>
  bcrypt.hash(password, SALT_ROUNDS)         // sel genere automatiquement

export const verifyPassword = (password: string, stored: string) =>
  bcrypt.compare(password, stored)           // comparaison a temps constant
```

**c) Nettoyer l'historique Git** (`git filter-repo` ou BFG) puis **révoquer** la clé exposée.

**d) Blocage en CI :** la règle Gitleaks `jwt-signing-secret` fait échouer le build
(`MAX_SECRETS = 0`), ce qui empêche toute réintroduction d'un secret.

## 3. Justification

Externaliser le secret rétablit le **principe de Kerckhoffs** : la sécurité repose sur la
clé, pas sur le secret du code. Le code peut alors être audité, partagé ou publié sans
compromettre le système, et la clé peut être tournée sans redéploiement applicatif.
bcrypt apporte deux propriétés que MD5 n'a pas : un **sel unique par mot de passe**
(les tables arc-en-ciel deviennent inutilisables et les condensats identiques
disparaissent) et un **facteur de coût configurable** qui rend le calcul volontairement
lent — une attaque par force brute passe de quelques secondes à plusieurs siècles pour un
mot de passe raisonnable. Le facteur de coût est ajustable dans le temps face à la
progression du matériel, ce qu'un algorithme figé ne permet pas.

## 4. Vérification

| Test | Avant | Après |
|---|---|---|
| Gitleaks sur le dépôt | **2 secrets** détectés (`jwt-signing-secret`, `weak-hash-md5`) | **0 secret** |
| Gitleaks sur l'historique (`--no-git` retiré) | secrets présents dans les commits | **0** après réécriture d'historique |
| Recherche `grep -r "BEGIN RSA PRIVATE KEY" .` | 1 occurrence | **0 occurrence** |
| Démarrage sans variable `JWT_PRIVATE_KEY` | l'application démarre | **échec explicite au démarrage** (*fail-fast*) |
| Format du condensat en base | `hex` 32 caractères (MD5) | `$2b$12$...` (bcrypt, 60 caractères) |
| Deux utilisateurs, même mot de passe | condensats **identiques** | condensats **différents** (sels distincts) |
| Règle SAST `weak-password-hashing` | 1 occurrence `ERROR` | **0 occurrence** |
| Build Jenkins (seuil `MAX_SECRETS=0`) | **FAILURE** | **SUCCESS** |

```bash
# Re-scan des secrets apres correction
docker run --rm -v "%cd%:/repo" -w /repo zricethezav/gitleaks:latest detect \
  --source . --config .gitleaks.toml --report-format json \
  --report-path reports/secrets-after.json --redact --verbose
```
