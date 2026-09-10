# V1 — Injection SQL sur le formulaire d'authentification

| Champ | Valeur |
|---|---|
| **Identifiant** | V1 |
| **Composant** | `routes/login.ts` — endpoint `POST /rest/user/login` |
| **CWE** | CWE-89 — *Improper Neutralization of Special Elements used in an SQL Command* |
| **OWASP Top 10** | A03:2021 — Injection |
| **Sévérité** | **Critical** (CVSS 3.1 : 9.8 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Détecté par** | Test manuel + SAST (règle `sqli-string-concatenation`) |

## 1. Cause — pourquoi la vulnérabilité existe-t-elle ?

La requête SQL d'authentification est construite par **concaténation de chaînes** avec
la valeur du champ `email` envoyée par le client. Le moteur SQL ne peut alors plus
distinguer les **données** de la **structure** de la requête : tout caractère de
contrôle (`'`, `--`, `OR`) fourni par l'utilisateur est interprété comme du code SQL.

```typescript
// CODE VULNÉRABLE — routes/login.ts
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' `
  + `AND password = '${security.hash(req.body.password || '')}' `
  + `AND deletedAt IS NULL`
)
```

**Preuve d'exploitation** — dans le champ e-mail :

```
' OR 1=1--
```

La requête devient `SELECT * FROM Users WHERE email = '' OR 1=1--' AND password = ...`.
La condition `1=1` est toujours vraie, `--` commente la vérification du mot de passe :
l'application renvoie le **premier utilisateur de la table**, c'est-à-dire
l'administrateur `admin@juice-sh.op`, avec un JWT valide.

## 2. Correction proposée

Utiliser des **requêtes paramétrées** (`replacements` Sequelize) : le pilote envoie la
structure de la requête et les valeurs par deux canaux séparés ; les valeurs ne sont
jamais analysées comme du SQL.

```typescript
// CODE CORRIGÉ — routes/login.ts
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  {
    replacements: {
      email: req.body.email || '',
      password: security.hash(req.body.password || '')
    },
    model: models.User,
    plain: true
  }
)
```

Mesures complémentaires (défense en profondeur) :

- validation de format en entrée (`express-validator` : `body('email').isEmail().normalizeEmail()`) ;
- utilisation de l'ORM (`User.findOne({ where: { email, password } })`) plutôt que du SQL brut ;
- compte de base de données applicatif en **moindre privilège** (pas de `DROP`, pas de `information_schema`) ;
- messages d'erreur génériques (« identifiants invalides ») pour ne pas révéler l'existence d'un compte.

## 3. Justification — pourquoi cette correction est-elle efficace ?

La correction agit à la **racine** de la vulnérabilité et non sur ses symptômes. Une
liste noire de caractères (`'`, `--`, `OR`) serait contournable (encodage hexadécimal,
commentaires `/**/`, variations de casse). Le *prepared statement* supprime
structurellement la confusion données/code : quelle que soit la charge envoyée, elle
reste une **valeur littérale** comparée à la colonne `email`. C'est la mesure
recommandée en premier par l'OWASP *SQL Injection Prevention Cheat Sheet*.

## 4. Vérification de la correction

| Test | Avant | Après |
|---|---|---|
| Payload `' OR 1=1--` dans le champ e-mail | Connexion en tant qu'`admin@juice-sh.op` (HTTP 200 + JWT) | **HTTP 401 Unauthorized** — « Invalid email or password » |
| Payload `admin@juice-sh.op'--` | Connexion sans mot de passe | **HTTP 401** |
| Payload `' UNION SELECT 1,2,3--` | Erreur SQL détaillée affichée | **HTTP 401**, aucune fuite d'erreur |
| Connexion légitime (`jim@juice-sh.op` / mot de passe correct) | OK | **OK — aucune régression** |
| Règle SAST `sqli-string-concatenation` | 1 occurrence — `ERROR` | **0 occurrence** |
| Scan DAST ZAP, règle 40018 (SQL Injection) | Alerte **High** | **Aucune alerte** |

**Commandes de vérification :**

```bash
# Test négatif (doit renvoyer 401)
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}"

# Re-scan SAST ciblé
docker run --rm -v "%cd%:/src" -w /src semgrep/semgrep:latest semgrep scan \
  --config security-config/semgrep-rules.yml routes/login.ts
```
