# V4 — Exposition de données sensibles et traversée de répertoire (/ftp)

| Champ | Valeur |
|---|---|
| **Identifiant** | V4 |
| **Composant** | `server.ts` — service de fichiers statiques `/ftp` |
| **CWE** | CWE-200 — *Exposure of Sensitive Information to an Unauthorized Actor* ; CWE-22 — *Path Traversal* (contournement par *poison null byte*, CWE-158) |
| **OWASP Top 10** | A01:2021 — Broken Access Control |
| **Sévérité** | **High** (CVSS 3.1 : 7.5) |
| **Détecté par** | Test manuel + DAST ZAP (règles 6 et 10027) |

## 1. Cause

Un répertoire interne (`ftp/`) contenant des documents métier est exposé **sans
authentification** par un service de fichiers statiques. Le filtre de sécurité repose sur
une simple vérification d'extension appliquée à la chaîne brute, contournable par un
**octet nul encodé** (`%2500`), que la couche Node interprète comme fin de chaîne.

```typescript
// CODE VULNÉRABLE — server.ts
app.use('/ftp', serveIndex('ftp', { icons: true }))
app.use('/ftp', (req, res, next) => {
  if (!req.url.endsWith('.md') && !req.url.endsWith('.pdf')) {
    return res.status(403).send('Only .md and .pdf files are allowed')
  }
  next()
})
app.use('/ftp', express.static('ftp'))
```

**Preuves d'exploitation :**

```
http://localhost:3000/ftp                              -> listing complet du repertoire
http://localhost:3000/ftp/acquisitions.md              -> document confidentiel (fusion-acquisition)
http://localhost:3000/ftp/package.json.bak%2500.md     -> fichier de sauvegarde interne
```

Le dernier cas contourne le filtre : la chaîne se termine bien par `.md` pour le test,
mais le système de fichiers lit `package.json.bak`.

## 2. Correction proposée

Supprimer l'exposition publique et, pour les fichiers légitimement téléchargeables,
appliquer authentification + **liste blanche** + normalisation de chemin :

```typescript
// CODE CORRIGÉ — server.ts
// 1) Suppression du listing de repertoire
// app.use('/ftp', serveIndex('ftp'))            <-- SUPPRIME

const path = require('path')
const FTP_ROOT = path.resolve(__dirname, 'ftp')
const ALLOWED_FILES = new Set(['legal.md', 'terms-of-use.pdf'])   // liste blanche

app.get('/ftp/:file', verifyAuthenticatedUser, (req, res) => {
  const name = path.basename(req.params.file)      // neutralise ../ et les sous-chemins

  if (name.includes('\0') || !ALLOWED_FILES.has(name)) {
    logger.warn(`Acces fichier refuse: ${req.params.file} (ip=${req.ip})`)
    return res.status(403).send('Forbidden')
  }

  const target = path.resolve(FTP_ROOT, name)
  if (!target.startsWith(FTP_ROOT + path.sep)) {   // verification du prefixe
    return res.status(403).send('Forbidden')
  }
  res.sendFile(target)
})
```

Mesures complémentaires :

- déplacer les documents confidentiels **hors de la racine web** (stockage objet privé, URL signées à durée limitée) ;
- retirer les fichiers de sauvegarde (`*.bak`, `*.old`) du dépôt et les ajouter au `.gitignore` ;
- désactiver l'affichage des messages d'erreur détaillés en production ;
- ajouter une règle DAST bloquante (ZAP 6 — *Path Traversal*) dans la CI.

## 3. Justification

La correction combine **trois** protections indépendantes : `path.basename()` élimine
toute séquence de traversée, la **liste blanche** interdit par défaut tout fichier non
prévu (approche *deny-by-default*, insensible aux techniques d'encodage), et la
vérification du préfixe garantit que le chemin résolu reste sous la racine autorisée. Le
rejet explicite de l'octet nul ferme le contournement `%2500`. Enfin, la suppression du
listing supprime la phase de reconnaissance : l'attaquant ne peut plus découvrir les noms
de fichiers.

## 4. Vérification

| Test | Avant | Après |
|---|---|---|
| `GET /ftp` | Listing HTML complet du répertoire | **HTTP 403 / 404** |
| `GET /ftp/acquisitions.md` | HTTP 200 + document confidentiel | **HTTP 403** |
| `GET /ftp/package.json.bak%2500.md` | HTTP 200 + fichier interne | **HTTP 403** |
| `GET /ftp/../package.json` | HTTP 200 | **HTTP 403** |
| `GET /ftp/legal.md` avec session valide | HTTP 200 | **HTTP 200 — aucune régression** |
| DAST ZAP règle 6 (Path Traversal) | 1 alerte | **Aucune alerte** |

```bash
for URL in "/ftp" "/ftp/acquisitions.md" "/ftp/package.json.bak%2500.md" "/ftp/legal.md"; do
  echo "$URL -> $(curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000$URL")"
done
```
