# Examen Final — Sécurité des Données · Évaluation de sécurité d'OWASP Juice Shop

**Licence 3 — Cybersécurité** · Auteur : **Ousmane BA** · Rôle : *Cybersecurity Analyst / Junior DevSecOps Engineer*

Évaluation de sécurité de l'application vulnérable **OWASP Juice Shop** avant mise en
production : identification et classification CWE des vulnérabilités, analyse d'impact
CIA, remédiations vérifiées, et intégration de contrôles de sécurité automatisés dans un
pipeline Jenkins.

---

## 1. Application analysée

| | |
|---|---|
| **Application** | OWASP Juice Shop (projet OWASP officiel — *Flagship*) |
| **Version** | image Docker `bkimminich/juice-shop:latest` |
| **Pile technique** | Node.js / Express / Angular / Sequelize / SQLite |
| **URL locale** | http://localhost:3000 |
| **Dépôt forké** | https://github.com/leonbathie/juice-shop |

> ⚠️ **Cadre d'usage** — Juice Shop est une application volontairement vulnérable, conçue
> pour l'entraînement. Toutes les manipulations décrites ici ont été réalisées sur une
> instance locale personnelle, sans aucune cible tierce.

---

## 2. Arborescence du dépôt

```
project/
├── README.md                    # ce fichier
├── Jenkinsfile                  # pipeline complet (SCA + Secrets + SAST + DAST)
├── Jenkinsfile.simple           # variante allégée (sans accès au démon Docker)
├── .gitleaks.toml               # configuration de la détection de secrets
├── reports/                     # sorties des outils (JSON / TXT / HTML)
├── screenshots/                 # captures d'écran (voir LISTE_CAPTURES.md)
├── security-config/
│   ├── semgrep-rules.yml        # règles SAST personnalisées (mappées CWE)
│   └── zap-baseline.conf        # politique DAST (FAIL / WARN / IGNORE)
├── scripts/
│   └── run-all-scans.ps1        # exécution locale des 4 contrôles
└── remediation/
    ├── V1-sql-injection.md
    ├── V2-xss.md
    ├── V3-broken-access-control.md
    ├── V4-exposition-donnees-ftp.md
    └── V5-secrets-et-hachage.md
```

---

## 3. Comment exécuter le projet

### 3.1 Prérequis

- Windows 11 + **Docker Desktop** (démon démarré)
- **Node.js 20 LTS** et npm
- **Git**
- **Jenkins** (conteneur Docker, cf. §3.4)

### 3.2 Lancer l'application cible

```powershell
docker pull bkimminich/juice-shop
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
# Vérification
curl.exe -s -o NUL -w "%{http_code}`n" http://localhost:3000
```

L'application est accessible sur **http://localhost:3000**.

### 3.3 Lancer les analyses de sécurité

**En une seule commande :**

```powershell
git clone https://github.com/leonbathie/juice-shop.git
cd juice-shop
powershell -ExecutionPolicy Bypass -File .\scripts\run-all-scans.ps1
```

**Ou outil par outil :**

```powershell
# SCA — analyse des dépendances
npm install --legacy-peer-deps --ignore-scripts
npm audit --json > reports\sca-npm-audit.json
npm audit        > reports\sca-npm-audit.txt

# Secret Detection — Gitleaks
docker run --rm -v "${PWD}:/repo" -w /repo zricethezav/gitleaks:latest detect `
  --source . --config .gitleaks.toml --report-format json `
  --report-path reports/secrets-gitleaks.json --redact --no-git --exit-code 0 --verbose

# SAST — Semgrep
docker run --rm -v "${PWD}:/src" -w /src semgrep/semgrep:latest semgrep scan `
  --config security-config/semgrep-rules.yml --config p/owasp-top-ten `
  --json --output reports/sast-semgrep.json --metrics=off routes lib models

# DAST — OWASP ZAP Baseline
docker run --rm -v "${PWD}\reports:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable `
  zap-baseline.py -t http://host.docker.internal:3000 `
  -J dast-zap.json -r dast-zap.html -I -m 3
```

### 3.4 Lancer le pipeline Jenkins

```powershell
# 1. Démarrer Jenkins avec accès au démon Docker
docker run -d --name jenkins-secu -u root `
  -p 8080:8080 -p 50000:50000 `
  -v jenkins_home:/var/jenkins_home `
  -v /var/run/docker.sock:/var/run/docker.sock `
  jenkins/jenkins:lts

# 2. Installer le client Docker dans le conteneur Jenkins
docker exec -u root jenkins-secu bash -c "curl -fsSL https://get.docker.com | sh"

# 3. Récupérer le mot de passe initial
docker exec jenkins-secu cat /var/jenkins_home/secrets/initialAdminPassword
```

Puis, sur **http://localhost:8080** :

1. déverrouiller Jenkins, installer les plugins suggérés, créer l'utilisateur admin ;
2. installer les plugins **Pipeline**, **Git**, **Email Extension**, **HTML Publisher**, **NodeJS** ;
3. *Nouvel Item* → **Pipeline** → nom `Securite-JuiceShop` ;
4. *Pipeline* → **Pipeline script from SCM** → Git → `https://github.com/leonbathie/juice-shop.git`, branche `master`, *Script Path* = `Jenkinsfile` ;
5. cocher **GitHub hook trigger for GITScm polling** ;
6. **Build Now**.

### 3.5 Notification par e-mail

*Administrer Jenkins → Configuration du système → Extended E-mail Notification* :

| Paramètre | Valeur |
|---|---|
| SMTP server | `smtp.gmail.com` |
| Port | `465` — SSL activé |
| Credentials | compte Gmail + **mot de passe d'application** |
| Default Content Type | HTML |

### 3.6 Déclenchement automatique (webhook)

```powershell
ngrok http 8080
```

Puis sur GitHub : *Settings → Webhooks → Add webhook* →
`https://<id>.ngrok-free.app/github-webhook/` · content type `application/json` · événement *Just the push event*.

---

## 4. Contrôles de sécurité intégrés

| Étape du pipeline | Type | Outil | Ce qu'il détecte | Limites |
|---|---|---|---|---|
| 1. Checkout | — | Git | — | — |
| 2. Build / Preparation | — | npm | — | — |
| 3. Security Analysis | **SCA** | `npm audit` | CVE des dépendances directes et transitives (CWE-1035, CWE-1104) | ne voit que l'arbre npm ; pas d'analyse d'exploitabilité réelle |
| 3. Security Analysis | **Secret Detection** | Gitleaks | clés, jetons, mots de passe codés en dur (CWE-798, CWE-321) | secrets à faible entropie non détectés ; faux positifs sur les données de test |
| 3. Security Analysis | **SAST** | Semgrep | SQLi, XSS, IDOR, path traversal, crypto faible (CWE-89, 79, 639, 22, 916) | pas de contexte d'exécution ; ne détecte pas les failles de logique métier |
| 4. Additional Security Check | **DAST** | OWASP ZAP Baseline | mauvaises configurations, en-têtes manquants, injections détectables en boîte noire | ne couvre que les pages atteintes par le crawl ; aucune visibilité sur le code |
| 5. Report Generation | — | script consolidé + *security gate* | applique les seuils `MAX_CRITICAL` / `MAX_SECRETS` | — |
| 6. Notification | — | Email Extension | envoi du résumé et des rapports | — |

**Positionnement dans le cycle :** SCA, Secret Detection et SAST interviennent **avant**
le déploiement (analyse du code, *shift-left*, rapides) ; le DAST intervient **après**
déploiement de l'instance de test, sur l'application en fonctionnement.

---

## 5. Vulnérabilités identifiées

| ID | Vulnérabilité | Composant | CWE | Sévérité |
|---|---|---|---|---|
| V1 | Injection SQL (authentification) | `routes/login.ts` | CWE-89 | **Critical** |
| V2 | Cross-Site Scripting (DOM) | recherche produit | CWE-79 | **High** |
| V3 | Broken Access Control / IDOR | `routes/basket.ts` | CWE-639 | **High** |
| V4 | Exposition de données + path traversal | `/ftp` | CWE-200 / CWE-22 | **High** |
| V5 | Secrets codés en dur + hachage MD5 | `lib/insecurity.ts` | CWE-798 / CWE-916 | **Critical** |
| V6 | Dépendances vulnérables (46 CVE) | `package.json` | CWE-1035 | **Critical** |
| V7 | Mauvaise configuration de sécurité | en-têtes HTTP | CWE-16 / CWE-693 | **Medium** |
| V8 | Absence de limitation des tentatives | `/rest/user/login` | CWE-307 | **Medium** |

Le détail complet (impact CIA, remédiation, vérification) figure dans le **rapport de
sécurité** et dans le dossier `remediation/`.

---

## 6. Décision de déploiement

> ### 🔴 REJECT DEPLOYMENT
>
> Deux vulnérabilités de sévérité **Critical** (V1 — injection SQL permettant une prise de
> contrôle administrateur sans authentification ; V5 — clé de signature JWT exposée
> permettant la forge de jetons) compromettent directement la confidentialité **et**
> l'intégrité des données utilisateurs. Le *security gate* du pipeline
> (`MAX_CRITICAL = 0`) échoue et bloque le déploiement. La mise en production ne pourra
> être reconsidérée qu'après correction de V1 à V5 et re-exécution complète du pipeline
> avec un build en succès.

---

## 7. Références

- OWASP Top 10 (2021) — https://owasp.org/Top10/
- MITRE CWE Top 25 — https://cwe.mitre.org/top25/
- OWASP Juice Shop — https://owasp.org/www-project-juice-shop/
- OWASP Cheat Sheet Series (SQL Injection, XSS, Access Control, Secrets Management)
