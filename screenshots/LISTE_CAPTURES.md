# Liste des captures d'écran à prendre

Nommer chaque fichier exactement comme indiqué : le rapport y fait référence par ce nom.

## A — Environnement (3 captures)

| Fichier | Ce qu'il faut montrer |
|---|---|
| `01-docker-version.png` | Terminal : `docker --version` + `docker ps` avec le conteneur `juice-shop` en `Up` |
| `02-juiceshop-accueil.png` | Navigateur sur http://localhost:3000 — page d'accueil de Juice Shop |
| `03-jenkins-dashboard.png` | http://localhost:8080 — tableau de bord Jenkins connecté |

## B — Partie 1 : identification des vulnérabilités (6 captures)

| Fichier | Ce qu'il faut montrer |
|---|---|
| `04-V1-sqli-payload.png` | Formulaire de connexion avec `' OR 1=1--` saisi dans le champ e-mail |
| `05-V1-sqli-admin.png` | Connecté en `admin@juice-sh.op` (menu compte ouvert, e-mail visible) |
| `06-V2-xss-payload.png` | Barre de recherche avec `<iframe src="javascript:alert('XSS')">` |
| `07-V2-xss-alerte.png` | Boîte d'alerte XSS affichée |
| `08-V3-idor-basket.png` | DevTools / Postman : `GET /rest/basket/2` renvoyant HTTP 200 + panier d'un autre utilisateur |
| `09-V4-ftp-listing.png` | http://localhost:3000/ftp — listing du répertoire + ouverture de `acquisitions.md` |

## C — Partie 4 : outils d'analyse (5 captures)

| Fichier | Ce qu'il faut montrer |
|---|---|
| `10-sca-npm-audit.png` | Sortie de `npm audit` avec le résumé du nombre de vulnérabilités par sévérité |
| `11-secrets-gitleaks.png` | Sortie Gitleaks avec les *findings* (secrets masqués par `--redact`) |
| `12-sast-semgrep.png` | Sortie Semgrep listant les règles déclenchées (CWE-89, CWE-79…) |
| `13-dast-zap.png` | Rapport HTML ZAP ouvert dans le navigateur (`reports/dast-zap.html`) |
| `14-arborescence-reports.png` | Explorateur/`dir reports` montrant tous les fichiers de rapport générés |

## D — Pipeline Jenkins (6 captures)

| Fichier | Ce qu'il faut montrer |
|---|---|
| `15-jenkins-config-pipeline.png` | Configuration du job : *Pipeline script from SCM*, URL GitHub, `Jenkinsfile` |
| `16-jenkins-stage-view.png` | *Stage View* avec les 6 étapes du pipeline |
| `17-jenkins-console.png` | Sortie console d'un build (extrait montrant les scans) |
| `18-jenkins-artifacts.png` | Artefacts archivés (`reports/**`) sur la page du build |
| `19-jenkins-gate-failure.png` | Build en **FAILURE** à cause du *security gate* (`MAX_CRITICAL = 0`) |
| `20-jenkins-email.png` | E-mail de notification reçu dans la boîte Gmail |

## E — Remédiation et vérification (5 captures)

| Fichier | Ce qu'il faut montrer |
|---|---|
| `21-V1-code-avant-apres.png` | Diff du code de `login.ts` : concaténation → requête paramétrée |
| `22-V1-verif-401.png` | Le payload `' OR 1=1--` renvoie maintenant **HTTP 401** |
| `23-V2-verif-xss.png` | Le payload XSS s'affiche en texte, aucune alerte |
| `24-V3-verif-403.png` | `GET /rest/basket/2` renvoie **HTTP 403** |
| `25-V5-verif-gitleaks.png` | Nouveau scan Gitleaks : **0 secret** détecté |

## F — Webhook et automatisation (2 captures)

| Fichier | Ce qu'il faut montrer |
|---|---|
| `26-github-webhook.png` | Page GitHub *Settings → Webhooks* avec la coche verte de livraison |
| `27-jenkins-build-webhook.png` | Build Jenkins avec la mention *Started by GitHub push by leonbathie* |

---

**Total : 27 captures.** Le rapport en intègre environ 20 ; conserver les autres en annexe.
