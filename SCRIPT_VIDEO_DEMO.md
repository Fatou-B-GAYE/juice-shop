# Script de la vidéo démo (5 à 10 minutes)

Objectif : présenter l'application, les principaux problèmes, une ou plusieurs
remédiations, le pipeline Jenkins, les résultats et la décision finale (Livrable 3).

**Conseils :** enregistre l'écran (OBS / Xbox Game Bar `Win+G`), parle en continu,
garde les onglets déjà ouverts avant de lancer l'enregistrement. Durée cible : **7 min**.

---

## 0:00 – 0:40 · Introduction

> « Bonjour, je suis Ousmane BA. Dans le cadre de l'examen final du cours Sécurité des
> Données, j'ai réalisé l'évaluation de sécurité de l'application OWASP Juice Shop, une
> application volontairement vulnérable, en jouant le rôle de Cybersecurity Analyst.
> Je vais vous montrer l'application, les vulnérabilités trouvées, leurs remédiations, le
> pipeline Jenkins qui automatise les contrôles, puis ma décision de déploiement. »

*Écran : page d'accueil Juice Shop (http://localhost:3000).*

---

## 0:40 – 1:10 · L'application

> « Juice Shop est une boutique en ligne : création de compte, authentification, panier,
> espace admin. Elle manipule des données sensibles — comptes, commandes, documents
> internes — ce qui en fait une bonne cible d'analyse avant une mise en production. »

*Écran : navigue vite dans l'app (login, recherche, panier).*

---

## 1:10 – 3:00 · Les principaux problèmes identifiés

Montre **3 failles en direct** (les plus visuelles) :

**Injection SQL (V1 — CWE-89, Critical)**
> « Dans le champ e-mail de la connexion, je saisis `' OR 1=1--`. »

*Tape le payload, clique Login.*
> « Je suis maintenant connecté en tant qu'administrateur, sans mot de passe : la requête
> SQL était construite par concaténation de chaînes. Impact : confidentialité et
> intégrité compromises, criticité Critical. »

**XSS (V2 — CWE-79, High)**
> « Dans la recherche, j'injecte une iframe JavaScript. »

*Montre l'alerte.*
> « Le terme de recherche était réinjecté dans le DOM sans échappement. Un attaquant
> pourrait voler le jeton de session. »

**Exposition /ftp (V4 — CWE-200 / CWE-22, High)**
> « L'URL /ftp expose un répertoire interne sans authentification, et le filtre
> d'extension se contourne avec un octet nul `%2500`. »

*Montre le listing + acquisitions.md.*

> « J'ai aussi identifié une faille de contrôle d'accès de type IDOR sur les paniers, et
> des secrets codés en dur avec un hachage MD5. Au total 8 vulnérabilités, détaillées et
> classées par CWE dans le rapport. »

---

## 3:00 – 4:00 · Une remédiation

Prends **l'injection SQL** :
> « Pour corriger l'injection SQL, on remplace la concaténation par une requête
> paramétrée : la valeur saisie n'est plus interprétée comme du code SQL mais comme une
> simple donnée. »

*Montre le diff avant/après de `remediation/V1-sql-injection.md`.*
> « Vérification : le même payload `' OR 1=1--` renvoie désormais une erreur 401, et une
> connexion légitime fonctionne toujours. La correction agit à la racine du problème. »

---

## 4:00 – 5:30 · Le pipeline Jenkins

> « J'ai intégré ces contrôles dans un pipeline Jenkins en six étapes : checkout, build,
> analyse de sécurité, contrôle additionnel, génération de rapport et notification. »

*Écran : Stage View du pipeline.*
> « L'étape d'analyse lance en parallèle quatre outils :
> le SCA avec npm audit sur les dépendances,
> la détection de secrets avec Gitleaks,
> l'analyse statique du code avec Semgrep,
> et l'analyse dynamique de l'application en boîte noire avec OWASP ZAP. »

*Montre la console d'un build, puis les artefacts.*
> « Un security gate fait échouer le build s'il reste des vulnérabilités critiques, et une
> notification par e-mail est envoyée avec le rapport. »

*Montre le build FAILURE + l'e-mail reçu.*

---

## 5:30 – 6:30 · Les résultats

> « Les résultats : npm audit remonte [DIS TON CHIFFRE] vulnérabilités dont plusieurs
> critiques, Gitleaks confirme la clé JWT exposée, Semgrep confirme l'injection SQL et la
> XSS, et ZAP signale les en-têtes de sécurité manquants. »

*Montre le rapport HTML de ZAP + le tableau de priorisation.*
> « Je classe : injection SQL en Critical à bloquer, secrets en Critical à bloquer, XSS et
> IDOR en High correction requise, exposition d'information en Medium. »

---

## 6:30 – 7:00 · La décision finale

> « Ma décision : **Reject Deployment**. Deux vulnérabilités critiques permettent une
> prise de contrôle administrateur et la forge de jetons d'authentification. Le security
> gate du pipeline échoue. La mise en production est refusée tant que les vulnérabilités
> critiques et élevées ne sont pas corrigées et le pipeline repassé au vert.
>
> Enfin, un outil qui ne détecte rien ne garantit pas qu'une application est sûre :
> faux négatifs, couverture partielle des règles et absence de contexte métier imposent
> de garder une analyse humaine. Merci. »

---

### Checklist avant d'envoyer la vidéo

- [ ] Durée entre 5 et 10 min
- [ ] Les 6 points du sujet sont couverts (app, problèmes, remédiation, pipeline, résultats, décision)
- [ ] Audio clair, texte lisible à l'écran
- [ ] Tes vrais chiffres SCA sont annoncés
- [ ] Format .mp4, nommé `Demo_Securite_JuiceShop_Ousmane_BA.mp4`
