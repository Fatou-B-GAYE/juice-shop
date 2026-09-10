# V2 — Cross-Site Scripting (DOM XSS) sur la barre de recherche

| Champ | Valeur |
|---|---|
| **Identifiant** | V2 |
| **Composant** | `frontend/src/app/search-result/search-result.component.html` — paramètre `?q=` |
| **CWE** | CWE-79 — *Improper Neutralization of Input During Web Page Generation* |
| **OWASP Top 10** | A03:2021 — Injection |
| **Sévérité** | **High** (CVSS 3.1 : 7.4) |
| **Détecté par** | Test manuel + SAST (règle `xss-unsanitized-output`) + DAST ZAP (règle 40016) |

## 1. Cause

Le terme de recherche saisi par l'utilisateur est réinjecté dans le DOM via le
*pipe* Angular `innerHTML` couplé à `bypassSecurityTrustHtml()`, ce qui **désactive
explicitement l'échappement automatique** du framework.

```html
<!-- CODE VULNÉRABLE -->
<h3>Search Results - <span [innerHTML]="searchValue"></span></h3>
```

```typescript
// CODE VULNÉRABLE
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
```

**Preuve d'exploitation** — dans la barre de recherche :

```html
<iframe src="javascript:alert(`XSS - session: ${document.cookie}`)">
```

Le script s'exécute dans le contexte d'origine de l'application. Un attaquant peut
diffuser l'URL `http://.../#/search?q=<payload>` et **exfiltrer le jeton JWT** stocké
côté client, donc usurper la session de la victime.

## 2. Correction proposée

Supprimer le contournement du sanitizer et rendre le texte **en tant que texte** :

```html
<!-- CODE CORRIGÉ : interpolation Angular, échappement automatique -->
<h3>Search Results - <span>{{ searchValue }}</span></h3>
```

```typescript
// CODE CORRIGÉ
this.searchValue = queryParam            // plus de bypassSecurityTrustHtml
```

Si du HTML riche est réellement nécessaire, assainir avec **DOMPurify** avec une liste
blanche stricte :

```typescript
import DOMPurify from 'dompurify'
this.searchValue = DOMPurify.sanitize(queryParam, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong'],
  ALLOWED_ATTR: []
})
```

Mesures complémentaires :

- **Content-Security-Policy** stricte : `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'` ;
- cookie de session en `HttpOnly; Secure; SameSite=Strict` (le JWT n'est plus lisible en JavaScript) ;
- en-tête `X-Content-Type-Options: nosniff`.

## 3. Justification

L'échappement contextuel en **sortie** est la seule protection fiable : filtrer en
entrée est contournable (`<img src=x onerror=...>`, encodages HTML/URL, `javascript:`,
SVG). En rendant la valeur comme texte, le navigateur affiche `<iframe ...>` sous forme
de caractères et ne construit aucun nœud exécutable. La CSP et le cookie `HttpOnly`
constituent une **seconde barrière** : même si une XSS résiduelle apparaissait, le script
externe serait bloqué et le jeton de session resterait inaccessible.

## 4. Vérification

| Test | Avant | Après |
|---|---|---|
| `<iframe src="javascript:alert(1)">` dans la recherche | Boîte d'alerte affichée | Chaîne affichée **en clair**, aucune exécution |
| `<img src=x onerror=alert(document.cookie)>` | Alerte + cookie exfiltré | Aucune exécution |
| `?q=<script>alert(1)</script>` (URL directe) | Alerte | Aucune exécution |
| Règle SAST `xss-unsanitized-output` | 1 occurrence `ERROR` | **0 occurrence** |
| DAST ZAP règles 40012 / 40014 / 40016 | 1 alerte **High** | **Aucune alerte** |
| En-tête CSP (`curl -I`) | absent | `Content-Security-Policy` présent |

```bash
# Vérification des en-têtes de sécurité
curl -sI http://localhost:3000 | findstr /I "content-security-policy x-content-type-options"
```
