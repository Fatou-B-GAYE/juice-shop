# V3 — Broken Access Control / IDOR sur le panier d'achat

| Champ | Valeur |
|---|---|
| **Identifiant** | V3 |
| **Composant** | `routes/basket.ts` — endpoint `GET /rest/basket/:id` |
| **CWE** | CWE-639 — *Authorization Bypass Through User-Controlled Key* (IDOR), reliée à CWE-284 |
| **OWASP Top 10** | A01:2021 — Broken Access Control |
| **Sévérité** | **High** (CVSS 3.1 : 8.1) |
| **Détecté par** | Test manuel (Burp / DevTools) + SAST (règle `idor-missing-ownership-check`) |

## 1. Cause

L'endpoint vérifie que l'utilisateur est **authentifié** mais pas qu'il est
**propriétaire** de la ressource demandée. L'identifiant du panier vient directement de
l'URL et sert de clé de lecture sans contrôle croisé avec l'identité du porteur du JWT.

```typescript
// CODE VULNÉRABLE — routes/basket.ts
module.exports = function retrieveBasket () {
  return (req, res, next) => {
    const id = req.params.id                      // valeur controlee par le client
    BasketModel.findOne({ where: { id }, include: [...] })
      .then(basket => res.json({ status: 'success', data: basket }))
  }
}
```

**Preuve d'exploitation** : connecté avec un compte disposant du panier `id = 1`, il
suffit de rejouer la requête sur `/rest/basket/2` pour lire le panier — donc les achats
et les informations de commande — d'un **autre client**.

```bash
curl -H "Authorization: Bearer <mon_JWT>" http://localhost:3000/rest/basket/2
```

## 2. Correction proposée

Contrôler la **propriété de la ressource** côté serveur, à partir de l'identité issue du
jeton et jamais d'un paramètre client :

```typescript
// CODE CORRIGÉ — routes/basket.ts
module.exports = function retrieveBasket () {
  return (req, res, next) => {
    const id = req.params.id
    const user = security.authenticatedUsers.from(req)   // identite issue du JWT

    if (!user) return res.status(401).json({ error: 'Unauthenticated' })

    BasketModel.findOne({ where: { id }, include: [...] })
      .then(basket => {
        if (!basket) return res.status(404).json({ error: 'Not found' })

        // Controle d'autorisation : le panier appartient-il au demandeur ?
        if (basket.UserId !== user.data.id) {
          logger.warn(`IDOR tentative: user ${user.data.id} -> basket ${id}`)
          return res.status(403).json({ error: 'Forbidden' })
        }
        res.json({ status: 'success', data: basket })
      })
      .catch(next)
  }
}
```

Mesures complémentaires :

- politique **deny-by-default** : middleware d'autorisation appliqué globalement, les routes publiques étant explicitement listées ;
- remplacement des identifiants séquentiels par des **UUID v4** (ne supprime pas la faille mais empêche l'énumération) ;
- journalisation des refus `403` et alerte au-delà d'un seuil (détection d'énumération) ;
- tests d'autorisation automatisés dans la CI.

## 3. Justification

La correction déplace la décision d'autorisation du **client vers le serveur** : la seule
source d'identité devient le JWT signé, que l'attaquant ne peut pas forger. Masquer le
bouton dans l'interface ou passer aux UUID relève de la *sécurité par l'obscurité* et ne
résiste pas à une requête forgée. Le contrôle explicite `basket.UserId !== user.data.id`
est vérifiable, testable et couvre toutes les valeurs possibles de `:id`.

## 4. Vérification

| Test | Avant | Après |
|---|---|---|
| `GET /rest/basket/2` avec le JWT du propriétaire du panier 1 | **HTTP 200** + données d'autrui | **HTTP 403 Forbidden** |
| `GET /rest/basket/1` avec le JWT du propriétaire du panier 1 | HTTP 200 | **HTTP 200 — aucune régression** |
| `GET /rest/basket/9999` | HTTP 200 / `null` | **HTTP 404** |
| `GET /rest/basket/2` sans jeton | HTTP 200 | **HTTP 401** |
| Règle SAST `idor-missing-ownership-check` | 1 occurrence `WARNING` | **0 occurrence** |
| Journal applicatif | rien | ligne `IDOR tentative` enregistrée |

```bash
# Script de verification de l'autorisation horizontale
TOKEN=$(curl -s -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"jim@juice-sh.op","password":"ncc-1701"}' | jq -r .authentication.token)

for ID in 1 2 3 4; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" \
         http://localhost:3000/rest/basket/$ID)
  echo "basket/$ID -> HTTP $CODE"
done
```
