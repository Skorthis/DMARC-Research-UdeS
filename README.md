# DMARC-Research-UdeS
Repository contenant les recherches et les résultats du projet de recherche sur le protocol DMARC dans le cadre du cours INF808 de l'université de Sherbrooke.


## Résumé

Le protocole DMARC (Domain-based Message Authentication, Reporting, and Conformance) est une méthode permettant aux propriétaires de domaines d'exprimer leurs politiques d'authentification des courriels et de recevoir des rapports sur leur utilisation. Il repose sur d'autres protocoleds, SPF (Sender Policy Framework) et DKIM (DomainKeys Identified Mail) pour assurer la vérification des messages.


La première étape du projet est de bien comprendre son fonctionnement et ses caractéristiques, pour cela il faut se pencher sur la [RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489 "DMARC RFC"). 


### 1. Objectifs de DMARC
* Authentifier l'expéditeur des courriels pour lutter contre l'usurpation de domaine.
* Définir des politiques sur la manière dont les courriels non conformes doivent être traités (aucune action, mise en quarantaine ou rejet).
* Recevoir des rapports sur les tentatives de fraude ou les erreurs d'authentification.
* Améliorer la protection contre le phishing et le spam en imposant des règles plus strictes aux services de messagerie.

### 2. Fonctionnement de DMARC
DMARC repose sur trois mécanismes : DNS, SPF et DKIM.

#### 2.1 Publication de la politique DMARC

Le propriétaire du domaine publie une politique DMARC sous forme d’un enregistrement `TXT` dans le DNS, sous `_dmarc.example.com`.

Exemple de configuration :

``` v=DMARC1; p=quarantine; rua=mailto:report@example.com```

`v=DMARC1` → Version du protocole.

`p=quarantine` → Politique appliquée aux courriels non conformes (quarantaine).

`rua=mailto:report@example.com` → Adresse de réception des rapports agrégés.


#### 2.2 Processus de validation d'un courriel

Lorsqu'un courriel est reçu, plusieurs étapes sont suivies :

1. Vérification SPF
SPF vérifie si l’adresse IP de l’expéditeur est autorisée à envoyer des courriels pour le domaine.
SPF valide uniquement le domaine indiqué dans le champ MAIL FROM du protocole SMTP.

2. Vérification DKIM
DKIM vérifie que le courriel contient une signature valide liée au domaine de l’expéditeur.
Un enregistrement DNS (clé publique) permet de valider la signature DKIM.

3. Vérification d’alignement (Identifier Alignment)
DMARC impose que le domaine utilisé dans SPF ou DKIM corresponde au domaine visible dans le champ From ([RFC5322](https://datatracker.ietf.org/doc/html/rfc5322)).

Deux modes d’alignement :

`Strict` → Le domaine doit être exactement le même.

`Relaxed` → Un sous-domaine peut être accepté.

4. Application de la politique DMARC
Si SPF et DKIM échouent :

`p=none` → Pas d’action, mais envoi de rapports.

`p=quarantine` → Le courriel est placé en spam.

`p=reject` → Le courriel est rejeté immédiatement.


#### 2.3 Rapports et supervision
DMARC permet aux propriétaires de domaines de recevoir des rapports d’activité :

Rapports agrégés (RUA) : Données statistiques sur les courriels envoyés depuis le domaine.

Rapports d’échec (RUF) : Détails des courriels ayant échoué aux vérifications SPF/DKIM.

Les rapports permettent d’analyser et d’améliorer l’authentification des courriels.

### 3. Le concept de confiance 

Une des questions de ce projet de recherche est de comprendre sur quel principe de confiance, le protocole DMARC repose et qui entretien cette dernière.

Ainsi, à la lecture de la RFC on remarque que a confiance en DMARC vient de plusieurs sources :


Le propriétaire du domaine publie sa politique DMARC dans le DNS.

Le serveur de messagerie récepteur applique cette politique en vérifiant SPF et DKIM.

Les fournisseurs d’courriels (Gmail, Outlook, Yahoo, etc.) interprètent ces règles et bloquent les courriels frauduleux.

Les rapports DMARC aident le propriétaire du domaine à surveiller l'utilisation de son domaine et à ajuster ses règles.

DMARC fonctionne sur la base de la vérification DNS, où la confiance repose sur l’intégrité du système DNS et la mise en place correcte de SPF et DKIM.

### 4. Limites et défis de DMARC

#### 4.1 Problèmes liés au transfert de courriels
Lorsqu’un courriel est transféré, l’IP de l’expéditeur change, ce qui peut faire échouer SPF.
DKIM peut également échouer si le message est modifié en transit.

#### 4.2 Faux positifs
Certains courriels légitimes peuvent être rejetés ou placés en spam si DMARC est mal configuré.
#### 4.3 Contournement par les attaquants
DMARC protège uniquement contre l'usurpation exacte du domaine.
Les attaquants peuvent utiliser des domaines similaires (`examp1e.com` au lieu de `example.com`).

#### 4.4 Dépendance au DNS
DMARC repose sur des enregistrements DNS, ce qui signifie que toute attaque sur le DNS (ex: spoofing, détournement) pourrait compromettre la protection.




### 5. Comment s'assurer que DMARC fonctionne ?

Vérifier les enregistrements DNS
Utiliser des outils comme :

``` dig TXT _dmarc.example.com```

MXToolbox

```nslookup -type=TXT _dmarc.example.com ```

Analyser les rapports DMARC

Lire les rapports agrégés (RUA) pour voir le taux de conformité.
Étudier les rapports d’échec (RUF) pour identifier les problèmes.
Déploiement progressif

Commencer avec `p=none` pour collecter des données.
Passer à `p=quarantine` puis `p=reject` une fois sûr que la configuration est correcte.


## DMARCBis 

Une nouvelle version du protocole DMARC est en phase de développement, DMARCbis. Cette version n'a pas encore été officiellement publié. Selon les informations disponibles, la spécification est en cours de finalisation et devrait être publiée en tant que norme proposée en 2025. 

### DMARCbis : Nouveautés, Changements et Raisons de la Nouvelle Version

DMARCbis est la nouvelle version du protocole DMARC, conçue pour remplacer RFC 7489. Elle a été développée pour intégrer les retours d’expérience et corriger certaines limitations identifiées lors du déploiement massif de DMARC ces dernières années. 

## Nouveautés et Changements Clés

- **Restructuration et Clarification du Document**  
  La spécification a été réorganisée et enrichie avec des exemples plus détaillés et des définitions plus claires. Cela facilite la compréhension et l’implémentation du protocole par les différents acteurs (propriétaires de domaines et récepteurs).

- **Amélioration de la Détermination du Domaine Organisationnel**  
  L’ancienne méthode basée sur la Public Suffix List (PSL) est remplacée par un algorithme de *DNS Tree Walk*. Cette approche permet :
  - Une identification plus précise du domaine organisationnel.
  - L’intégration de la notion de domaine public (Public Suffix Domain, PSD) grâce au tag `psd`.

- **Modification des Tags de l’Enregistrement DMARC**  
  Pour simplifier l’implémentation, certains tags ont été supprimés et de nouveaux ajoutés :
  
  - **Tags supprimés :** `pct`, `rf` et `ri`.
  - **Tags ajoutés :**
    - `np` : Permet de définir la politique applicable aux sous-domaines inexistants.
    - `psd` : Indique si le domaine est considéré comme un domaine public (PSD).
    - `t` : Remplace en partie le fonctionnement du tag `pct` en indiquant le mode test (pour ne pas appliquer strictement la politique).

- **Évolution des Terminologies**  
  Certains termes ont été clarifiés ou renommés pour mieux refléter leur rôle dans le processus DMARC, par exemple le terme *Report Receiver* est remplacé par *Report Consumer*.

- **Meilleure Prise en Compte des Flux de Courriels Indirects**  
  DMARCbis aborde plus explicitement les problèmes liés aux transferts de courriels et aux listes de diffusion, qui peuvent fausser l’alignement SPF/DKIM. Des recommandations sont fournies pour éviter des rejets inappropriés dans ces cas particuliers.

## Pourquoi cette Nouvelle Version ?

- **Retours d’Expérience et Leçons Apprises**  
  Depuis 2015, le déploiement de DMARC a permis de constater certaines limites (par exemple, des erreurs de configuration fréquentes ou des difficultés liées aux flux de courriels indirects). DMARCbis vise à corriger ces insuffisances.

- **Simplification et Robustesse de l’Implémentation**  
  En clarifiant la spécification et en améliorant les mécanismes de découverte du domaine organisationnel, la nouvelle version rend l’implémentation de DMARC plus simple et plus fiable pour tous les acteurs.

- **Passage vers une Norme Officielle**  
  Alors que RFC 7489 avait un statut informatif, DMARCbis est destiné à devenir une norme officielle (Standards Track). Cela vise à uniformiser les implémentations et à encourager une adoption plus large du protocole.

- **Adaptation aux Enjeux Actuels de Sécurité des Courriels**  
  La mise à jour tient compte des évolutions de l’écosystème des courriels et des besoins actuels en matière de sécurité, notamment pour mieux gérer les cas complexes (transferts, listes de diffusion) et garantir une meilleure interopérabilité entre les systèmes.

## Conclusion

DMARCbis représente une évolution naturelle du protocole DMARC, apportant des améliorations significatives pour renforcer l’authentification et la sécurité des courriels. En clarifiant la spécification, en améliorant la détermination du domaine organisationnel et en simplifiant l’implémentation via de nouveaux tags, DMARCbis vise à rendre le protocole plus robuste et mieux adapté aux exigences actuelles de l’écosystème des courriels.


# Pratique 

## Vérification du bon fonctionnement de la politique DMARC sur le domaine de l'université

On commence par vérifier la bonne mise en place d'une politique DMARC dans l'enregistrement TXT du nom de domaine `usherbrooke.ca`.

*La commande a été effectuée le 10/02/2025 à 7:35 AM*


`dig TXT _dmarc.usherbrooke.ca +short` 

Cette commande utilise l'outil dig afin de retourner seulement la partie DMARC qui se situe sous ` _dmarc.nomDeDomaine` de l'enregistrement TXT. 

En voici la sortie : 

` "v=DMARC1; p=none; rua=mailto:dmarc_agg@vali.email, mailto:ms365-dmarc-rua@usherbrooke.ca; ruf=mailto:ms365-dmarc-ruf@usherbrooke.ca;" `


Ainsi, on remarque que l'université utilise DMARC, a bien configuré des courriels pour l'envoi des rapports, cependant, la politique est configurée sur `p=none`. Il n'y a donc pas de vérification DMARC qui s'effectue. 


Sachant que DMARC repose sur SPF et DKIM. Il faut aussi vérifier leur présence et leur bon fonctionnement.

`dig TXT usherbrooke.ca +short `

Ce qui nous retourne *abrégé pour lisibilité* :

`"v=spf1 include:spf.protection.outlook.com ip4:132.210.0.0/16 a:b.spf.service-now.com a:c.spf.service-now.com a:d.spf.service-now.com include:_spf2.usherbrooke.ca -all"`

Cette configuration semble correcte, la politique est bien sur `-all` ce qui bloque tout serveur non listé dans la politique. 


On peut vérifier la signature DKIM en regardant une en-tête de courriel : 

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=usherbrooke.ca;
 s=selector1;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=femt5K3LUCAMw7vEjTI+xYAxdBNS8+6Ogcr3BQkqzHo=;
 b=SUu7vo0CM6Y90IJNadRl2UJzcSYpVYSHXLQK+L8kqtcTYvsZ7Y8CMIZRkfMVNo3X4dT3tpY+eI7cbyD2jaBXzbi5NOh92ME48p3oIeEIMq4lsboiOlvnCyp0D6qRWR69waI8Y/QlwO4cBqwu4/IubhisbZe1HIHZIAh4OIGva6Bja+9Guq72zn2em2kLig4nUgI5DsHNjq4ciWjUybOwt5aF5SDlPs/ZiULBrzn48KfKfahMbLrNsLsTdWU5KKFOlg+3gDILsjSvtMWEwPBQPnekYauZx4tuguy7z+YbN92Y+NDx3/IrIr4I8xgn+2K2WJahZ4L+PLwtkTwtweTxmA==


Signature Information:
v= Version:         1
a= Algorithm:       rsa-sha256
c= Method:          relaxed/relaxed
d= Domain:          usherbrooke.ca
s= Selector:        selector1
q= Protocol:        
```

Concernant le point de confiance et le certificat utilisé, on utilise l'outil openssl pour se connecter au domaine et récupérer les informations. 

`openssl s_client -connect usherbrooke.ca:443 -servername usherbrooke.ca | openssl x509 -noout -issuer -subject`


Ce qui nous donne : 
```
Connecting to 132.210.7.145
depth=2 C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust RSA Certification Authority
verify return:1
depth=1 C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Extended Validation Secure Server CA
verify return:1
depth=0 serialNumber=977000, jurisdictionC=CA, jurisdictionST=Quebec, businessCategory=Government Entity, C=CA, ST=Québec, O=Université de Sherbrooke, CN=www.usherbrooke.ca
verify return:1
issuer=C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Extended Validation Secure Server CA
subject=serialNumber=977000, jurisdictionC=CA, jurisdictionST=Quebec, businessCategory=Government Entity, C=CA, ST=Québec, O=Université de Sherbrooke, CN=www.usherbrooke.ca
```

Et enfin, la dernière partie est l'enregistrement DNS : 


`whois usherbrooke.ca `

Nous retrouvons beaucoup d'informations : 

```
Domain Name: usherbrooke.ca
Registry Domain ID: D52743-CIRA
Registrar WHOIS Server: whois.ca.fury.ca
Registrar URL: www.webdomaine.ca
Updated Date: 2021-11-18T19:11:53Z
Creation Date: 2000-11-20T18:14:21Z
Registry Expiry Date: 2029-12-01T05:00:00Z
Registrar: A.R.C. Informatique Inc.
Registrar IANA ID: not applicable
Registrar Abuse Contact Email: mona@arcinfo.qc.ca
Registrar Abuse Contact Phone: +1.4185459224
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registry Registrant ID: 347340-CIRA
Registrant Name: Claude Poulin
Registrant Organization: Universite de Sherbrooke
Registrant Street: 2500  boulevard Universite, Service des technologies de l'information
Registrant City: Sherbrooke
Registrant State/Province: QC
Registrant Postal Code: J1K2R1
Registrant Country: CA
Registrant Phone: +1.8198218000
Registrant Phone Ext:
Registrant Fax: +1.8198218045
Registrant Fax Ext:
Registrant Email: dns-contact-adm@listes.usherbrooke.ca
Registry Admin ID: 101800458-CIRA
Admin Name: Claude Poulin
Admin Organization: Universite de Sherbrooke
Admin Street: 2500 boulevard Universite, Service des technologies de l'information
Admin City: Sherbrooke
Admin State/Province: QC
Admin Postal Code: J1K2R1
Admin Country: CA
Admin Phone: +1.8198218000
Admin Phone Ext:
Admin Fax: +1.8198218045
Admin Fax Ext:
Admin Email: dns-contact-adm@listes.usherbrooke.ca
Registry Tech ID: 101800739-CIRA
Tech Name: Steeve Gagnon
Tech Organization: Universite de Sherbrooke
Tech Street: 2500 boulevard Universite, Service des technologies de l'information
Tech City: Sherbrooke
Tech State/Province: QC
Tech Postal Code: J1K2R1
Tech Country: CA
Tech Phone: +1.8198218000
Tech Phone Ext:
Tech Fax: +1.8198218045
Tech Fax Ext:
Tech Email: dns-contact-tech@listes.usherbrooke.ca
```


Réception d'un courriel, les différentes étapes et relations entre les protocoles: 

```
├── 1. Connexion SMTP et réception par le serveur (MTA)
│   ├── a. Établissement de la connexion (handshake SMTP)
│   ├── b. Négociation de la sécurité (STARTTLS/TLS)
│   │      └── → Vérification du certificat SSL/TLS du serveur expéditeur
│   └── c. Transmission du courriel (DATA)
│
├── 2. Traitement initial par le serveur de réception (MTA/MDA)
│   ├── a. Extraction de l'adresse d'enveloppe (MAIL FROM)
│   │      └── → Vérification SPF :
│   │             • Le serveur de réception interroge le DNS du domaine MAIL FROM
│   │             • Vérifie si l'IP du serveur expéditeur est autorisée (v=spf1 …)
│   │             • Retourne un résultat : pass, softfail, ou fail
│   ├── b. Extraction de l'en-tête "From" (RFC5322.From)
│   └── c. Recherche d'une signature DKIM dans les en-têtes
│          └── Vérification DKIM :
│                • Le serveur récupère la clé publique via DNS (sélecteur._domainkey.domaine)
│                • Vérifie que la signature correspond au contenu et n'a pas été altérée
│                • Retourne pass ou fail
│
├── 3. Application de DMARC
│   ├── a. Utilisation de l'adresse visible dans "From" comme domaine principal
│   ├── b. Vérification d’alignement :
│   │      • Comparaison entre l'adresse du champ From et :
│   │             - Le domaine validé par SPF
│   │             - Le domaine utilisé dans la signature DKIM
│   ├── c. Détermination du résultat DMARC :
│   │      • Si au moins SPF ou DKIM réussit ET sont alignés avec From → DMARC pass
│   │      • Sinon, en fonction de la politique publiée (p=none, quarantine, reject) → action recommandée
│   └── d. Génération de rapports (agrégés et/ou de défaillance) envoyés au propriétaire du domaine
│
└── 4. Autres vérifications et filtrages
    ├── a. Analyse du contenu (anti-spam, anti-phishing)
    ├── b. Vérification de la réputation de l'IP expéditrice
    └── c. Application de politiques locales supplémentaires
```
