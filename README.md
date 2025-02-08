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
