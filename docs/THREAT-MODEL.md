# Modèle de menaces (STRIDE) et évaluation des risques (DREAD)

Périmètre : navigateur → Traefik → `gateway` → `uaa-service` / `ingestion-service` / `rag-service` → `qdrant`, plus l'appel à l'API Groq.

Évaluation DREAD, comme dans le cours : chaque critère est noté de 0 à 10, et
**Risque = (Dommage + Reproductibilité + Exploitabilité + Utilisateurs affectés + Découvrabilité) / 5**.

| STRIDE | Menace | D | R | E | A | D | Risque /10 | Contre-mesure | Traitement |
|---|---|---|---|---|---|---|---|---|---|
| **S**poofing | JWT falsifié ou volé utilisé sur un service | 9 | 6 | 5 | 8 | 5 | **6,6** | RS256, émetteur, audience et expiration vérifiés par la passerelle **et** par chaque service ; jeton de 15 min | Réduire |
| **S**poofing | Un pod se fait passer pour la passerelle | 8 | 4 | 4 | 8 | 3 | **5,4** | mTLS (CA privée) + NetworkPolicy (seule la passerelle joint ingestion et rag) | Réduire |
| **T**ampering | Requête modifiée entre services | 7 | 3 | 3 | 7 | 4 | **4,8** | TLS sur chaque saut, HTTPS à l'entrée | Réduire |
| **T**ampering | Document piégé ou injection de prompt | 6 | 8 | 7 | 6 | 7 | **6,8** | Validation, masquage, balises `<doc>`, détection d'injection | Réduire |
| **R**epudiation | Un utilisateur nie un dépôt ou une question | 5 | 5 | 5 | 4 | 4 | **4,6** | Journal d'audit ; l'utilisateur vient du jeton signé | Réduire |
| **I**nformation disclosure | Lecture du document d'un autre groupe | 9 | 8 | 7 | 9 | 7 | **8,0** | ABAC : filtre Qdrant construit côté serveur à partir du claim `groups` signé | Réduire |
| **I**nformation disclosure | Secrets ou données personnelles envoyés à l'API externe | 8 | 7 | 6 | 7 | 5 | **6,6** | Masquage avant indexation, filtre de sortie, un seul service sortant | Réduire |
| **I**nformation disclosure | Mot de passe et jeton interceptés sur le réseau | 8 | 6 | 5 | 8 | 6 | **6,6** | HTTPS à l'entrée, redirection HTTP → HTTPS, HSTS | Réduire |
| **D**enial of service | Force brute, envois surdimensionnés, abus de quota | 5 | 8 | 7 | 6 | 7 | **6,6** | Limite de tentatives, limites de taille, 1 Mio max à l'entrée | Réduire |
| **E**levation of privilege | Pod compromis qui se déplace latéralement | 8 | 4 | 4 | 8 | 3 | **5,4** | NetworkPolicy *default-deny*, aucun flux ingestion ↔ rag, non-root, FS en lecture seule, `drop ALL` | Réduire |
| **E**levation of privilege | Utilisateur sans le rôle requis | 7 | 7 | 6 | 7 | 6 | **6,6** | RBAC à la passerelle et dans chaque service, `denyAll` par défaut | Réduire |

Risques résiduels acceptés (voir README, section 7) : pas de révocation des jetons, limite de tentatives par réplica, audit en mémoire des pods, sortie Internet filtrée par IP.
