# Assistant documentaire sécurisé (RAG) en microservices Java

Projet *Ingénierie des Systèmes Sécurisés* — ENSIAS, 2026–2027.

---

## 1. Qu'est-ce qu'un RAG ?

Un **RAG** (*Retrieval-Augmented Generation*, génération augmentée par la recherche) est un assistant qui répond aux questions **à partir de vos propres documents**, et non de ce que le modèle d'IA a appris ailleurs.

Il fonctionne en deux temps :

1. **Indexation** : chaque document déposé est découpé en petits passages, transformés en vecteurs (une représentation numérique du sens) et rangés dans une base vectorielle.
2. **Question** : la question est elle aussi transformée en vecteur ; on retrouve les passages les plus proches, puis on les donne au modèle d'IA, qui rédige une réponse appuyée sur ces seuls passages.

## 2. Le projet

Nous avons construit un tel assistant pour une entreprise, où chaque document n'est destiné qu'à certains groupes (finance, RH…). Le problème devient alors un problème de **sécurité** :

- seul un utilisateur connecté peut s'en servir ;
- il ne peut faire que ce que son rôle autorise ;
- il ne doit **jamais** recevoir une réponse tirée d'un document qui n'est pas destiné à son groupe ;
- les secrets contenus dans les documents ne doivent pas ressortir, même si on essaie de piéger l'IA.

L'application est découpée en **microservices Java** (Java 21, Spring Boot, Spring Security), déployés sur **Kubernetes**, selon le principe **Zero Trust** : aucun service ne fait confiance à un autre sans vérifier son identité.

---

## 3. Comment nous l'avons fait

### Les services

| Service | Rôle |
|---|---|
| `gateway` | Porte d'entrée unique et interface web. Vérifie le jeton et le rôle de l'utilisateur, puis transmet la requête au bon service. |
| `uaa-service` | Service d'authentification. Vérifie le mot de passe, limite les tentatives et signe le jeton de connexion. |
| `ingestion-service` | Reçoit un document, masque les secrets et données personnelles, le découpe, le vectorise et l'indexe avec ses groupes autorisés. |
| `rag-service` | Reçoit une question, bloque les injections de prompt, cherche les passages autorisés, interroge le modèle (Groq) et filtre la réponse. |
| `qdrant` | Base vectorielle où sont rangés les passages. |
| `services/common` | Code partagé : vérification des jetons, rôles, connexions mTLS, journal d'audit. |

### Le parcours d'une requête

```
Navigateur ──HTTPS──▶ gateway ──mTLS──▶ uaa-service           (connexion)
                         │
                         ├──mTLS──▶ ingestion-service ──mTLS──▶ qdrant   (dépôt d'un document)
                         │
                         └──mTLS──▶ rag-service ──mTLS──▶ qdrant         (question)
                                         └──HTTPS──▶ API Groq
```

1. **Connexion** : l'utilisateur envoie son identifiant et son mot de passe. `uaa-service` les vérifie et renvoie un **jeton JWT** qui contient son nom, ses rôles et ses groupes, valable 15 minutes.
2. **Dépôt** : `alice` (groupe `finance`) dépose un document pour le groupe `finance`. `ingestion-service` vérifie qu'elle appartient bien à ce groupe, remplace `password=hunter2` par `[REDACTED]`, puis indexe le document avec l'étiquette `finance`.
3. **Question** : `bob` (groupe `rh`) pose une question sur le budget. `rag-service` ne cherche que parmi les passages étiquetés `rh` : il ne trouve rien et répond qu'aucun document ne le permet.

### Les mécanismes de sécurité

| Mécanisme | Ce qu'il garantit | Comment |
|---|---|---|
| **JWT signé (RS256)** | L'identité de l'utilisateur | Seul `uaa-service` possède la clé privée et peut signer. Tous les autres services vérifient avec la clé publique : un jeton modifié ou falsifié est refusé (401). |
| **RBAC (rôles)** | Ce que l'utilisateur peut faire | Rôle `INGEST` pour déposer, `QUERY` pour interroger. Vérifié par la passerelle **et** par chaque service (403 sinon). |
| **ABAC (groupes)** | Quels documents il peut lire | Les groupes viennent du jeton signé. Le filtre est appliqué directement dans la recherche Qdrant. |
| **mTLS** | L'identité de chaque service | Chaque service a son propre certificat, délivré par une autorité privée (cert-manager). Un pod sans certificat est rejeté dès la connexion. |
| **NetworkPolicy** | Qui peut parler à qui | Tout est bloqué par défaut. Seuls les échanges prévus sont autorisés ; par exemple `ingestion-service` ne peut joindre ni `rag-service` ni Internet. |
| **HTTPS + en-têtes** | La sécurité côté navigateur | HTTP redirige vers HTTPS. En-têtes CSP, HSTS et X-Frame-Options. |
| **Protection des mots de passe** | La résistance aux attaques | Mots de passe hachés (PBKDF2 salé). Après plusieurs échecs, les tentatives sont bloquées (429). |
| **Protection de l'IA** | Pas de fuite par le modèle | Les injections de prompt (« ignore previous instructions… ») sont refusées (400). Les secrets sont masqués avant l'indexation et la réponse est filtrée. |
| **Journal d'audit** | La traçabilité | Chaque action (connexion, dépôt, question, blocage) est journalisée en JSON avec l'utilisateur issu du jeton. |

### La chaîne DevSecOps (GitHub Actions)

À chaque push, `.github/workflows/devsecops.yml` vérifie automatiquement le projet :

| Étape | Outil | Rôle |
|---|---|---|
| Secrets | TruffleHog | Détecte les mots de passe ou clés oubliés dans l'historique Git |
| SAST | Semgrep | Analyse le code Java, les Dockerfile et les fichiers Kubernetes |
| SCA | OWASP Dependency-Check, Trivy | Détecte les dépendances vulnérables et les mauvaises configurations |
| Tests | `mvn verify` | Lance les 22 tests de sécurité JUnit |
| Images | Docker, Trivy | Construit les 4 images, les scanne et génère leur SBOM (CycloneDX) |

Une étape en échec bloque la chaîne. **Dependabot** propose en plus chaque semaine les mises à jour des dépendances Maven, des images Docker et des actions GitHub.

---

## 4. Lancer le projet

### Versions utilisées

Le projet a été développé et testé avec les versions suivantes. Des versions plus récentes devraient fonctionner, mais Java doit être en version 21 ou plus.

| Composant | Version |
|---|---|
| Java (JDK) | 21 |
| Spring Boot (avec Spring Security et Spring MVC) | 4.1.2 |
| Nimbus JOSE + JWT | 10.9.1 |
| Maven (via le wrapper `mvnw`) | 3.9.11 |
| IntelliJ IDEA | 2026.3 |
| Qdrant | v1.12.4 |
| Docker | 29.9.2 |
| k3d / k3s | v5.9.0 / v1.35.5-k3s1 |
| kubectl | v1.36.1 |
| cert-manager | v1.16.2 |
| OpenSSL | 3.5.9 |
| Images Docker | `maven:3.9-eclipse-temurin-21` (build), `gcr.io/distroless/java21-debian13:nonroot` (exécution) |

### Ouvrir le code dans IntelliJ IDEA

1. `File > Open`, puis sélectionner le dossier du projet (celui qui contient `pom.xml`). Choisir **Open as Project** et faire confiance au projet.
2. IntelliJ importe automatiquement les 5 modules Maven (`common`, `uaa-service`, `gateway`, `ingestion-service`, `rag-service`).
3. Le projet nécessite **Java 21**. Si IntelliJ le signale, aller dans `File > Project Structure > Project > SDK > Download JDK…` et choisir la version 21.
4. Lancer les tests avec la configuration **« Tests de securite (mvn verify) »** en haut à droite, ou en ligne de commande avec `./mvnw verify` (`mvnw.cmd verify` sous Windows). Maven n'a pas besoin d'être installé : le wrapper le télécharge.

### Lancer l'application sans Kubernetes (depuis IntelliJ)

Prérequis : Java 21, Docker (pour la base Qdrant) et Bash avec openssl 3 (Git Bash sous Windows).

**Étape 1 : générer les clés JWT et les comptes de démonstration.** Dans un terminal, à la racine du projet :

```bash
bash scripts/gen-secrets.sh --local
```

Le script crée le dossier `.local/` (ignoré par Git) : `private.pem` et `public.pem` (clés RSA du JWT), `users.json` (comptes, mots de passe hachés) et `demo-credentials` (mots de passe en clair d'`alice` et `bob`).

**Étape 2 : démarrer Qdrant**, la base vectorielle :

```bash
docker run -d --name qdrant -p 6333:6333 qdrant/qdrant:v1.12.4
```

**Étape 3 : démarrer les 4 microservices.** Dans IntelliJ, choisir la configuration **« Tous les services (local) »** en haut à droite, puis cliquer sur ▶. Elle démarre, avec les bonnes variables d'environnement :

| Service | Port | Rôle |
|---|---|---|
| `uaa-service` | 8001 | Vérifie le mot de passe et signe le JWT |
| `ingestion-service` | 8002 | Reçoit et indexe les documents |
| `rag-service` | 8003 | Répond aux questions (réponses simulées par défaut) |
| `gateway` | 8080 | Point d'entrée et interface web |

Les services peuvent aussi être lancés un par un avec les configurations « 1 - uaa-service (local) » à « 4 - gateway (local) », dans cet ordre.

**Étape 4 : ouvrir <http://localhost:8080/>** et se connecter avec `alice` ou `bob`. Les mots de passe sont dans `.local/demo-credentials`.

**Étape 5 (facultatif) : tester l'API en ligne de commande.**

```bash
PW=$(grep '^alice:' .local/demo-credentials | cut -d' ' -f2)
TOKEN=$(curl -s http://localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"alice\",\"password\":\"$PW\"}" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
curl -i http://localhost:8080/api/query                                # 401 : pas de jeton
curl -i http://localhost:8080/api/query -H "Authorization: Bearer faux" # 401 : jeton invalide
```

Pour tout arrêter : bouton ■ dans IntelliJ, puis `docker rm -f qdrant`.

> **Limites de ce mode.** Le JWT RS256, le RBAC (rôles) et l'ABAC (groupes) sont actifs, car ils sont dans le code Java. En revanche, les services communiquent en HTTP simple : le **mTLS**, les **NetworkPolicies** et l'**ingress HTTPS** n'existent que dans Kubernetes. Pour les voir, utiliser le déploiement ci-dessous.

### Déployer en local (Kubernetes, sécurité complète)

Prérequis : Docker, k3d, kubectl, openssl et Bash (Git Bash sous Windows).

```bash
bash scripts/deploy-local.sh
```

Le script crée un cluster Kubernetes local de 3 nœuds, installe cert-manager, construit les images, génère les clés et les comptes de démonstration, puis déploie tout.

Ouvrir ensuite **<https://localhost:8443/>**. Les mots de passe sont dans `.demo-credentials` :

| Compte | Rôles | Groupe |
|---|---|---|
| `alice` | `INGEST`, `QUERY` | `finance` |
| `bob` | `QUERY` | `rh` |

Sans clé, les réponses de l'IA sont simulées. Pour de vraies réponses, créer une clé gratuite sur <https://console.groq.com/keys>, puis :

```bash
read -rs GROQ_API_KEY
kubectl -n rag create secret generic groq-api-key --from-literal=key="$GROQ_API_KEY"
unset GROQ_API_KEY
bash scripts/deploy-local.sh
```

## 5. Vérifier la sécurité

- **Tests automatiques** : `mvn verify` (22 tests JUnit, sans cluster).
- **Tests sur le cluster** : `tests/cluster/mtls-test.yaml` et `tests/cluster/netpol-test.yaml`.

| Essai | Résultat attendu |
|---|---|
| Requête sans jeton, ou avec un faux jeton | 401 |
| `bob` essaie de déposer un document | 403 |
| `bob` interroge un document `finance` | aucune source |
| Mauvais mot de passe répété | 401, puis 429 |
| Injection de prompt | 400 |
| Question sur un mot de passe masqué | la valeur n'apparaît jamais |
| Pod sans certificat | connexion TLS refusée |
| `ingestion-service` vers Internet | bloqué |

## 6. Organisation du dépôt

```
services/        les 4 microservices et le code commun
k8s/             déploiement Kubernetes (PKI, services, Qdrant, NetworkPolicy, HTTPS)
scripts/         déploiement, génération des clés, connexion
tests/cluster/   tests mTLS et réseau sur le cluster
```

## 7. Limites

- Un jeton volé reste valide jusqu'à son expiration (15 minutes).
- Changer la clé de signature impose un redémarrage des services.
- La limite de tentatives est gardée en mémoire, séparément sur chaque réplica.
- Les documents de Qdrant sont perdus au redémarrage.
- Le journal d'audit reste dans les logs des pods.
