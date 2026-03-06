# Guide d'Observabilite - LLM Attack Lab

Ce guide fournit une documentation complete pour l'infrastructure d'observabilite du LLM Attack Lab, incluant le monitoring en temps reel, les alertes de securite, et la visualisation des attaques ML/LLM.

## Table des matieres

- [Vue d'ensemble](#vue-densemble)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Stack Technologique](#stack-technologique)
- [Dashboards Grafana](#dashboards-grafana)
- [Metriques](#metriques)
- [Alerting](#alerting)
- [Configuration Avancee](#configuration-avancee)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

---

## Vue d'ensemble

L'infrastructure d'observabilite du LLM Attack Lab permet de:

- **Detecter en temps reel** les attaques adversariales, prompt injections et jailbreaks
- **Visualiser** les metriques de securite via des dashboards Grafana interactifs
- **Alerter** automatiquement sur les incidents de securite critiques
- **Analyser** les patterns comportementaux suspects (model extraction, data poisoning)
- **Auditer** toutes les interactions avec les modeles ML/LLM

### Capacites de Detection

| Type d'Attaque | Detection | Temps de Detection | Metriques Cles |
|----------------|-----------|-------------------|----------------|
| Prompt Injection | Temps reel | < 1s | `llm_prompt_injection_score` |
| Jailbreak | Temps reel | < 1s | `llm_output_policy_violations_total` |
| Adversarial Inputs | Temps reel | < 5s | `ml_input_reconstruction_error` |
| Model Extraction | Comportemental | ~10min | `ml_api_queries_total` |
| Data Poisoning | Drift detection | ~15min | `ml_prediction_distribution_psi` |
| System Prompt Extraction | Temps reel | < 1s | `llm_prompt_similarity_to_system` |

---

## Quick Start

### 1. Lancer le stack complet

```bash
# Demarrer tous les services d'observabilite
docker-compose up -d

# Verifier que tous les services sont up
docker-compose ps
```

### 2. Acceder aux interfaces

| Service | URL | Credentials |
|---------|-----|-------------|
| **Grafana** | http://localhost:3000 | `admin` / `llmattacklab` |
| **VictoriaMetrics** | http://localhost:8428 | - |
| **Application** | http://localhost:8081 | - |
| **Metrics (Prometheus)** | http://localhost:8000/metrics | - |

### 3. Verifier la collecte de metriques

```bash
# Verifier que les metriques sont collectees
curl -s http://localhost:8000/metrics | grep llm_

# Verifier VictoriaMetrics
curl -s "http://localhost:8428/api/v1/query?query=up"
```

### 4. Acceder aux dashboards

1. Ouvrir Grafana: http://localhost:3000
2. Se connecter avec `admin` / `llmattacklab`
3. Aller dans **Dashboards** > **Browse**
4. Selectionner un dashboard:
   - **LLM Attack Lab** - Vue operationnelle
   - **ML/LLM Security Metrics** - Detection de securite
   - **Documentation** - Documentation integree

---

## Architecture

```
+------------------------------------------------------------------+
|                    LLM Attack Lab Application                      |
|  +------------------+  +-------------------+  +-----------------+  |
|  | Attack Engine    |  | Defense System    |  | Web Interface   |  |
|  |                  |  |                   |  |                 |  |
|  | - Prompt Inject  |  | - Guardrails      |  | - Dashboard     |  |
|  | - Jailbreak      |  | - Output Filter   |  | - API REST      |  |
|  | - Poisoning      |  | - Input Sanitizer |  | - Metrics       |  |
|  +--------+---------+  +---------+---------+  +--------+--------+  |
|           |                      |                     |           |
|           +----------------------+---------------------+           |
|                                  |                                 |
|  +---------------------------+   |   +---------------------------+ |
|  | MetricsCollector         |   |   | SecurityMetricsCollector  | |
|  | - Counters               |<--+-->| - Adversarial metrics     | |
|  | - Histograms             |       | - Behavior metrics        | |
|  | - Gauges                 |       | - LLM security metrics    | |
|  +------------+-------------+       +------------+--------------+ |
|               |                                  |                 |
|               +----------------------------------+                 |
|                                |                                   |
|                    +-----------v-----------+                       |
|                    |    OTelManager        |                       |
|                    | (OpenTelemetry SDK)   |                       |
|                    +-----------+-----------+                       |
+----------------------------|--------------------------------------|+
                             |                                      |
                             | OTLP (gRPC :4317 / HTTP :4318)       |
                             |                                      |
              +--------------v--------------+                       |
              |   OpenTelemetry Collector   |                       |
              |                             |                       |
              | - Receivers: otlp, prom     |                       |
              | - Processors: batch, memory |                       |
              | - Exporters: prometheusrw   |                       |
              +--------------+--------------+                       |
                             |                                      |
                             | Remote Write                         |
                             |                                      |
              +--------------v--------------+       +---------------+
              |     VictoriaMetrics         |       |    vmAgent    |
              |                             |<------| (Scraper)     |
              | - Time Series Database      |       +---------------+
              | - 30 days retention         |              ^
              | - PromQL compatible         |              |
              +--------------+--------------+              |
                             |                    Scrape :8000, :8428
                             |                             |
              +--------------v--------------+              |
              |        Grafana              |--------------+
              |                             |
              | - 2 Dashboards pre-config   |
              | - Auto-refresh 5-10s        |
              | - Variable templates        |
              +-----------------------------+
```

### Flux de donnees

1. **Collection**: L'application genere des metriques via `MetricsCollector` et `SecurityMetricsCollector`
2. **Export**: OpenTelemetry SDK expose les metriques au format Prometheus sur `:8000`
3. **Scraping**: vmAgent et OTel Collector scrapent les endpoints de metriques
4. **Storage**: VictoriaMetrics stocke les time series (retention 30 jours)
5. **Visualization**: Grafana query VictoriaMetrics via PromQL
6. **Alerting**: Les regles Prometheus evaluent les conditions d'alerte

---

## Stack Technologique

### Services Docker

| Service | Image | Port(s) | Role |
|---------|-------|---------|------|
| `llm-attack-lab` | `python:3.11-slim` | 8081, 8000 | Application principale |
| `otel-collector` | `otel/opentelemetry-collector-contrib:0.91.0` | 4317, 4318, 8888, 8889, 13133 | Pipeline de telemetrie |
| `victoriametrics` | `victoriametrics/victoria-metrics:v1.96.0` | 8428 | Base de donnees time series |
| `grafana` | `grafana/grafana:10.2.3` | 3000 | Visualisation et dashboards |
| `vmagent` | `victoriametrics/vmagent:v1.96.0` | 8429 | Scraping Prometheus |

### Pourquoi ce choix de stack?

| Composant | Avantages |
|-----------|-----------|
| **VictoriaMetrics** | 10x plus rapide que Prometheus, compression superieure, compatible PromQL |
| **OpenTelemetry** | Standard CNCF, vendor-neutral, supporte traces/metrics/logs |
| **Grafana** | Interface intuitive, ecosysteme de plugins, alerting natif |
| **vmAgent** | Leger, haute performance, dedup automatique |

---

## Dashboards Grafana

### Dashboard 1: LLM Attack Lab (Principal)

**URL**: http://localhost:3000/d/llm-attack-lab-main

**Refresh**: 5 secondes

Ce dashboard fournit une vue operationnelle de l'activite du lab.

#### Section: Overview

| Panel | Type | Description |
|-------|------|-------------|
| Total Attacks | Stat | Compteur total des attaques simulees |
| Attack Success Rate | Stat | % d'attaques reussies (vert < 50%, rouge > 80%) |
| Detection Rate | Stat | % d'attaques detectees (rouge < 50%, vert > 80%) |
| System Status | Stat | SAFE ou COMPROMISED |
| Security Level | Stat | NONE/LOW/MEDIUM/HIGH/MAXIMUM |
| Total Requests | Stat | Nombre total de requetes traitees |

#### Section: Attack Metrics

| Panel | Type | Description |
|-------|------|-------------|
| Attack Rate by Type | Time series | Taux d'attaques par type (prompt_injection, jailbreak, etc.) |
| Attacks by Type | Pie chart | Distribution des attaques par categorie |
| Attack Duration (p95) | Time series | Latence p95 des attaques par type |

#### Section: Defense Metrics

| Panel | Type | Description |
|-------|------|-------------|
| Defense Actions Rate | Time series | Actions defensives declenchees par seconde |
| Defense by Threat Level | Pie chart | Distribution par niveau de menace |
| Request Latency | Time series | Latence p50/p95/p99 des requetes |

#### Section: System Health

| Panel | Type | Description |
|-------|------|-------------|
| Request Rate | Time series | Requetes par seconde |
| Memory Usage | Time series | Consommation memoire de l'application |

---

### Dashboard 2: ML/LLM Security Metrics (Securite)

**URL**: http://localhost:3000/d/ml-security-metrics

**Refresh**: 10 secondes

Ce dashboard se concentre sur la detection d'attaques ML/LLM specifiques.

#### Section: Security Overview

| Panel | Metrique | Seuils |
|-------|----------|--------|
| Critical Alerts (1h) | `security_alerts_total{severity="critical"}` | Jaune > 5, Rouge > 10 |
| Warning Alerts (1h) | `security_alerts_total{severity="warning"}` | Jaune > 10, Orange > 25 |
| Injection Score (p95) | `llm_prompt_injection_score` | Jaune > 0.5, Rouge > 0.85 |
| Distribution PSI | `ml_prediction_distribution_psi` | Jaune > 0.1, Rouge > 0.2 |
| Reconstruction Error (p95) | `ml_input_reconstruction_error` | Jaune > 2, Rouge > 2.5 |
| Policy Violations (1h) | `llm_output_policy_violations_total` | Jaune > 50, Rouge > 100 |

#### Section: Adversarial Detection

| Panel | Description | Attaques detectees |
|-------|-------------|-------------------|
| Input Reconstruction Error | Erreur autoencoder (FGSM, PGD) | Adversarial inputs |
| Embedding Distance to Centroid | Distance OOD aux centroides | Out-of-distribution |
| Prediction Stability Score | Variance sous perturbation | Adversarial inputs |
| Unstable Predictions Rate | Taux de predictions instables | FGSM, PGD, CW |
| Prediction Confidence Distribution | Distribution des scores de confiance | High-confidence adversarial |

#### Section: Behavior Analysis

| Panel | Description | Attaques detectees |
|-------|-------------|-------------------|
| Distribution Drift (PSI) | Population Stability Index | Data poisoning, Model drift |
| Per-Class Accuracy vs Baseline | Accuracy par classe vs reference | Targeted poisoning |
| Predictions by Class Distribution | Distribution des predictions | Class imbalance attacks |
| API Queries per User (10min) | Volume de requetes par utilisateur | Model extraction |

#### Section: LLM Security

| Panel | Description | Attaques detectees |
|-------|-------------|-------------------|
| Prompt Injection Score | Score du detecteur d'injection | Prompt injection |
| System Prompt Similarity | Similarite avec le system prompt | System prompt extraction |
| Policy Violations by Type | Violations par type et severite | Jailbreak, Harmful content |
| Tool Calls by Name/User | Appels d'outils dangereux | Agent attacks |
| Tool Calls: Safe vs Dangerous | Ratio outils safe/dangereux | Privilege escalation |

#### Section: Attack Coverage Matrix

Table montrant l'etat en temps reel de chaque type de detection:

| Detection Type | Metrique | Statut |
|---------------|----------|--------|
| Adversarial | `ml_input_reconstruction_error` | Active/Inactive |
| OOD | `ml_embedding_distance_to_centroid` | Active/Inactive |
| Instability | `ml_unstable_predictions_total` | Active/Inactive |
| Drift | `ml_prediction_distribution_psi` | Active/Inactive |
| Injection | `llm_prompt_injection_score` | Active/Inactive |
| Jailbreak | `llm_output_policy_violations_total` | Active/Inactive |

---

### Dashboard 3: Documentation

**URL**: http://localhost:3000/d/llm-attack-lab-docs

**Refresh**: Aucun (contenu statique)

Ce dashboard integre toute la documentation du projet directement dans Grafana:

| Section | Contenu |
|---------|---------|
| README Principal | Presentation du projet, types d'attaques, installation |
| Quick Start | Guide de demarrage rapide |
| Capacites et Stack | Detection capabilities, stack technologique |
| Architecture | Diagramme d'architecture et flux de donnees |
| Catalogue des Metriques | Matrice de couverture, metriques adversarial/comportementales/LLM |
| Alerting | Alertes critiques et warning avec actions recommandees |
| Troubleshooting | Problemes courants et commandes de diagnostic |
| Best Practices | Recommandations cyber/observabilite |
| Configuration Avancee | Variables d'environnement, personnalisation des seuils |
| Requetes PromQL | Exemples de requetes utiles |
| References | Liens vers OWASP, MITRE ATLAS, documentation |

---

## Metriques

### Catalogue complet des metriques

#### Metriques Operationnelles

```promql
# Compteurs d'attaques
llm_attacks_total{attack_type, success, detected}
llm_requests_total
llm_defense_actions_total{action, threat_level}

# Latences
llm_attack_duration_seconds_bucket{attack_type}
llm_request_latency_seconds_bucket

# Etat systeme
llm_compromised_status          # 0 = SAFE, 1 = COMPROMISED
llm_security_level              # 0-4 (NONE to MAXIMUM)
```

#### Metriques de Securite ML

```promql
# Pattern Adversarial
ml_input_reconstruction_error_bucket{model_name, input_type}
ml_prediction_confidence_bucket{model_name, predicted_class}
ml_embedding_distance_to_centroid_bucket{model_name, layer}
ml_prediction_stability_score{model_name, perturbation_type}
ml_unstable_predictions_total{model_name, perturbation_type}

# Pattern Comportemental
ml_predictions_by_class_total{model_name, predicted_class}
ml_prediction_distribution_psi{model_name, reference_window}
ml_api_queries_total{user_id, ip_address, endpoint}
ml_accuracy_by_class{model_name, class_name}
```

#### Metriques de Securite LLM

```promql
# Detection d'injection
llm_prompt_injection_score_bucket{model_name, detection_method}

# Extraction de system prompt
llm_prompt_similarity_to_system_bucket{model_name}

# Violations de politique
llm_output_policy_violations_total{model_name, violation_type, severity}

# Appels d'outils
llm_tool_calls_total{tool_name, user_id, success, is_dangerous}
```

### Requetes PromQL utiles

```promql
# Taux d'attaques par type sur 5 minutes
sum by (attack_type) (rate(llm_attacks_total[5m]))

# Taux de succes des attaques
sum(llm_attacks_total{success="true"}) / sum(llm_attacks_total) * 100

# Score d'injection p95 sur 5 minutes
histogram_quantile(0.95, rate(llm_prompt_injection_score_bucket[5m]))

# Utilisateurs avec > 100 requetes en 10 minutes
sum by (user_id) (increase(ml_api_queries_total[10m])) > 100

# Drift PSI superieur au seuil
ml_prediction_distribution_psi > 0.2

# Erreur de reconstruction elevee avec haute confiance (adversarial suspect)
histogram_quantile(0.95, rate(ml_input_reconstruction_error_bucket[5m])) > 2.5
  AND
histogram_quantile(0.95, rate(ml_prediction_confidence_bucket[5m])) > 0.95
```

---

## Alerting

### Regles d'alerte configurees

Les alertes sont definies dans `/config/prometheus/rules/security_alerts.yml`.

#### Alertes Critiques (action immediate requise)

| Alerte | Condition | Action recommandee |
|--------|-----------|-------------------|
| `PromptInjectionDetected` | `injection_score > 0.85` | Bloquer la requete, logger l'incident |
| `SystemPromptExtractionAttempt` | `similarity > 0.7` | Bloquer, alerter l'equipe securite |
| `SuspiciousToolUsage` | `dangerous_calls > 5/5min` | Revoquer les permissions, investiguer |
| `AttackSuccessRateHigh` | `success_rate > 50%` | Renforcer les defenses |
| `CriticalSecurityAlerts` | `critical_alerts > 0` | Reponse incident immediate |

#### Alertes Warning (investigation requise)

| Alerte | Condition | Action recommandee |
|--------|-----------|-------------------|
| `PotentialAdversarialInput` | `recon_error > 2.5 AND conf > 0.95` | Analyser l'input, ajuster les seuils |
| `OutOfDistributionInput` | `distance > 3x threshold` | Logger, monitorer la tendance |
| `ModelDistributionDrift` | `PSI > 0.2 for 15m` | Verifier les donnees d'entree |
| `SuspiciousQueryPattern` | `queries > 100/10min` | Rate limiting, verification utilisateur |
| `LowDetectionRate` | `detection_rate < 50%` | Revoir les mecanismes de detection |

### Configuration des notifications

Pour configurer les notifications (Slack, PagerDuty, Email), editer la configuration Grafana:

```yaml
# Dans docker-compose.yaml, ajouter les variables d'environnement
environment:
  - GF_SMTP_ENABLED=true
  - GF_SMTP_HOST=smtp.example.com:587
  - GF_SMTP_USER=alerts@example.com
  - GF_SMTP_PASSWORD=password
```

Ou configurer via l'interface Grafana:
1. Aller dans **Alerting** > **Contact points**
2. Ajouter un nouveau contact point
3. Configurer le canal (Email, Slack, Webhook, etc.)
4. Tester la notification

---

## Configuration Avancee

### Variables d'environnement

```bash
# === Application ===
PROMETHEUS_METRICS_PORT=8000      # Port d'export des metriques
PROMETHEUS_PORT_AUTO=true         # Auto-selection du port si occupe
PROMETHEUS_PORT_RANGE=10          # Plage de ports a essayer

# === OpenTelemetry ===
OTEL_SERVICE_NAME=llm-attack-lab
OTEL_SERVICE_VERSION=1.0.0
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
OTEL_ENABLE_TRACING=true
OTEL_ENABLE_METRICS=true
OTEL_EXPORTER_OTLP_TIMEOUT=30
OTEL_METRIC_EXPORT_INTERVAL=15000

# === Auto-Stress Testing (pour demo) ===
AUTO_STRESS=true                  # Active la generation automatique de donnees
AUTO_STRESS_DELAY=5               # Delai avant demarrage (secondes)
AUTO_STRESS_POPULATE=100          # Nombre d'attaques initiales
AUTO_STRESS_BATCH=10              # Taille des batches
AUTO_STRESS_WORKERS=5             # Workers paralleles
AUTO_STRESS_ATTACK_RATIO=0.7      # Ratio d'attaques vs requetes normales
```

### Personnalisation des seuils

Modifier les seuils d'alerte dans le code:

```python
from llm_attack_lab.monitoring import get_security_metrics

metrics = get_security_metrics()

# Ajuster les seuils
metrics.set_threshold("ml_input_reconstruction_error", 3.0)
metrics.set_threshold("llm_prompt_injection_score", 0.90)
metrics.set_threshold("ml_api_queries_rate", 200)

# Definir une baseline
metrics.set_baseline(
    "ml_accuracy_by_class",
    value=0.95,
    labels={"model_name": "my_model", "class_name": "positive"}
)
```

### Ajout de nouvelles metriques

```python
from llm_attack_lab.monitoring import get_security_metrics

metrics = get_security_metrics()

# Enregistrer une metrique custom
metrics.record_custom_metric(
    name="my_custom_detection_score",
    value=0.75,
    metric_type="histogram",
    labels={"detector": "custom_v1"}
)
```

### Retention et stockage

```yaml
# Dans docker-compose.yaml, section victoriametrics
command:
  - '-retentionPeriod=30d'      # Retention par defaut
  - '-storage.minFreeDiskSpaceBytes=1GB'
  - '-search.maxUniqueTimeseries=300000'
```

Pour augmenter la retention:
```yaml
  - '-retentionPeriod=90d'      # 90 jours
```

---

## Troubleshooting

### Problemes courants

#### 1. Les metriques n'apparaissent pas dans Grafana

**Symptomes**: Dashboards vides, "No data"

**Diagnostic**:
```bash
# Verifier que l'application expose les metriques
curl -s http://localhost:8000/metrics | head -20

# Verifier que VictoriaMetrics recoit les donnees
curl -s "http://localhost:8428/api/v1/query?query=up"

# Verifier les logs du collecteur
docker-compose logs otel-collector | tail -50
```

**Solutions**:
- Redemarrer les services: `docker-compose restart`
- Verifier le reseau: `docker network inspect iattack_monitoring`
- Verifier les ports: `docker-compose ps`

#### 2. Alertes non declenchees

**Symptomes**: Les conditions sont remplies mais pas d'alerte

**Diagnostic**:
```bash
# Verifier que les regles sont chargees
curl -s http://localhost:8428/api/v1/rules

# Verifier l'etat des alertes
curl -s http://localhost:8428/api/v1/alerts
```

**Solutions**:
- Recharger les regles: Redemarrer VictoriaMetrics
- Verifier la syntaxe des regles PromQL
- Verifier les durations (for: 5m)

#### 3. Grafana ne se connecte pas a VictoriaMetrics

**Symptomes**: "Data source is not working"

**Diagnostic**:
```bash
# Tester la connexion depuis le container Grafana
docker-compose exec grafana wget -qO- http://victoriametrics:8428/api/v1/query?query=up
```

**Solutions**:
- Verifier le nom du service dans datasources.yaml
- Verifier que le service victoriametrics est up
- Utiliser `victoriametrics:8428` (nom du service, pas localhost)

#### 4. Metriques de securite a 0

**Symptomes**: Tous les compteurs de securite sont a zero

**Solutions**:
- Activer le stress testing: `AUTO_STRESS=true`
- Lancer manuellement: `python -m llm_attack_lab --demo`
- Generer des attaques via l'API:
```bash
curl -X POST http://localhost:8081/api/attack \
  -H "Content-Type: application/json" \
  -d '{"type": "prompt_injection", "payload": "ignore previous instructions"}'
```

### Logs utiles

```bash
# Logs de l'application
docker-compose logs -f llm-attack-lab

# Logs du collecteur OTel
docker-compose logs -f otel-collector

# Logs VictoriaMetrics
docker-compose logs -f victoriametrics

# Logs Grafana
docker-compose logs -f grafana
```

### Commandes de debug

```bash
# Verifier toutes les metriques exposees
curl -s http://localhost:8000/metrics | grep -E "^(llm_|ml_|security_)"

# Lister les series dans VictoriaMetrics
curl -s "http://localhost:8428/api/v1/series?match[]={__name__=~'llm_.*'}"

# Tester une requete PromQL
curl -s "http://localhost:8428/api/v1/query?query=sum(llm_attacks_total)"

# Verifier la sante du collecteur
curl -s http://localhost:13133/
```

---

## Best Practices

### 1. Nomenclature des metriques

```
<namespace>_<subsystem>_<name>_<unit>

Exemples:
- llm_attacks_total           (counter)
- llm_attack_duration_seconds (histogram)
- ml_prediction_distribution_psi (gauge)
```

### 2. Labels

**DO**:
- Utiliser des labels a cardinalite bornee
- Labels: `attack_type`, `severity`, `model_name`

**DON'T**:
- Eviter les labels a haute cardinalite
- Pas de: `user_id`, `request_id`, `timestamp` en labels

### 3. Alerting

- Definir des seuils realistes bases sur des baselines
- Utiliser des durations (`for: 5m`) pour eviter les faux positifs
- Documenter chaque alerte avec des runbooks

### 4. Dashboards

- Organiser par cas d'usage (operationnel vs securite)
- Utiliser des variables pour filtrer par modele/environnement
- Limiter le nombre de panels par dashboard (< 20)

### 5. Retention

- Production: 30-90 jours
- Archivage long terme: exporter vers S3/GCS
- Prevoir ~2GB/jour pour une utilisation standard

---

## Liens utiles

- [OpenTelemetry Documentation](https://opentelemetry.io/docs/)
- [VictoriaMetrics Documentation](https://docs.victoriametrics.com/)
- [Grafana Documentation](https://grafana.com/docs/)
- [PromQL Cheat Sheet](https://promlabs.com/promql-cheat-sheet/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

---

## Changelog

### v1.0.0 (2025-01)
- Initial release avec stack VictoriaMetrics + OTel
- 13 metriques de securite ML/LLM
- 20+ regles d'alerte Prometheus
- 2 dashboards Grafana pre-configures
