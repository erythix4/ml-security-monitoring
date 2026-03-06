# Monitoring & Security Metrics

Ce module fournit une solution complète de monitoring et d'observabilité pour le LLM Attack Simulation Lab, avec un focus particulier sur la détection des attaques ML/LLM.

## Table des matières

- [Architecture](#architecture)
- [Métriques de sécurité](#métriques-de-sécurité)
  - [Pattern Adversarial](#pattern-adversarial)
  - [Pattern Comportemental](#pattern-comportemental)
  - [Pattern LLM](#pattern-llm)
- [Alertes](#alertes)
- [Dashboards Grafana](#dashboards-grafana)
- [Utilisation](#utilisation)
- [Configuration](#configuration)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        LLM Attack Lab Application                        │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────────┐ │
│  │ MetricsCollector│  │SecurityMetrics   │  │    AlertManager         │ │
│  │  (Core metrics) │  │(ML/LLM Security) │  │   (Rule-based alerts)   │ │
│  └────────┬────────┘  └────────┬─────────┘  └───────────┬─────────────┘ │
│           │                    │                        │               │
│           └────────────────────┼────────────────────────┘               │
│                                │                                        │
│                    ┌───────────▼───────────┐                           │
│                    │   OTel Manager        │                           │
│                    │ (Prometheus Export)   │                           │
│                    └───────────┬───────────┘                           │
└────────────────────────────────┼────────────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   OpenTelemetry        │
                    │     Collector          │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
    ┌─────────▼─────────┐ ┌─────▼─────┐  ┌────────▼────────┐
    │  VictoriaMetrics  │ │  Grafana  │  │  Alert Manager  │
    │  (Time Series DB) │ │(Dashboard)│  │   (Routing)     │
    └───────────────────┘ └───────────┘  └─────────────────┘
```

---

## Métriques de sécurité

### Catalogue complet des métriques

| Métrique | Pattern | Description | Seuil d'alerte | Attaques détectées |
|----------|---------|-------------|----------------|-------------------|
| `ml_input_reconstruction_error` | Adversarial | Erreur de reconstruction autoencoder | > 2.5 | FGSM, PGD, Adversarial inputs |
| `ml_prediction_confidence_bucket` | Adversarial | Distribution des scores de confiance | > 0.95 (avec haute erreur) | Adversarial inputs |
| `ml_embedding_distance_to_centroid` | Adversarial | Distance aux centroïdes du training | > 3x threshold | Out-of-distribution, Adversarial |
| `ml_prediction_stability_score` | Adversarial | Variance des prédictions sous perturbation | Spike > 3x moyenne | Adversarial inputs |
| `ml_unstable_predictions_total` | Adversarial | Counter des prédictions instables | rate > 3x avg_over_time | Adversarial inputs |
| `ml_predictions_by_class_total` | Behavior | Distribution des classes prédites | Changement soudain | Data poisoning, Drift |
| `ml_prediction_distribution_psi` | Behavior | Score de drift PSI/KL | > 0.2 pendant 15m | Data poisoning, Model drift |
| `ml_api_queries_total` | Behavior | Requêtes par user/IP | > 100 req/10min | Model extraction |
| `ml_accuracy_by_class` | Behavior | Précision par classe | Drop > 10% vs J-1 | Targeted poisoning |
| `llm_prompt_injection_score` | LLM | Score du classifieur injection (0-1) | > 0.85 | Prompt injection, Jailbreak |
| `llm_prompt_similarity_to_system` | LLM | Distance embedding au system prompt | > 0.7 | System prompt extraction |
| `llm_output_policy_violations_total` | LLM | Triggers du content filter | Violations répétées | Jailbreak |
| `llm_tool_calls_total` | LLM | Appels d'outils par nom/user/succès | > 5 calls/5min (shell/exec) | Agent attacks, Prompt injection |

### Pattern Adversarial

Détecte les inputs adversariaux générés par des techniques comme FGSM, PGD, ou autres perturbations.

```python
from llm_attack_lab.monitoring import get_security_metrics

metrics = get_security_metrics()

# Enregistrer une erreur de reconstruction
metrics.record_reconstruction_error(
    error=2.8,
    model_name="classifier_v1",
    input_type="image"
)

# Enregistrer la distance d'embedding
metrics.record_embedding_distance(
    distance=5.2,
    model_name="classifier_v1",
    layer="output"
)

# Enregistrer une prédiction instable
metrics.record_unstable_prediction(
    model_name="classifier_v1",
    perturbation_type="gaussian_noise"
)
```

### Pattern Comportemental

Détecte les anomalies comportementales : drift de données, extraction de modèle, poisoning ciblé.

```python
# Tracker la distribution des classes
metrics.record_prediction_class(
    model_name="classifier_v1",
    predicted_class="cat"
)

# Enregistrer le score PSI (Population Stability Index)
metrics.record_distribution_psi(
    psi_score=0.15,
    model_name="classifier_v1",
    reference_window="1d"
)

# Tracker les requêtes API par utilisateur
metrics.record_api_query(
    user_id="user_123",
    ip_address="192.168.1.1",
    endpoint="/predict"
)

# Mettre à jour la précision par classe
metrics.record_class_accuracy(
    accuracy=0.92,
    model_name="classifier_v1",
    class_name="cat"
)
```

### Pattern LLM

Détecte les attaques spécifiques aux LLMs : injection de prompt, jailbreak, extraction de system prompt.

```python
# Score de détection d'injection de prompt
metrics.record_prompt_injection_score(
    score=0.92,
    model_name="gpt-4",
    detection_method="classifier"
)

# Similarité avec le system prompt (extraction detection)
metrics.record_system_prompt_similarity(
    similarity=0.75,
    model_name="gpt-4"
)

# Violation de politique de contenu
metrics.record_policy_violation(
    model_name="gpt-4",
    violation_type="harmful_content",
    severity="high"
)

# Appel d'outil (avec flag dangereux)
metrics.record_tool_call(
    tool_name="shell",
    user_id="user_456",
    success=True,
    is_dangerous=True
)
```

---

## Alertes

Les alertes sont définies dans `/config/prometheus/rules/security_alerts.yml`.

### Alertes par sévérité

| Nom de l'alerte | Pattern | Sévérité | Expression PromQL | Attaque ciblée |
|-----------------|---------|----------|-------------------|----------------|
| PotentialAdversarialInput | Adversarial | warning | `reconstruction_error > 2.5 AND confidence > 0.95` | Adversarial inputs |
| OutOfDistributionInput | Adversarial | warning | `embedding_distance > 3 * threshold` | OOD inputs |
| PredictionInstabilitySpike | Adversarial | warning | `rate(unstable) > 3 * avg_over_time` | Adversarial inputs |
| ModelDistributionDrift | Behavior | warning | `psi > 0.2 for 15m` | Data poisoning |
| SuspiciousQueryPattern | Behavior | warning | `rate(queries) > 100 per 10m` | Model extraction |
| TargetedAccuracyDrop | Behavior | warning | `accuracy_drop > 10%` | Targeted attack |
| **PromptInjectionDetected** | LLM | **critical** | `injection_score > 0.85` | Prompt injection |
| **SystemPromptExtractionAttempt** | LLM | **critical** | `similarity > 0.7 OR output_contains_prompt` | System prompt extraction |
| **SuspiciousToolUsage** | LLM | **critical** | `dangerous_tool_calls > 5 per 5m` | Agent attacks |

### Configuration des alertes

```python
from llm_attack_lab.monitoring import AlertManager, AlertSeverity

# Obtenir l'instance globale
from llm_attack_lab.monitoring.alerts import get_alert_manager

alert_mgr = get_alert_manager()

# Ajouter une règle personnalisée
from llm_attack_lab.monitoring.alerts import AlertRule

alert_mgr.add_rule(AlertRule(
    name="custom_injection_detection",
    description="Custom prompt injection threshold",
    metric_name="llm_prompt_injection_score",
    condition="gt",
    threshold=0.9,
    severity=AlertSeverity.CRITICAL,
    cooldown_seconds=30,
))

# Créer une alerte manuelle
alert = alert_mgr.create_alert(
    name="security_incident",
    message="Suspicious activity detected from user_123",
    severity=AlertSeverity.WARNING,
    source="manual",
    metadata={"user_id": "user_123", "ip": "192.168.1.1"}
)
```

---

## Dashboards Grafana

Deux dashboards sont disponibles :

### 1. LLM Attack Lab (Principal)
**UID**: `llm-attack-lab-main`

- Vue d'ensemble des attaques
- Taux de succès et détection
- Métriques de défense
- Santé système

### 2. ML/LLM Security Metrics (Sécurité)
**UID**: `ml-security-metrics`

- **Section Overview** : Alertes critiques, score d'injection, PSI, violations
- **Section Adversarial** : Reconstruction error, embedding distance, stabilité
- **Section Behavior** : Drift PSI, accuracy par classe, queries par user
- **Section LLM** : Injection score, similarité system prompt, tool calls
- **Matrice de couverture** : Vue tableau de l'état des métriques

### Accès aux dashboards

```
http://localhost:3000/d/llm-attack-lab-main    # Dashboard principal
http://localhost:3000/d/ml-security-metrics    # Dashboard sécurité
```

---

## Utilisation

### Initialisation rapide

```python
from llm_attack_lab.monitoring import (
    init_security_metrics,
    get_security_metrics,
    AlertManager,
)

# Initialiser les métriques de sécurité
security_metrics = init_security_metrics()

# Utiliser dans votre code
def process_input(user_input, model):
    # Calculer le score d'injection
    injection_score = detect_injection(user_input)
    security_metrics.record_prompt_injection_score(
        score=injection_score,
        model_name=model.name
    )

    # Vérifier la similarité avec le system prompt
    similarity = compute_similarity(user_input, model.system_prompt)
    security_metrics.record_system_prompt_similarity(
        similarity=similarity,
        model_name=model.name
    )

    # Si score élevé, enregistrer l'alerte
    if injection_score > 0.85:
        security_metrics.record_security_alert(
            alert_type="prompt_injection",
            severity="critical",
            pattern="llm"
        )
```

### Intégration avec le flow d'attaque

```python
def run_attack_simulation(attack_type, target_model):
    metrics = get_security_metrics()

    # Avant l'attaque : mesurer les baselines
    baseline_accuracy = measure_model_accuracy(target_model)
    metrics.set_baseline("ml_accuracy_by_class", baseline_accuracy)

    # Pendant l'attaque
    for input_sample in attack_samples:
        # Enregistrer les métriques de détection
        recon_error = autoencoder.reconstruct(input_sample)
        metrics.record_reconstruction_error(recon_error)

        embedding_dist = compute_centroid_distance(input_sample)
        metrics.record_embedding_distance(embedding_dist)

    # Après l'attaque : détecter le drift
    psi_score = compute_distribution_shift()
    metrics.record_distribution_psi(psi_score)
```

---

## Configuration

### Variables d'environnement

```bash
# Prometheus metrics port
PROMETHEUS_METRICS_PORT=8000
PROMETHEUS_PORT_AUTO=true
PROMETHEUS_PORT_RANGE=10

# OpenTelemetry
OTEL_SERVICE_NAME=llm-attack-lab
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
OTEL_ENABLE_TRACING=true
OTEL_ENABLE_METRICS=true

# Timeouts
OTEL_EXPORTER_OTLP_TIMEOUT=30
OTEL_METRIC_EXPORT_INTERVAL=15000
```

### Seuils personnalisés

```python
metrics = get_security_metrics()

# Modifier les seuils d'alerte
metrics.set_threshold("ml_input_reconstruction_error", 3.0)
metrics.set_threshold("llm_prompt_injection_score", 0.90)
metrics.set_threshold("ml_api_queries_rate", 200)

# Définir le threshold d'embedding pour un modèle
metrics.set_embedding_threshold(threshold=5.0, model_name="my_model")

# Définir une baseline d'accuracy
metrics.set_baseline(
    "ml_accuracy_by_class",
    value=0.95,
    labels={"model_name": "my_model", "class_name": "positive"}
)
```

---

## Matrice de couverture des attaques

Cette matrice montre quelles métriques permettent de détecter chaque type d'attaque :

| Métrique | Adversarial | Poisoning | Extraction | Prompt Injection | Jailbreak | Drift |
|----------|:-----------:|:---------:|:----------:|:----------------:|:---------:|:-----:|
| ml_input_reconstruction_error | ✓ | | | | | |
| ml_prediction_confidence_bucket | ✓ | | | | | |
| ml_embedding_distance_to_centroid | ✓ | | | | | |
| ml_prediction_stability_score | ✓ | | | | | |
| ml_unstable_predictions_total | ✓ | | | | | |
| ml_predictions_by_class_total | | ✓ | | | | ✓ |
| ml_prediction_distribution_psi | | ✓ | | | | ✓ |
| ml_api_queries_total | | | ✓ | | | |
| ml_accuracy_by_class | | ✓ | | | | |
| llm_prompt_injection_score | | | | ✓ | ✓ | |
| llm_prompt_similarity_to_system | | | ✓ | ✓ | | |
| llm_output_policy_violations_total | | | | | ✓ | |
| llm_tool_calls_total | | | | ✓ | ✓ | |

---

## Structure des fichiers

```
llm_attack_lab/monitoring/
├── __init__.py              # Exports du module
├── metrics.py               # MetricsCollector (métriques de base)
├── security_metrics.py      # SecurityMetricsCollector (ML/LLM)
├── alerts.py                # AlertManager et règles d'alerte
├── otel.py                  # Intégration OpenTelemetry
├── logger.py                # Logging structuré
├── dashboard.py             # Dashboard CLI
└── README.md                # Cette documentation

config/
├── prometheus/
│   └── rules/
│       └── security_alerts.yml   # Règles d'alerte Prometheus
├── grafana/
│   ├── dashboards/
│   │   ├── llm-attack-lab.json       # Dashboard principal
│   │   └── ml-security-metrics.json  # Dashboard sécurité
│   └── provisioning/
│       ├── dashboards/dashboards.yaml
│       └── datasources/datasources.yaml
├── otel-collector-config.yaml
└── vmagent.yaml
```

---

## Références

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Adversarial Robustness Toolbox (ART)](https://github.com/Trusted-AI/adversarial-robustness-toolbox)
- [Population Stability Index (PSI)](https://www.listendata.com/2015/05/population-stability-index.html)
- [Prometheus Alerting Rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)
- [Grafana Dashboard Best Practices](https://grafana.com/docs/grafana/latest/dashboards/build-dashboards/best-practices/)
