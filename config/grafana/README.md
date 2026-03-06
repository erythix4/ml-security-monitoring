# Grafana - ML/LLM Security Observability

## Overview

This folder contains Grafana dashboards and configurations for ML and LLM model security monitoring. The goal is to detect adversarial attacks, prompt injections, extraction attempts, and other cyber threats in real-time.

---

## Observability Architecture

```
+------------------+     +-------------------+     +------------------+
|   Application    |---->|  OpenTelemetry    |---->| VictoriaMetrics  |
|   (Metrics)      |     |  Collector        |     |   (Storage)      |
+------------------+     +-------------------+     +------------------+
        |                        |                         |
        v                        v                         v
+------------------+     +-------------------+     +------------------+
|   Prometheus     |     |   Alertmanager    |     |    Grafana       |
|   (Scraping)     |     |   (Alerts)        |     | (Visualization)  |
+------------------+     +-------------------+     +------------------+
```

### Ports and Services

| Service          | Port  | Description                          |
|------------------|-------|--------------------------------------|
| Grafana          | 3000  | Visualization interface              |
| VictoriaMetrics  | 8428  | Metrics storage (PromQL)             |
| OTel Collector   | 4317  | OTLP gRPC                            |
| OTel Collector   | 4318  | OTLP HTTP                            |
| OTel Prometheus  | 8889  | Prometheus export                    |
| Application      | 8000  | Application metrics                  |

---

## Attack Types and Metrics Mapping

This section provides a clear mapping between attack types and the security metrics used to detect them.

### Attack Coverage Matrix

| Attack Type | Primary Metrics | Secondary Metrics | Detection Strategy |
|-------------|----------------|-------------------|-------------------|
| **Adversarial Inputs** | `ml_input_reconstruction_error`, `ml_prediction_stability_score` | `ml_embedding_distance_to_centroid`, `ml_unstable_predictions_total` | High reconstruction error + low stability indicates adversarial perturbation |
| **Data Poisoning** | `ml_prediction_distribution_psi`, `ml_predictions_by_class_total` | `ml_accuracy_by_class` | Distribution drift over time + accuracy drop on specific classes |
| **Model Extraction** | `ml_api_queries_total` | `llm_tool_calls_total` | Abnormal query patterns + rate limiting triggers |
| **Prompt Injection** | `llm_prompt_injection_score` | `llm_tool_calls_total`, `llm_output_policy_violations_total` | High injection classifier score + unauthorized tool calls |
| **Jailbreak** | `llm_output_policy_violations_total`, `llm_prompt_injection_score` | `llm_tool_calls_total{is_dangerous="true"}` | Policy violations + dangerous tool usage |
| **System Prompt Extraction** | `llm_prompt_similarity_to_system` | `ml_api_queries_total` | High similarity between user input and system prompt |
| **Out-of-Distribution (OOD)** | `ml_embedding_distance_to_centroid` | `ml_prediction_confidence_bucket` | Embedding distance exceeds baseline threshold |
| **Model Drift** | `ml_prediction_distribution_psi` | `ml_accuracy_by_class`, `ml_predictions_by_class_total` | PSI > 0.2 over extended period |
| **Membership Inference** | `ml_prediction_confidence_bucket`, `ml_api_queries_total` | `ml_embedding_distance_to_centroid` | Query patterns targeting confidence scores |

### Metrics-to-Attacks Quick Reference

| Metric | Detects |
|--------|---------|
| `ml_input_reconstruction_error` | Adversarial (FGSM, PGD), OOD inputs |
| `ml_prediction_confidence_bucket` | Adversarial inputs, Membership Inference |
| `ml_embedding_distance_to_centroid` | OOD, Adversarial, Membership Inference |
| `ml_prediction_stability_score` | Adversarial inputs |
| `ml_unstable_predictions_total` | Adversarial inputs |
| `ml_predictions_by_class_total` | Data poisoning, Model drift |
| `ml_prediction_distribution_psi` | Data poisoning, Model drift |
| `ml_api_queries_total` | Model extraction, Membership Inference |
| `ml_accuracy_by_class` | Targeted poisoning, Model drift |
| `llm_prompt_injection_score` | Prompt injection, Jailbreak |
| `llm_prompt_similarity_to_system` | System prompt extraction, Prompt injection |
| `llm_output_policy_violations_total` | Jailbreak |
| `llm_tool_calls_total` | Agent attacks, Prompt injection, Jailbreak |

---

## Security Metrics Catalog

### Category 1: Adversarial Detection Metrics

These metrics detect malicious inputs designed to fool the model.

#### `ml_input_reconstruction_error`
- **Type**: Histogram
- **Description**: Autoencoder reconstruction error for anomaly detection
- **Labels**: `model_name`, `input_type`
- **Alert Threshold**: > 2.5
- **Detected Attacks**: FGSM, PGD, adversarial inputs
- **Grafana Panel**: "Input Reconstruction Error" (Section: Adversarial Detection)

```promql
# 95th percentile of reconstruction error
histogram_quantile(0.95, rate(ml_input_reconstruction_error_bucket[5m]))
```

#### `ml_prediction_confidence_bucket`
- **Type**: Histogram
- **Description**: Distribution of prediction confidence scores
- **Labels**: `model_name`, `predicted_class`
- **Alert Threshold**: > 0.95 with high error
- **Detected Attacks**: Adversarial inputs, Membership Inference
- **Grafana Panel**: "Prediction Confidence Distribution" (Section: Adversarial Detection)

```promql
# Median confidence by class
histogram_quantile(0.5, rate(ml_prediction_confidence_bucket[5m]))
```

#### `ml_embedding_distance_to_centroid`
- **Type**: Histogram
- **Description**: Distance from embeddings to training centroid
- **Labels**: `model_name`, `layer`
- **Alert Threshold**: > 3x baseline threshold
- **Detected Attacks**: Out-of-distribution, Adversarial
- **Grafana Panel**: "Embedding Distance to Centroid" (Section: Adversarial Detection)

```promql
# p95 distance with threshold
histogram_quantile(0.95, rate(ml_embedding_distance_to_centroid_bucket[5m]))
ml_embedding_distance_threshold * 3
```

#### `ml_prediction_stability_score`
- **Type**: Gauge
- **Description**: Prediction variance under light perturbations
- **Labels**: `model_name`, `perturbation_type`
- **Alert Threshold**: Spike > 3x average
- **Detected Attacks**: Adversarial inputs
- **Grafana Panel**: "Prediction Stability Score" (Section: Adversarial Detection)

```promql
ml_prediction_stability_score{model_name="$model"}
```

#### `ml_unstable_predictions_total`
- **Type**: Counter
- **Description**: Count of predictions that changed under perturbation
- **Labels**: `model_name`, `perturbation_type`
- **Alert Threshold**: rate > 3x avg_over_time
- **Detected Attacks**: Adversarial inputs
- **Grafana Panel**: "Unstable Predictions Rate" (Section: Adversarial Detection)

```promql
rate(ml_unstable_predictions_total[5m])
```

---

### Category 2: Behavioral Analysis Metrics

These metrics detect anomalies in model usage patterns.

#### `ml_predictions_by_class_total`
- **Type**: Counter
- **Description**: Distribution of predicted classes over time
- **Labels**: `model_name`, `predicted_class`
- **Alert Threshold**: Sudden distribution change
- **Detected Attacks**: Data poisoning, Drift
- **Grafana Panel**: "Predictions by Class Distribution" (Section: Behavior Analysis)

```promql
rate(ml_predictions_by_class_total[5m])
```

#### `ml_prediction_distribution_psi`
- **Type**: Gauge
- **Description**: Population Stability Index / KL divergence for drift detection
- **Labels**: `model_name`, `reference_window`
- **Alert Threshold**: > 0.2 for 15min
- **Detected Attacks**: Data poisoning, Model drift
- **Grafana Panel**: "Distribution Drift (PSI)" (Section: Behavior Analysis)

```promql
ml_prediction_distribution_psi{reference_window="1d"}
```

#### `ml_api_queries_total`
- **Type**: Counter
- **Description**: API requests per user/IP for rate limiting
- **Labels**: `user_id`, `ip_address`, `endpoint`
- **Alert Threshold**: > 100 req/10min per user
- **Detected Attacks**: Model extraction, Membership Inference
- **Grafana Panel**: "API Queries per User (10min window)" (Section: Behavior Analysis)

```promql
sum by (user_id) (rate(ml_api_queries_total[10m])) * 600
```

#### `ml_accuracy_by_class`
- **Type**: Gauge
- **Description**: Per-class accuracy to detect targeted attacks
- **Labels**: `model_name`, `class_name`
- **Alert Threshold**: Drop > 10% vs baseline
- **Detected Attacks**: Targeted poisoning
- **Grafana Panel**: "Per-Class Accuracy vs Baseline" (Section: Behavior Analysis)

```promql
ml_accuracy_by_class{class_name="$class"}
ml_baseline_accuracy{class_name="$class"}
```

---

### Category 3: LLM Security Metrics

These metrics detect LLM-specific attacks.

#### `llm_prompt_injection_score`
- **Type**: Histogram
- **Description**: Injection detection classifier score (0-1)
- **Labels**: `model_name`, `detection_method`
- **Alert Threshold**: > 0.85
- **Detected Attacks**: Prompt injection, Jailbreak
- **Grafana Panel**: "Prompt Injection Score" (Section: LLM Security)

```promql
# Injection score percentiles
histogram_quantile(0.50, rate(llm_prompt_injection_score_bucket[5m]))
histogram_quantile(0.95, rate(llm_prompt_injection_score_bucket[5m]))
histogram_quantile(0.99, rate(llm_prompt_injection_score_bucket[5m]))
```

#### `llm_prompt_similarity_to_system`
- **Type**: Histogram
- **Description**: Embedding similarity between user input and system prompt
- **Labels**: `model_name`
- **Alert Threshold**: > 0.7
- **Detected Attacks**: System prompt extraction
- **Grafana Panel**: "System Prompt Similarity (Extraction Detection)" (Section: LLM Security)

```promql
histogram_quantile(0.95, rate(llm_prompt_similarity_to_system_bucket[5m]))
```

#### `llm_output_policy_violations_total`
- **Type**: Counter
- **Description**: Content policy violations counter
- **Labels**: `model_name`, `violation_type`, `severity`
- **Alert Threshold**: Repeated violations
- **Detected Attacks**: Jailbreak
- **Grafana Panel**: "Policy Violations by Type" (Section: LLM Security)

```promql
rate(llm_output_policy_violations_total[5m])
sum(increase(llm_output_policy_violations_total[1h]))
```

#### `llm_tool_calls_total`
- **Type**: Counter
- **Description**: Tool/function calls by name, user, and status
- **Labels**: `tool_name`, `user_id`, `success`, `is_dangerous`
- **Alert Threshold**: > 5 calls/5min (shell/exec)
- **Detected Attacks**: Agent attacks, Prompt injection
- **Grafana Panel**: "Tool Calls by Name/User", "Tool Calls: Safe vs Dangerous" (Section: LLM Security)

```promql
sum by (tool_name, user_id) (rate(llm_tool_calls_total[5m])) * 300
sum by (is_dangerous) (increase(llm_tool_calls_total[1h]))
```

---

## Grafana Dashboards

### Dashboard 1: ML/LLM Security Metrics
**UID**: `ml-security-metrics`
**File**: `dashboards/ml-security-metrics.json`

#### Sections and Panels

| Section | Panel ID | Panel | Metric(s) Used |
|---------|----------|-------|----------------|
| Security Overview | 101 | Critical Alerts (1h) | `security_alerts_total{severity="critical"}` |
| Security Overview | 102 | Warning Alerts (1h) | `security_alerts_total{severity="warning"}` |
| Security Overview | 103 | Injection Score (p95) | `llm_prompt_injection_score_bucket` |
| Security Overview | 104 | Distribution PSI | `ml_prediction_distribution_psi` |
| Security Overview | 105 | Reconstruction Error (p95) | `ml_input_reconstruction_error_bucket` |
| Security Overview | 106 | Policy Violations (1h) | `llm_output_policy_violations_total` |
| Adversarial Detection | 201 | Input Reconstruction Error | `ml_input_reconstruction_error_bucket` |
| Adversarial Detection | 202 | Embedding Distance to Centroid | `ml_embedding_distance_to_centroid_bucket` |
| Adversarial Detection | 203 | Prediction Stability Score | `ml_prediction_stability_score` |
| Adversarial Detection | 204 | Unstable Predictions Rate | `ml_unstable_predictions_total` |
| Adversarial Detection | 205 | Prediction Confidence Distribution | `ml_prediction_confidence_bucket` |
| Behavior Analysis | 301 | Distribution Drift (PSI) | `ml_prediction_distribution_psi` |
| Behavior Analysis | 302 | Per-Class Accuracy vs Baseline | `ml_accuracy_by_class`, `ml_baseline_accuracy` |
| Behavior Analysis | 303 | Predictions by Class Distribution | `ml_predictions_by_class_total` |
| Behavior Analysis | 304 | API Queries per User (10min window) | `ml_api_queries_total` |
| LLM Security | 401 | Prompt Injection Score | `llm_prompt_injection_score_bucket` |
| LLM Security | 402 | System Prompt Similarity | `llm_prompt_similarity_to_system_bucket` |
| LLM Security | 403 | Policy Violations by Type | `llm_output_policy_violations_total` |
| LLM Security | 404 | Tool Calls by Name/User | `llm_tool_calls_total` |
| LLM Security | 405 | Tool Calls: Safe vs Dangerous | `llm_tool_calls_total` |
| Attack Coverage Matrix | 501 | Active Security Monitoring Coverage | All metrics |

### Dashboard 2: LLM Attack Lab
**UID**: `llm-attack-lab-main`
**File**: `dashboards/llm-attack-lab.json`

Main operational dashboard with attack and defense overview.

### Dashboard 3: Documentation
**UID**: `llm-attack-lab-docs`
**File**: `dashboards/documentation.json`
**URL**: http://localhost:3000/d/llm-attack-lab-docs

Dashboard integrating all project documentation directly in Grafana:
- Main project README
- Quick Start guide
- Architecture and tech stack
- Complete security metrics catalog
- Attack/metrics coverage matrix
- Alerting rules (critical and warning)
- Troubleshooting guide
- Cyber/observability best practices
- PromQL query examples
- References and useful links

---

## Alerting Rules

Alerts are configured in `/config/prometheus/rules/security_alerts.yml`.

### Critical Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| PromptInjectionDetected | `llm_prompt_injection_score > 0.85` | critical |
| PotentialAdversarialInput | `ml_input_reconstruction_error > 2.5` | critical |
| ModelDistributionDrift | `ml_prediction_distribution_psi > 0.2` for 15m | critical |
| SuspiciousToolUsage | `rate(llm_tool_calls_total{is_dangerous="true"}) > 5/5m` | critical |

### Warning Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| OutOfDistributionInput | `ml_embedding_distance_to_centroid > 3x threshold` | warning |
| SystemPromptExtractionAttempt | `llm_prompt_similarity_to_system > 0.7` | warning |
| SuspiciousQueryPattern | `rate(ml_api_queries_total) > 100/10m` | warning |
| PredictionInstabilitySpike | `ml_prediction_stability_score > 3x avg` | warning |

---

## Troubleshooting Guide

### Issue: No Data in Grafana

1. **Check VictoriaMetrics**:
```bash
curl http://localhost:8428/api/v1/query?query=up
```

2. **Check application metrics**:
```bash
curl http://localhost:8000/metrics | grep -E "^(ml_|llm_)"
```

3. **Check OTel Collector**:
```bash
curl http://localhost:8889/metrics
```

### Issue: Alerts Not Triggering

1. Verify metrics have recent data
2. Check labels in PromQL queries
3. Check Prometheus/Alertmanager logs

### Issue: Missing Metrics

Metrics are initialized at startup with baseline values. If some metrics are missing:

```python
from llm_attack_lab.monitoring import get_security_metrics
metrics = get_security_metrics()
metrics.initialize()
```

### Issue: Empty Panels

All PromQL queries use `or vector(0)` fallback to display a default value when no data exists. If panels still appear empty:

1. Verify the application is running and emitting metrics
2. Check that metric names match exactly (case-sensitive)
3. Ensure label filters match existing label values
4. Wait for the initial scrape interval (default: 15s)

---

## Advanced Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PROMETHEUS_MULTIPROC_DIR` | Directory for multiprocess metrics | `/tmp/prometheus` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTel endpoint | `http://localhost:4317` |
| `VICTORIAMETRICS_URL` | VictoriaMetrics URL | `http://localhost:8428` |

### Threshold Customization

Alert thresholds can be adjusted via code:

```python
from llm_attack_lab.monitoring import get_security_metrics

metrics = get_security_metrics()
metrics.set_threshold("llm_prompt_injection_score", 0.90)
metrics.set_threshold("ml_prediction_distribution_psi", 0.15)
metrics.set_embedding_threshold(4.0, model_name="production-model")
```

---

## Cyber/Observability Best Practices

### 1. Defense in Depth

- Combine multiple metrics for detection
- Don't rely on a single indicator
- Configure alerts at multiple levels (warning, critical)

### 2. Baseline and Context

- Always establish a baseline before production deployment
- Adjust thresholds based on business context
- Document thresholds and their justification

### 3. Event Correlation

- Use labels to correlate metrics
- Investigate multi-metric patterns
- Example: high `llm_prompt_injection_score` + `llm_tool_calls_total{is_dangerous="true"}` = probable attack

### 4. Retention and Forensics

- VictoriaMetrics retains 30 days by default
- Export alerts for long-term investigation
- Log suspicious requests for post-incident analysis

### 5. Monitoring the Monitoring

- Monitor the health of the observability stack
- Alert on metric collection failures
- Regularly verify dashboards display data

---

## File Structure

```
config/grafana/
├── README.md                          # This file
├── dashboards/
│   ├── llm-attack-lab.json           # Operational dashboard
│   ├── ml-security-metrics.json      # ML/LLM security dashboard
│   └── documentation.json            # Integrated documentation
└── provisioning/
    ├── dashboards/
    │   └── dashboards.yaml           # Auto-load configuration
    └── datasources/
        └── datasources.yaml          # Data source configuration
```

---

## References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS - Adversarial ML](https://atlas.mitre.org/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/naming/)
- [Grafana Dashboard Guidelines](https://grafana.com/docs/grafana/latest/dashboards/)

---

## Changelog

- **v1.0** - Initial creation with 13 security metrics
- **v1.1** - Added attack coverage matrix
- **v1.2** - Complete Grafana mapping documentation
- **v1.3** - Translated to English, improved attack-to-metrics organization, added Membership Inference coverage
