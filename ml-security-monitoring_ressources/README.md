# AI Security Monitoring

> Detecting Threats Against Production ML Systems with Open Source Tools

[![FOSDEM 2026](https://img.shields.io/badge/FOSDEM-2026-00D4AA?style=flat-square)](https://fosdem.org/2026/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

This repository contains production-ready configurations, alerting rules, and code examples for monitoring AI/ML systems security using the open source observability stack (Prometheus, Loki, Grafana, OpenTelemetry).

**Presented at FOSDEM 2026 - Security Devroom**

---

## 🎯 What's Inside

| Directory | Description |
|-----------|-------------|
| [`alerting/`](alerting/) | Prometheus alerting rules for adversarial detection, model behavior monitoring, and LLM security |
| [`exporters/`](exporters/) | Python exporter examples for custom ML security metrics |
| [`dashboards/`](dashboards/) | Grafana dashboard JSON files for ML security visualization |
| [`logql/`](logql/) | LogQL query library for Loki-based investigation |
| [`docs/`](docs/) | Threat model framework template and architecture guides |
| [`demo/`](demo/) | Docker Compose stack for live demonstrations |

---

## 🚨 Detection Patterns

### Pattern 1: Adversarial Input Detection
Detect inputs crafted to fool your model while appearing normal to humans.

```yaml
# High confidence + high reconstruction error = potential adversarial
alert: PotentialAdversarialInput
expr: ml_input_reconstruction_error > 2.5 AND ml_prediction_confidence > 0.95
```

### Pattern 2: Model Behavior Monitoring
Detect poisoning and extraction attacks by monitoring behavior drift.

```yaml
# Prediction distribution drift (potential poisoning)
alert: ModelDistributionDrift
expr: ml_prediction_distribution_psi > 0.2
for: 15m
```

### Pattern 3: LLM Security Monitoring
Detect prompt injection, jailbreaks, and system prompt extraction.

```yaml
# High confidence prompt injection detected
alert: PromptInjectionDetected
expr: llm_prompt_injection_score > 0.85
labels:
  severity: critical
```

---

## 📊 Metrics Reference

### Anomaly Detection
| Metric | Description |
|--------|-------------|
| `ml_input_reconstruction_error` | Autoencoder reconstruction error |
| `ml_embedding_distance_to_centroid` | Distance from training distribution |
| `ml_prediction_stability_score` | Prediction variance under perturbation |

### Distribution Drift
| Metric | Description |
|--------|-------------|
| `ml_prediction_distribution_psi` | Population Stability Index |
| `ml_predictions_by_class_total` | Prediction class distribution |
| `ml_accuracy_by_class` | Ground truth accuracy when available |

### API Behavior
| Metric | Description |
|--------|-------------|
| `ml_api_queries_total` | Queries per user/IP |
| `ml_query_entropy_score` | Query pattern entropy |

### LLM Specific
| Metric | Description |
|--------|-------------|
| `llm_prompt_injection_score` | Injection classifier confidence (0-1) |
| `llm_prompt_similarity_to_system` | Embedding distance to system prompt |
| `llm_output_policy_violations_total` | Content filter triggers |
| `llm_tool_calls_total` | Tool calls by name, user, success/failure |

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.9+
- A model to monitor (or use the demo fraud detector)

### Run the Demo Stack

```bash
cd demo/
docker-compose up -d

# Access Grafana at http://localhost:3000
# Default credentials: admin/admin
```

### Install the Python Exporter

```bash
pip install prometheus-client numpy scikit-learn

# In your inference code
from exporters.ml_security_exporter import MLSecurityExporter

exporter = MLSecurityExporter(model_name="fraud-detector-v2")
exporter.start_server(port=8000)

# During inference
exporter.record_prediction(input_data, prediction, confidence)
```

---

## 🔗 Integration

### SOC Integration Options

| Method | Use Case |
|--------|----------|
| Alertmanager Webhooks | Native integration with most SIEMs |
| Grafana OnCall | Built-in incident management |
| Loki to SIEM | Forward critical logs via syslog |
| OTel Exporters | Send to any OTel-compatible backend |

---

## ⚠️ Limitations

- **Not a silver bullet**: These patterns detect known attack signatures. Zero-day and novel techniques may evade detection initially.
- **Setup required**: Reconstruction error detection needs a trained autoencoder. Baselines must be calibrated per model.
- **False positives**: Legitimate out-of-distribution data may trigger alerts. Tune thresholds for your use case.

---

## 📚 Resources

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/) - Adversarial Threat Landscape for AI Systems
- [ProtectAI Prompt Injection Classifier](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2)

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

Apache 2.0 - See [LICENSE](LICENSE) for details.

---

## 👤 Author

**Samuel Desseaux**  
Founder & CTO - [Erythix](https://erythix.tech) (FR) / Aureonis (BE)

- Twitter: [@samueldesseaux](https://twitter.com/samueldesseaux)
- Website: [erythix.tech](https://erythix.tech)

---

*Presented at FOSDEM 2026 Security Devroom - Brussels, Belgium*
