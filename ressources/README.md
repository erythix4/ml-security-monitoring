# ML Security Monitoring

**Detecting Threats Against Production ML Systems in Cloud-Native Environments**

> Resources from the talk *"AI Security Monitoring: Detecting Threats Against Production ML Systems"*  
> Samuel Desseaux · Erythix (FR) / Aureonis (BE) · VictoriaMetrics Training Partner  
> CNCF Meetup Cloud-Native Security | FOSDEM 2026 Security devroom

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Stack](https://img.shields.io/badge/stack-VictoriaMetrics%20%7C%20Loki%20%7C%20Grafana%20%7C%20Falco%20%7C%20OTel-informational)](helm/ml-security-stack)

---

## What's in This Repository

| Resource | Path | Description |
|---|---|---|
| 📋 **Threat Model Framework** | [`threat-model-framework.pdf`](threat-model-framework.pdf) | Fillable PDF: asset identification, adversary profiling, K8s attack vectors checklist |
| 🔔 **PromQL / vmalert Alert Rules** | [`alerting-rules/`](alerting-rules/) | YAML rules for adversarial, drift, extraction, and LLM security (vmalert compatible) |
| 🦅 **Falco ML Rules** | [`falco/ml-security-rules.yaml`](falco/ml-security-rules.yaml) | Custom Falco rules: model exfiltration, shell access, GPU driver monitoring |
| ⎈ **Helm Charts** | [`helm/ml-security-stack/`](helm/ml-security-stack/) | Complete K8s deployment: VictoriaMetrics + Loki + Grafana + Falco + OTel Collector |
| 🔍 **LogQL Investigation** | [`logql/investigation-queries.md`](logql/investigation-queries.md) | Query library: attack correlation, user behavior, forensic investigation |
| 🛡️ **SOC + EU AI Act Guide** | [`soc-compliance/soc-eu-ai-act-guide.md`](soc-compliance/soc-eu-ai-act-guide.md) | Architecture, Alertmanager configs, compliance mapping, SOC runbooks |

---

## Quick Start

### Option A — Full Stack (Helm)

```bash
# Add dependency repos
helm repo add victoriametrics https://victoriametrics.github.io/helm-charts/
helm repo add grafana         https://grafana.github.io/helm-charts
helm repo add falcosecurity   https://falcosecurity.github.io/charts
helm repo add open-telemetry  https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update

# Install
helm install ml-security ./helm/ml-security-stack \
  --namespace ml-security \
  --create-namespace \
  -f helm/ml-security-stack/values.yaml

# Verify
kubectl get pods -n ml-security
kubectl port-forward svc/ml-security-grafana 3000:80 -n ml-security
```

### Option B — Alert Rules Only (vmalert)

```bash
# Load rules into an existing VictoriaMetrics + vmalert setup
kubectl create configmap ml-alerting-rules \
  --from-file=alerting-rules/ \
  -n monitoring

# Reference the ConfigMap in your VMAlert resource:
# spec.ruleSelector.matchLabels.configmap: ml-alerting-rules
```

### Option C — Falco Rules Only

```bash
kubectl create configmap falco-ml-rules \
  --from-file=falco/ml-security-rules.yaml \
  -n falco

# Mount as /etc/falco/ml-security-rules.yaml in the Falco DaemonSet
```

---

## Repository Structure

```
ml-security-monitoring/
├── README.md
├── threat-model-framework.pdf          # Fillable threat model template
├── alerting-rules/
│   ├── adversarial-detection.yml       # Adversarial input & OOD alerts
│   ├── drift-and-extraction.yml        # Drift monitoring + model theft detection
│   └── llm-security.yml               # Prompt injection, jailbreak, PII leakage
├── falco/
│   └── ml-security-rules.yaml         # Runtime security: exfiltration, shell, GPU
├── helm/
│   └── ml-security-stack/
│       ├── Chart.yaml
│       ├── values.yaml                 # All component configuration
│       └── templates/
│           ├── namespace.yaml
│           └── configmaps.yaml
├── logql/
│   └── investigation-queries.md       # 30+ LogQL queries for forensics
└── soc-compliance/
    └── soc-eu-ai-act-guide.md         # Architecture, runbooks, EU AI Act mapping
```

---

## Detection Coverage

| Threat | MITRE ATLAS | Detection | Rule File |
|---|---|---|---|
| Adversarial inputs (FGSM/PGD) | AML.T0015 | Reconstruction error + confidence mismatch | `adversarial-detection.yml` |
| Out-of-distribution inputs | AML.T0015 | Embedding distance to centroid | `adversarial-detection.yml` |
| Model extraction via API | AML.T0035 | Request spike + boundary probing | `drift-and-extraction.yml` |
| Training data poisoning | AML.T0020 | PSI drift + accuracy degradation | `drift-and-extraction.yml` |
| Prompt injection | AML.T0051 | Classifier score > 0.85 | `llm-security.yml` |
| Jailbreak / guardrail bypass | AML.T0054 | Safety refusal rate + pattern matching | `llm-security.yml` |
| LLM output PII leakage | AML.T0048 | PII detector on output | `llm-security.yml` |
| RAG context poisoning | AML.T0020 | Context anomaly score | `llm-security.yml` |
| Model file exfiltration | AML.T0044 | Falco: network tool + model file read | `falco/ml-security-rules.yaml` |
| Shell in ML container | AML.T0011 | Falco: shell spawn in serving pod | `falco/ml-security-rules.yaml` |
| GPU driver exploitation | AML.T0006 | Falco: ioctl on /dev/nvidia* | `falco/ml-security-rules.yaml` |

---

## Required Metrics (Instrument Your ML Code)

Your inference service must expose the following Prometheus metrics:

```python
# Python example (prometheus_client)
from prometheus_client import Gauge, Counter, Histogram

ml_input_reconstruction_error    = Gauge("ml_input_reconstruction_error",    "Autoencoder reconstruction error", ["model_name", "namespace"])
ml_prediction_confidence         = Gauge("ml_prediction_confidence",         "Model prediction confidence",      ["model_name", "namespace"])
ml_embedding_distance_to_centroid= Gauge("ml_embedding_distance_to_centroid","Distance from training centroid",  ["model_name", "namespace"])
ml_embedding_distance_threshold  = Gauge("ml_embedding_distance_threshold",  "Configured OOD threshold",         ["model_name", "namespace"])
ml_feature_psi_score             = Gauge("ml_feature_psi_score",             "Population Stability Index",       ["model_name", "feature_name"])
ml_api_requests_total            = Counter("ml_api_requests_total",          "Total inference requests",         ["model_name", "client_id"])
ml_llm_injection_classifier_score= Gauge("ml_llm_injection_classifier_score","Prompt injection classifier",      ["app_name", "session_id"])
ml_llm_safety_refusals_total     = Counter("ml_llm_safety_refusals_total",   "Safety refusal events",            ["app_name"])
```

---

## References

- [MITRE ATLAS](https://atlas.mitre.org) — Adversarial ML Threat Matrix
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CNCF Cloud Native Security Whitepaper](https://github.com/cncf/tag-security)
- [EU AI Act](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689)
- [Falco Documentation](https://falco.org/docs/)
- [VictoriaMetrics vmalert](https://docs.victoriametrics.com/vmalert/)

---

## License

Apache 2.0 — See [LICENSE](LICENSE)  
PRs welcome! Open an issue to report gaps or contribute new detection rules.

---

*Samuel Desseaux · [erythix.io](https://erythix.io) · samuel@erythix.io*  
*Erythix (FR) · Aureonis (BE) · VictoriaMetrics Training Partner (France, Benelux, DACH)*
