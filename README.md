# iAttack — AI Security Monitoring Lab

> **Simulate, understand, and detect AI attacks with cloud-native observability**

[![CNCF Meetup](https://img.shields.io/badge/CNCF-Meetup-326CE5?style=flat-square&logo=kubernetes)](https://www.cncf.io/)
[![FOSDEM 2026](https://img.shields.io/badge/FOSDEM-2026-00D4AA?style=flat-square)](https://fosdem.org/2026/)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue.svg?style=flat-square)](LICENSE)
[![VictoriaMetrics](https://img.shields.io/badge/VictoriaMetrics-Partner-FF3366?style=flat-square)](https://victoriametrics.com/)

A hands-on lab to simulate LLM/ML attacks, observe their signatures in real-time, and understand how to detect them using the open-source CNCF security stack.

**Your AI model is an attack surface. Monitor it like one.**

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    iAttack Lab Application                       │
│                                                                  │
│  ┌─────────────┐  ┌────────────────┐  ┌────────────────────┐    │
│  │ Attacks      │  │ Defenses       │  │ Monitoring         │    │
│  │              │  │                │  │                    │    │
│  │ • Prompt Inj │  │ • Guardrails   │  │ • SecurityMetrics  │    │
│  │ • Jailbreak  │  │ • Input Filter │  │ • OTel Integration │    │
│  │ • Poisoning  │  │ • Output Filter│  │ • Prometheus       │    │
│  │ • Extraction │  │ • Rate Limit   │  │ • Alert Engine     │    │
│  │ • Membership │  │                │  │                    │    │
│  └──────┬───────┘  └───────┬────────┘  └────────┬───────────┘    │
│         └──────────────────┴─────────────────────┘               │
│                              │                                   │
│                    Prometheus :8000/metrics                       │
│                    OTLP gRPC :4317                                │
└──────────────────────────────┬───────────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
┌──────────────┐  ┌──────────────────┐  ┌──────────────┐
│ OTel Collect.│  │ VictoriaMetrics  │  │   Loki       │
│              │──│ + vmalert        │  │              │
│ Traces+Met.  │  │ PromQL alerting  │  │ LogQL invest.│
└──────┬───────┘  └────────┬─────────┘  └──────┬───────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                    ┌──────▼───────┐
                    │   Grafana    │
                    │ Dashboards   │
                    │ Unified View │
                    └──────────────┘

K8s deployment adds: Falco (eBPF) · Kyverno · DCGM Exporter · NetworkPolicies
```

---

## Quick Start

### Docker Compose (local dev)

```bash
git clone https://github.com/erythix4/iattack.git
cd iattack

# Start the full observability stack
docker-compose up -d

# Access points:
#   App:              http://localhost:8081
#   Grafana:          http://localhost:3000  (admin / llmattacklab)
#   VictoriaMetrics:  http://localhost:8428
#   Metrics:          http://localhost:8000/metrics
```

### Kubernetes (production)

```bash
# Deploy the entire CNCF security stack
./scripts/deploy-k8s.sh

# Or step by step with Helm (slide 16):
helm repo add vm https://victoriametrics.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo add falcosecurity https://falcosecurity.github.io/charts

helm install vmsingle vm/victoria-metrics-single \
  -n monitoring --create-namespace

helm install falco falcosecurity/falco \
  --set falcosidekick.enabled=true \
  --set-file customRules."falco_ml_rules\.yaml"=config/falco/falco_ml_rules.yaml \
  -n security --create-namespace
```

---

## Repository Structure

```
iattack/
├── llm_attack_lab/              # Core Python application
│   ├── attacks/                 # 5 attack simulators
│   │   ├── prompt_injection.py  #   Direct/indirect injection, role hijacking
│   │   ├── jailbreak.py         #   DAN, hypothetical framing, grandma exploit
│   │   ├── data_poisoning.py    #   Backdoor, label flipping, clean-label
│   │   ├── model_extraction.py  #   API probing, distillation, data extraction
│   │   └── membership_inference.py  # Perplexity-based membership detection
│   ├── defenses/                # Defense mechanisms
│   │   ├── guardrails.py        #   Multi-layer guardrail system
│   │   ├── input_sanitizer.py   #   Pattern detection, unicode normalization
│   │   └── output_filter.py     #   Content classification, redaction
│   ├── monitoring/              # Observability layer
│   │   ├── security_metrics.py  #   ML-specific security metrics catalog
│   │   ├── otel.py              #   OpenTelemetry SDK integration
│   │   ├── metrics.py           #   Prometheus metrics exporter
│   │   ├── alerts.py            #   Alert engine + thresholds
│   │   └── dashboard.py         #   CLI security dashboard
│   ├── core/                    # Engine
│   │   ├── attack_engine.py     #   Base attack class + execution engine
│   │   └── llm_simulator.py     #   LLM simulation for lab purposes
│   └── web/                     # Flask web interface
│       └── app.py               #   REST API + web dashboard
│
├── config/                      # Configuration files
│   ├── otel-collector-config.yaml   # OTel Collector pipeline
│   ├── vmagent.yaml                 # Prometheus scraping
│   ├── vmalert/                     # ★ vmalert security rules
│   │   └── ml-security-rules.yaml   #   GPU, inference, adversarial, LLM alerts
│   ├── falco/                       # ★ Falco ML runtime rules
│   │   ├── falco_ml_rules.yaml      #   Model theft, shell, GPU, crypto mining
│   │   └── falco-values.yaml        #   Helm values for Falco deployment
│   ├── kyverno/                     # ★ Admission control policies
│   │   └── ml-policies.yaml         #   Image signing, read-only models, seccomp
│   ├── seccomp/                     # ★ Container security profiles
│   │   └── seccomp-ml-inference.json  # Custom seccomp allowing GPU ioctls
│   ├── dcgm/                        # ★ GPU metrics exporter
│   └── grafana/                     # Dashboard provisioning
│
├── k8s/                         # ★ Kubernetes manifests
│   ├── namespaces/              #   ml-serving, monitoring, security (PSS enforced)
│   ├── ml-serving/              #   App deployment + NetworkPolicies
│   │   ├── deployment.yaml      #   Init containers, sidecar, seccomp, read-only
│   │   └── networkpolicies.yaml #   Default deny, inference-only, rate limiting
│   └── monitoring/              #   VM, vmalert, OTel DaemonSet, Grafana, DCGM
│
├── ci-cd/                       # ★ Secure ML pipeline
│   └── tekton/                  #   Tekton pipeline: scan → sign → SBOM → deploy
│
├── ml-security-monitoring_ressources/  # Companion resources (FOSDEM/CNCF)
│   ├── alerting/                #   PromQL/vmalert rule YAML files
│   ├── dashboards/              #   Grafana JSON dashboards
│   ├── exporters/               #   Python security metrics exporter
│   ├── logql/                   #   LogQL query library for investigation
│   └── docs/                    #   Threat model framework, speaker notes
│
├── scripts/                     # Deployment & testing
│   ├── deploy-k8s.sh           # ★ One-command K8s deployment
│   └── run_tests.sh            #   Test suite runner
│
├── tests/                       # Comprehensive test suite
├── docs/                        # Documentation
│   ├── ATTACKS.md               #   Attack guide (5 types, techniques, defenses)
│   ├── DEFENSES.md              #   Defense architecture
│   ├── OBSERVABILITY.md         #   Monitoring stack guide
│   └── DEMO_GUIDE.md            #   Demo walkthrough
│
├── docker-compose.yaml          # Local dev stack (VM + Loki + OTel + Grafana + vmalert)
├── Dockerfile                   # Application container
└── requirements.txt             # Python dependencies
```

*★ = new files aligned with CNCF Meetup presentation content*

---

## Detection Patterns

The lab implements the 3 detection patterns from the presentation:

### Pattern 1: Adversarial Input Detection

Detect crafted inputs that fool classifiers while appearing normal.

| Metric | Alert Threshold | Attack Detected |
|--------|----------------|-----------------|
| `ml_input_reconstruction_error` | > 2.5 | FGSM, PGD |
| `ml_prediction_confidence` | > 0.95 (with high error) | Adversarial inputs |
| `ml_embedding_distance_to_centroid` | > 3x threshold | Out-of-distribution |
| `ml_prediction_stability_score` | Spike > 3x avg | Perturbation attacks |

### Pattern 2: Model Behavior Monitoring

Detect poisoning and extraction through behavioral drift.

| Metric | Alert Threshold | Attack Detected |
|--------|----------------|-----------------|
| `ml_prediction_distribution_psi` | > 0.2 | Data poisoning |
| `ml_feature_importance_drift` | Sudden change | Poisoned training |
| `ml_api_queries_total` + entropy | High rate + low entropy | Model extraction |
| `ml_accuracy_by_class` | Drop on specific class | Targeted attack |

### Pattern 3: LLM-Specific Security

Detect prompt injection, jailbreaks, and agent abuse.

| Metric | Alert Threshold | Attack Detected |
|--------|----------------|-----------------|
| `llm_prompt_injection_score` | > 0.85 | Prompt injection |
| `llm_prompt_similarity_to_system` | > 0.9 | System prompt extraction |
| `llm_output_policy_violations_total` | rate > 0 | Jailbreak / bypass |
| `llm_tool_calls_total{tool=~"shell\|exec"}` | > 5/5m | Agent tool abuse |

---

## Kubernetes Security Features

### Runtime Hardening

- **Pod Security Standards**: `restricted` profile enforced on `ml-serving` namespace
- **Custom seccomp**: allows GPU ioctls while blocking dangerous syscalls
- **Read-only model mounts**: prevents runtime model tampering
- **Network isolation**: default-deny with explicit inference and monitoring ingress
- **Init container verification**: SHA-256 model integrity check before serving

### Admission Control (Kyverno)

- Image signature verification via cosign/Sigstore
- Mandatory security labels for compliance tracking
- Read-only model volume enforcement
- Seccomp profile requirement
- Privilege escalation prevention

### Runtime Detection (Falco)

- Model file exfiltration (`.pt`, `.onnx`, `.safetensors`)
- Shell access in inference containers
- GPU driver exploit attempts (CVE-2024-0132)
- Unauthorized outbound connections
- Crypto mining detection
- System prompt file access by unexpected processes

### GPU Security (DCGM + vmalert)

- Crypto mining detection: GPU busy + no inference traffic
- Memory leak prediction: linear growth projection
- Thermal anomaly alerting (> 85°C sustained)
- Encoder usage detection (video encoding ≠ ML inference)
- XID error monitoring (driver exploit indicators)

---

## CI/CD Pipeline Security

The Tekton pipeline implements 5 security stages:

```
Train → Scan → Sign → SBOM → Deploy
         │       │       │
    ModelScan  cosign  CycloneDX
    Fickling  Sigstore  SLSA L3
```

1. **Scan**: ModelScan for malicious model files, Fickling for pickle exploits
2. **Sign**: cosign keyless signing via Sigstore (SLSA Level 3 provenance)
3. **SBOM**: CycloneDX bill of materials for model + dependencies
4. **Deploy**: Model hash → ConfigMap → init container verification

---

## SOC Integration & EU AI Act

The stack maps to EU AI Act compliance requirements:

| Article | Requirement | Implementation |
|---------|-------------|----------------|
| Art. 9 | Risk management | VictoriaMetrics + vmalert continuous monitoring |
| Art. 12 | Record-keeping | Loki + OTel structured logs |
| Art. 13 | Transparency | Explainability metrics + audit trail |
| Art. 14 | Human oversight | Grafana alerting → SOC escalation |
| Art. 15 | Accuracy & robustness | PSI/KL drift detection, adversarial resilience |

---

## Lab Usage

### Interactive Mode

```bash
# CLI interactive mode
python -m llm_attack_lab --interactive

# Run a specific attack
python -m llm_attack_lab --attack prompt_injection

# List all attacks
python -m llm_attack_lab --list

# Web dashboard
python -m llm_attack_lab --web
```

### Running Attacks (observe in Grafana)

```bash
# Start the stack
docker-compose up -d

# Open Grafana → ML Security Dashboard
# Run attacks via CLI or web UI
# Watch metrics spike in real-time
```

### Verifying Metrics

```bash
# Check application metrics
curl -s http://localhost:8000/metrics | grep -E "^(llm_|ml_)"

# Query VictoriaMetrics
curl -s "http://localhost:8428/api/v1/query?query=llm_prompt_injection_score"

# Check vmalert rules
curl -s http://localhost:8880/api/v1/rules
```

---

## Presentation Materials

This lab accompanies the presentations:

- **CNCF Meetup**: *AI Security Monitoring: Detecting Threats Against Production ML Systems*
- **FOSDEM 2026 Security Devroom**: *AI Security Monitoring: Detecting Threats Against Production ML Systems*

Slides and companion resources are in `ml-security-monitoring_ressources/`.

---

## Tech Stack

| Component | Role | Version |
|-----------|------|---------|
| VictoriaMetrics | TSDB + PromQL alerting | v1.96.0 |
| vmalert | Alert rule evaluation | v1.96.0 |
| Grafana | Visualization | 10.2.3 |
| OpenTelemetry Collector | Telemetry pipeline | 0.91.0 |
| Loki | Log aggregation + LogQL | 2.9.3 |
| Falco | eBPF runtime security | latest |
| Kyverno | K8s admission control | latest |
| DCGM Exporter | GPU metrics | 3.3.0 |
| Tekton | CI/CD pipelines | v1 |

---

## Author

**Samuel Desseaux**
Founder & CTO · [Erythix](https://erythix.tech) (FR) / Aureonis (BE)
VictoriaMetrics Training Partner

---

## License

GPL-3.0 — see [LICENSE](LICENSE)
