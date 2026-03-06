# SOC Integration & EU AI Act Compliance Guide
## ML Security Monitoring Stack
**github.com/erythix4/ml-security-monitoring**  
Samuel Desseaux · Erythix / Aureonis · Apache 2.0

---

## Part 1 — Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     ML Workload (Kubernetes)                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │  Inference  │  │  Training   │  │  LLM Apps   │                 │
│  │    Pods     │  │    Jobs     │  │  (RAG/Agent)│                 │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                 │
│         │ OTel SDK        │ OTel SDK        │ OTel SDK              │
└─────────┼────────────────┼─────────────────┼──────────────────────-┘
          │                │                 │
          ▼                ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  OTel Collector (DaemonSet)                         │
│  Receives: traces / metrics / logs   Processes: batch, filter, tag  │
└──────────────┬──────────────────────────────┬───────────────────────┘
               │ metrics (RemoteWrite)         │ logs (Loki push)
               ▼                              ▼
┌──────────────────────────┐    ┌─────────────────────────────────────┐
│    VictoriaMetrics       │    │             Loki                    │
│  (metrics + vmalert)     │    │  (structured security event logs)   │
└──────────┬───────────────┘    └──────────────┬──────────────────────┘
           │ alerts                            │ log queries (LogQL)
           ▼                                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         Grafana                                      │
│   ML Security Dashboard  │  LLM Threat Dashboard  │  Compliance view │
└──────────────────────────┴───────────────────────-┴───────────────────┘
           │ AlertManager webhooks
           ▼
┌──────────────────────────────────────────────────────────────────────┐
│        SOC SIEM  (Splunk / OpenSearch / IBM QRadar / Wazuh)         │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                     Falco (eBPF DaemonSet)                          │
│  Detects: shell access / model exfiltration / GPU driver abuse       │
│  Routes via: Falcosidekick → Loki + Alertmanager                    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Part 2 — Alertmanager Configuration

### 2.1 — Routing tree explained

```yaml
# Key routing decisions:
# 1. All critical alerts → Slack + SOC email
# 2. LLM-specific threats → LLM security team
# 3. Model theft indicators → SOC + legal hold workflow
# 4. EU AI Act incidents → compliance officer

route:
  group_by: ["alertname", "namespace", "model_name"]
  group_wait: 30s       # Collect related alerts before sending
  group_interval: 5m    # Resend grouped alerts after 5 min
  repeat_interval: 4h   # Suppress repeat notifications after 4 h
  receiver: default

  routes:
    # Critical path: immediate SOC notification
    - matchers: [severity="critical"]
      receiver: soc-critical
      continue: true  # Also evaluate subsequent routes

    # LLM attacks
    - matchers: [category="llm_security"]
      receiver: llm-security-team

    # EU AI Act high-risk system incidents
    - matchers: [eu_ai_act_incident="true"]
      receiver: compliance-officer
      group_wait: 0s  # Immediate - regulatory requirement

    # Model theft
    - matchers: [category=~"extraction|model_theft"]
      receiver: legal-and-soc
```

### 2.2 — SOC webhook for SIEM ingestion

```yaml
receivers:
  - name: soc-siem-webhook
    webhook_configs:
      - url: "https://your-siem.internal/api/ingest/ml-security"
        http_config:
          authorization:
            type: Bearer
            credentials: "${SIEM_API_TOKEN}"
        send_resolved: true
        # Payload is standard Alertmanager JSON — most SIEMs support it natively
```

### 2.3 — PagerDuty integration (on-call rotation)

```yaml
  - name: soc-pagerduty
    pagerduty_configs:
      - routing_key: "${PAGERDUTY_INTEGRATION_KEY}"
        severity: "{{ if eq .CommonLabels.severity \"critical\" }}critical{{ else }}warning{{ end }}"
        summary: "{{ .GroupLabels.alertname }} on {{ .CommonLabels.model_name }}"
        details:
          model: "{{ .CommonLabels.model_name }}"
          namespace: "{{ .CommonLabels.namespace }}"
          category: "{{ .CommonLabels.category }}"
```

---

## Part 3 — Grafana Dashboard Specifications

### Dashboard 1 — ML Security Overview (ID: ml-sec-overview)

| Panel | Query | Visualization |
|---|---|---|
| Threat events / 5 min | `sum by (category) (increase(ml_threat_events_total[5m]))` | Time series |
| Active adversarial sessions | `count(ml_llm_security_risk_score > 0.7)` | Stat |
| Model extraction risk score | `avg(ml_extraction_risk_score) by (model_name)` | Gauge |
| Falco critical events | `sum(rate({job="falcosidekick"} \| json \| priority="Critical" [5m]))` | Stat |
| Top attacked models | `topk(5, sum by (model_name) (increase(ml_threat_events_total[1h])))` | Bar chart |
| Threat heatmap | `sum by (threat_type, hour) (...)` | Heatmap |

### Dashboard 2 — LLM Threat Monitor (ID: ml-llm-threats)

| Panel | Query | Visualization |
|---|---|---|
| Injection attempts/min | `rate(ml_llm_injection_classifier_score > 0.85 [1m])` | Time series |
| Jailbreak rate | `rate(ml_llm_jailbreak_pattern_matches_total[5m])` | Time series |
| PII leakage events | `increase(ml_llm_pii_detections_in_output_total[1h])` | Stat (alert if > 0) |
| Safety refusal rate | `rate(ml_llm_safety_refusals_total[5m])` | Time series |
| RAG anomaly scores | `max by (app_name) (ml_rag_retrieved_context_anomaly_score)` | Table |
| Session risk table | LogQL: `{component="llm-serving"} \| json \| threat_type != ""` | Logs panel |

### Dashboard 3 — Compliance & Audit (ID: ml-compliance)

| Panel | Purpose |
|---|---|
| EU AI Act incident count (30d) | GPAI incident reporting tracker |
| Data leakage events | GDPR Art. 33 breach notification trigger |
| Model accuracy SLA | Continuous monitoring obligation (Art. 9) |
| Audit log export button | Pre-built panel with 90-day log export |
| RBAC access audit | Who accessed model endpoints + when |

---

## Part 4 — EU AI Act Compliance Mapping

### 4.1 — Applicability

| System Type | Risk Level | Monitoring Obligation |
|---|---|---|
| General purpose AI (GPAI) | Varies | Incident reporting, capability eval |
| High-risk AI (Annex III: HR, credit, biometrics…) | HIGH | Art. 9: risk management system, continuous monitoring |
| LLM deployed in regulated sector | HIGH | Transparency, human oversight, logging |
| Recommendation systems (general) | LIMITED | Transparency notice |
| Internal ML tools (no third-party deployment) | MINIMAL | Basic logging recommended |

### 4.2 — Article-by-article mapping to monitoring capabilities

| EU AI Act Article | Requirement | Stack Component | Implementation |
|---|---|---|---|
| **Art. 9** | Risk management system | VictoriaMetrics + vmalert | Continuous metrics + automated alerts |
| **Art. 12** | Record-keeping & logging | Loki (90-day retention) | Structured JSON logs, tamper-evident |
| **Art. 13** | Transparency & user information | Grafana dashboards | Audit-ready reports |
| **Art. 15** | Accuracy, robustness, cybersecurity | Adversarial detection rules | PromQL rules in `adversarial-detection.yml` |
| **Art. 17** | Quality management | Drift monitoring | `drift-and-extraction.yml` drift alerts |
| **Art. 26** | Deployer obligations | OTel + Falco | Runtime monitoring + container security |
| **Art. 73** | Incident reporting (GPAI) | Alertmanager → compliance receiver | Automated compliance notifications |
| **Art. 88** | Confidentiality of data | Falco rules | Model exfiltration + data leakage detection |

### 4.3 — Incident reporting checklist (Art. 73 GPAI)

When a `PotentialAdversarialInput`, `LLMOutputDataLeakage`, or `ModelExtractionQuerySpike` alert fires for a high-risk AI system:

```
□ 1. Capture alert details + Grafana snapshot (automated via webhook)
□ 2. Export relevant Loki logs for the incident window (see LogQL §6.2)
□ 3. Assess actual harm vs. near-miss
□ 4. If personal data involved → GDPR Art. 33 notification within 72h
□ 5. If serious incident under AI Act → notify national market surveillance authority
□ 6. Document in the technical file (Art. 11)
□ 7. Update risk management record (Art. 9.6)
□ 8. Review and update monitoring rules if new threat pattern detected
```

### 4.4 — Audit log requirements

```yaml
# Loki retention configuration for compliance
# Set in values.yaml → loki.loki.limits_config
limits_config:
  retention_period: 2160h   # 90 days minimum (Art. 12 recommendation)
  # For high-risk AI systems, consider 365d+
```

Ensure logs include at minimum:
- Timestamp (UTC, ISO 8601)
- Model name and version
- Prediction inputs hash (not raw PII)
- Prediction output category
- Any detected threat type + score
- User/session identifier (pseudonymized)
- System component generating the event

---

## Part 5 — SOC Runbooks

### Runbook: Adversarial Input (alert `PotentialAdversarialInput`)

```
SEVERITY: Critical
SLA: Acknowledge < 15 min, Triage < 30 min

1. CONFIRM
   - Check Grafana ML Security Overview dashboard
   - Identify: model_name, namespace, client_id, session_id

2. SCOPE
   - LogQL: {component="serving"} | json | session_id="<ID>"
   - Is this a single session or multiple clients?
   - Determine if model served wrong predictions (accuracy metric)

3. CONTAIN
   - Rate-limit or block the offending client_id at the API gateway
   - If widespread: scale down serving replicas and page model owner

4. INVESTIGATE
   - Export logs (see LogQL §6.2)
   - Check if adversarial examples succeeded (confidence was acted on)
   - Review ML pipeline for upstream data integrity

5. RECOVER
   - Re-enable serving after confirming traffic is clean
   - Update adversarial detection threshold if needed
   - File EU AI Act incident record if high-risk system
```

### Runbook: Model Exfiltration (Falco `Model File Exfiltration via Network Tool`)

```
SEVERITY: Critical
SLA: Acknowledge < 5 min, Contain < 15 min

1. CONFIRM
   - Loki: {job="falcosidekick"} | json | rule="Model File Exfiltration via Network Tool"
   - Identify: pod, proc.name, fd.name (model file), destination IP

2. CONTAIN (IMMEDIATE)
   - kubectl delete pod <POD_NAME> -n <NAMESPACE>  # Kill the pod
   - Apply NetworkPolicy to block egress from model serving namespace:
     kubectl apply -f emergency-network-policy.yaml

3. SCOPE
   - Was the model file fully transferred? Check network bytes (fd.bytes)
   - Which model was targeted? Check fd.name
   - How did attacker gain access? Check K8s audit logs for RBAC changes

4. RECOVER
   - Rotate model signing keys
   - Redeploy from clean image
   - File IP theft incident report (legal team)
   - Update Falco rules if new exfiltration method detected
```

### Runbook: LLM PII Leakage (alert `LLMOutputDataLeakage`)

```
SEVERITY: Critical — GDPR Art. 33 applies
SLA: Acknowledge < 5 min, DPO notification < 1 hour

1. CONFIRM & PRESERVE
   - Export full session log immediately (LogQL §3.3)
   - Do NOT delete logs — preserve for legal

2. IDENTIFY SCOPE
   - How many sessions affected? Which users?
   - What PII type: name, email, health, financial?

3. CONTAIN
   - If active: terminate affected sessions
   - Disable the problematic LLM endpoint temporarily

4. NOTIFY
   - DPO: within 1 hour (internal obligation)
   - CNIL (France) / DPA: within 72 hours if confirmed breach (GDPR Art. 33)
   - Affected users: if high risk to their rights (GDPR Art. 34)

5. REMEDIATE
   - Update prompt templates to prevent PII passthrough
   - Add output PII filtering layer
   - Review RAG document ingestion pipeline for PII contamination
```

---

## Part 6 — Quick Reference

### Environment variables needed

```bash
export CLUSTER_NAME="prod-eu-west-1"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export SIEM_API_TOKEN="..."
export PAGERDUTY_INTEGRATION_KEY="..."
```

### Install the stack

```bash
# Add Helm repos
helm repo add victoriametrics https://victoriametrics.github.io/helm-charts/
helm repo add grafana https://grafana.github.io/helm-charts
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update

# Install
helm install ml-security ./helm/ml-security-stack \
  --namespace ml-security \
  --create-namespace \
  --values helm/ml-security-stack/values.yaml \
  --set alertmanager.config.receivers[0].slack_configs[0].api_url=$SLACK_WEBHOOK_URL
```

### Verify deployment

```bash
kubectl get pods -n ml-security
kubectl port-forward svc/ml-security-grafana 3000:80 -n ml-security
# Open http://localhost:3000 — admin / changeme
```

### Add ML monitoring to your inference pods

```yaml
# Add these labels and annotations to your ML pod spec:
metadata:
  labels:
    ml-monitoring: "true"
    model_name: "your-model-name"
    component: "serving"
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
```
