# LogQL Investigation Query Library
## ML Security Monitoring — Attack Correlation & Forensics
**github.com/erythix4/ml-security-monitoring**  
Samuel Desseaux · Erythix / Aureonis · Apache 2.0

---

## How to Use This Library

Paste queries directly into Grafana Explore (Loki datasource) or use `logcli`:

```bash
logcli query '{namespace="ml-production"}' --limit=100 --since=1h
```

Replace label values (`model_name`, `namespace`, `pod`) to match your environment.

---

## 1. Adversarial Input Detection

### 1.1 — All adversarial input events in the last hour
```logql
{namespace=~".+", component="serving"}
  |= "adversarial"
  | json
  | threat_type = "adversarial_input"
  | line_format "{{.ts}} [{{.level}}] model={{.model_name}} score={{.score}} session={{.session_id}}"
```

### 1.2 — High reconstruction error events (score > 2.5)
```logql
{component="serving"}
  | json
  | threat_type = "adversarial_input"
  | score > 2.5
  | line_format "{{.ts}} model={{.model_name}} recon_error={{.score}} client={{.client_id}}"
```

### 1.3 — Out-of-distribution inputs grouped by model
```logql
sum by (model_name) (
  count_over_time(
    {component="serving"}
    | json
    | threat_type = "ood_input"
    [5m]
  )
)
```

### 1.4 — Adversarial events per client IP (identify systematic probing)
```logql
topk(10,
  sum by (client_ip) (
    count_over_time(
      {component="serving"}
      | json
      | threat_type =~ "adversarial_input|ood_input"
      [1h]
    )
  )
)
```

---

## 2. Model Extraction Attack Correlation

### 2.1 — API request spike detection per client
```logql
sum by (client_id) (
  rate(
    {component="serving"}
    | json
    | level = "info"
    | action = "inference_request"
    [5m]
  )
)
```

### 2.2 — Boundary probing: low confidence + high volume from same session
```logql
{component="serving"}
  | json
  | prediction_confidence < 0.55
  | prediction_confidence > 0.45
  | line_format "{{.ts}} model={{.model_name}} client={{.client_id}} conf={{.prediction_confidence}}"
```

### 2.3 — Single client responsible for > 80% of requests (extraction indicator)
```logql
# Run in two steps: first get total, then get per-client
# Step 1 — total requests
sum(rate({component="serving"} | json | action="inference_request" [10m]))

# Step 2 — per client
sum by (client_id) (
  rate(
    {component="serving"}
    | json
    | action = "inference_request"
    [10m]
  )
)
```

### 2.4 — Extraction session reconstruction (follow a suspicious session)
```logql
{namespace=~".+"}
  | json
  | session_id = "<SUSPICIOUS_SESSION_ID>"
  | line_format "{{.ts}} [{{.level}}] {{.action}} model={{.model_name}} conf={{.prediction_confidence}}"
```

---

## 3. LLM Security Investigation

### 3.1 — All prompt injection events
```logql
{component=~"llm-serving|llm-gateway"}
  | json
  | threat_type = "prompt_injection"
  | line_format "{{.ts}} app={{.app_name}} session={{.session_id}} score={{.score}}"
```

### 3.2 — Jailbreak attempts timeline
```logql
count_over_time(
  {component=~"llm-serving|llm-gateway"}
  | json
  | threat_type = "jailbreak"
  [1m]
)
```

### 3.3 — PII detected in LLM output (GDPR incident investigation)
```logql
{component=~"llm-serving|llm-gateway"}
  | json
  | threat_type = "pii_in_output"
  | line_format "{{.ts}} app={{.app_name}} session={{.session_id}} pii_type={{.pii_type}} user={{.user_id}}"
```

### 3.4 — RAG poisoning: anomalous context retrieval events
```logql
{component=~"llm-serving|rag-service"}
  | json
  | threat_type = "rag_context_anomaly"
  | anomaly_score > 0.75
  | line_format "{{.ts}} doc_id={{.retrieved_doc_id}} score={{.anomaly_score}} query={{.user_query}}"
```

### 3.5 — System prompt extraction attempts
```logql
{component=~"llm-serving|llm-gateway"}
  | json
  | threat_type = "system_prompt_probe"
  | line_format "{{.ts}} session={{.session_id}} pattern={{.probe_pattern}} app={{.app_name}}"
```

### 3.6 — Agent tool abuse: unexpected tool calls
```logql
{component="llm-agent"}
  | json
  | action = "tool_call"
  | tool_name !~ "(search|calculator|code_interpreter|retriever)"
  | line_format "{{.ts}} agent={{.agent_id}} tool={{.tool_name}} session={{.session_id}}"
```

### 3.7 — Full session forensics for a given user (LLM audit trail)
```logql
{component=~"llm-serving|llm-gateway|llm-agent"}
  | json
  | user_id = "<USER_ID>"
  | line_format "{{.ts}} [{{.level}}] {{.action}} app={{.app_name}} threat={{.threat_type}}"
```

---

## 4. Falco Runtime Events Correlation

### 4.1 — All critical Falco ML events
```logql
{job="falcosidekick"}
  | json
  | priority = "Critical"
  | rule =~ "Model.*|Shell.*|GPU.*|Reverse.*"
  | line_format "{{.time}} [{{.priority}}] {{.rule}} pod={{.k8s_pod_name}} ns={{.k8s_ns_name}}"
```

### 4.2 — Shell spawned in ML containers (timeline)
```logql
count_over_time(
  {job="falcosidekick"}
  | json
  | rule = "Shell Spawned Inside ML Container"
  [1m]
)
```

### 4.3 — Model exfiltration attempts by pod
```logql
{job="falcosidekick"}
  | json
  | rule =~ "Model File.*"
  | line_format "{{.time}} rule={{.rule}} proc={{.proc_name}} file={{.fd_name}} pod={{.k8s_pod_name}}"
```

### 4.4 — GPU device access anomalies
```logql
{job="falcosidekick"}
  | json
  | rule =~ ".*GPU.*|.*NVIDIA.*"
  | line_format "{{.time}} [{{.priority}}] {{.rule}} proc={{.proc_name}} pod={{.k8s_pod_name}}"
```

### 4.5 — Correlate Falco alert with upstream ML metrics (cross-signal)
```logql
# Find the pod from Falco event, then cross-reference with Loki ML logs
# Step 1 — get pod name from Falco
{job="falcosidekick"}
  | json
  | rule =~ "Model.*"
  | line_format "pod={{.k8s_pod_name}} time={{.time}}"

# Step 2 — investigate that pod's ML application logs
{pod="<POD_FROM_STEP_1>"}
  | json
  | line_format "{{.ts}} [{{.level}}] {{.action}} threat={{.threat_type}}"
```

---

## 5. User Behavior Analysis

### 5.1 — Unique users per model (baseline normal usage)
```logql
count by (model_name) (
  sum by (model_name, user_id) (
    count_over_time(
      {component="serving"}
      | json
      | action = "inference_request"
      [1h]
    )
  )
)
```

### 5.2 — Requests per user over time (spot behavioral outliers)
```logql
sum by (user_id) (
  rate(
    {component="serving"}
    | json
    | action = "inference_request"
    [5m]
  )
)
```

### 5.3 — Users with multiple threat event types (high-risk actor)
```logql
sum by (user_id, threat_type) (
  count_over_time(
    {component=~"serving|llm-serving"}
    | json
    | threat_type != ""
    [24h]
  )
)
```

---

## 6. Forensic Investigation Templates

### 6.1 — Full attack timeline for a specific session
```logql
{namespace=~".+"}
  | json
  | session_id = "<SESSION_ID>"
  | line_format "{{.ts}} [{{.level}}] svc={{.component}} action={{.action}} threat={{.threat_type}} score={{.score}}"
```

### 6.2 — Incident window — all security events in a time range
```logql
# Set time range in Grafana or with --from/--to in logcli
{namespace=~"ml-.+"}
  | json
  | threat_type != ""
  | line_format "{{.ts}} ns={{.namespace}} pod={{.pod}} model={{.model_name}} threat={{.threat_type}} score={{.score}}"
```

### 6.3 — Export raw events for SIEM ingestion
```bash
logcli query \
  '{namespace=~"ml-.+"} | json | threat_type != ""' \
  --from="2026-01-01T00:00:00Z" \
  --to="2026-01-02T00:00:00Z" \
  --output=raw \
  > incident-export.ndjson
```

### 6.4 — Threat event frequency heatmap data (Grafana time series)
```logql
sum by (threat_type) (
  count_over_time(
    {namespace=~"ml-.+"}
    | json
    | threat_type != ""
    [5m]
  )
)
```

---

## Label Reference

| Label | Description | Example |
|---|---|---|
| `namespace` | K8s namespace | `ml-production` |
| `pod` | K8s pod name | `inference-server-7d9f` |
| `component` | Service role | `serving`, `training`, `llm-serving` |
| `model_name` | ML model identifier | `fraud-detector-v3` |
| `session_id` | User/request session | `sess_abc123` |
| `client_id` | API client identifier | `client_xyz` |
| `user_id` | End-user identifier | `usr_001` |
| `threat_type` | Detected threat category | `adversarial_input`, `prompt_injection`, `rag_context_anomaly` |
| `score` | Anomaly/threat score | `2.87` |
| `action` | Log event action | `inference_request`, `tool_call` |
