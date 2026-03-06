# LogQL Query Library for ML Security Investigation

This document provides ready-to-use LogQL queries for investigating ML security incidents using Grafana Loki.

## Log Schema

Expected JSON log format:

```json
{
  "timestamp": "2025-02-01T10:30:00Z",
  "level": "security",
  "model": "fraud-detector-v2",
  "event_type": "adversarial_detected",
  "user_id": "usr_abc123",
  "confidence": 0.94,
  "reconstruction_error": 2.7,
  "trace_id": "abc123..."
}
```

---

## Adversarial Detection Queries

### Find all adversarial detections for a user
```logql
{job="ml-security"} |= "adversarial" | json | user_id="usr_abc123"
```

### High reconstruction error events (last 24h)
```logql
{job="ml-security"} | json | reconstruction_error > 2.5
```

### Adversarial detections with high confidence
```logql
{job="ml-security"} 
  | json 
  | event_type="adversarial_detected" 
  | confidence > 0.9 
  | reconstruction_error > 2.0
```

### Count adversarial events by model
```logql
sum by (model) (
  count_over_time({job="ml-security"} | json | event_type="adversarial_detected" [1h])
)
```

### Adversarial events timeline
```logql
{job="ml-security"} | json | event_type="adversarial_detected" | line_format "{{.timestamp}} - Model: {{.model}} - User: {{.user_id}} - Error: {{.reconstruction_error}}"
```

---

## Prompt Injection Queries

### Prompt injection attempts with context
```logql
{job="llm-security"} |= "injection" | json | injection_score > 0.8
```

### All injection attempts for specific user
```logql
{job="llm-security"} 
  | json 
  | event_type="prompt_injection" 
  | user_id="usr_abc123"
```

### High severity injection attempts
```logql
{job="llm-security"} 
  | json 
  | event_type="prompt_injection" 
  | injection_score > 0.95
  | line_format "🚨 CRITICAL: User {{.user_id}} - Score: {{.injection_score}} - Prompt: {{.prompt | trunc 100}}"
```

### Injection attempts by pattern type
```logql
sum by (pattern_type) (
  count_over_time({job="llm-security"} | json | event_type="prompt_injection" [24h])
)
```

### System prompt extraction attempts
```logql
{job="llm-security"} 
  | json 
  | event_type=~"system_prompt_extraction|prompt_similar_to_system"
```

---

## Model Extraction Queries

### High query rate users
```logql
{job="ml-security"} 
  | json 
  | event_type="api_query"
  | line_format "{{.user_id}}"
  | topk(10, count_over_time({} [1h])) by (user_id)
```

### Low entropy query patterns (systematic probing)
```logql
{job="ml-security"} | json | query_entropy < 2.0
```

### Boundary probing detection
```logql
{job="ml-security"} 
  | json 
  | event_type="boundary_query_detected"
  | line_format "User: {{.user_id}} - Model: {{.model}} - Boundary ratio: {{.boundary_ratio}}"
```

### Extract user query history
```logql
{job="ml-security"} 
  | json 
  | user_id="suspect_user_123"
  | line_format "{{.timestamp}} | {{.event_type}} | Input: {{.input_hash}}"
```

---

## Model Drift Queries

### Distribution drift events
```logql
{job="ml-security"} | json | event_type="distribution_drift" | psi_score > 0.2
```

### Accuracy drops by class
```logql
{job="ml-security"} 
  | json 
  | event_type="accuracy_drop"
  | line_format "Model: {{.model}} - Class: {{.class}} - Drop: {{.accuracy_delta}}"
```

### Feature importance changes
```logql
{job="ml-security"} 
  | json 
  | event_type="feature_importance_shift"
  | abs(importance_delta) > 0.15
```

---

## Security Event Aggregations

### Count security events by type (last hour)
```logql
sum by (event_type) (
  count_over_time({job="ml-security"} [1h])
)
```

### Security events heatmap by hour
```logql
sum by (event_type) (
  count_over_time({job="ml-security"} | json | level="security" [$__interval])
)
```

### Top offending users (last 24h)
```logql
topk(10,
  sum by (user_id) (
    count_over_time({job="ml-security"} | json | level="security" [24h])
  )
)
```

### Critical events only
```logql
{job="ml-security"} | json | severity="critical"
```

---

## Correlation Queries

### Correlate events by trace ID
```logql
{job=~"ml-security|llm-security"} | json | trace_id="abc123def456"
```

### User activity timeline
```logql
{job=~"ml-security|llm-security"} 
  | json 
  | user_id="usr_abc123"
  | line_format "{{.timestamp}} | {{.job}} | {{.event_type}} | {{.model}}"
```

### Events around incident time (±5 minutes)
```logql
{job="ml-security"} 
  | json 
  | __timestamp__ >= 1706780000000000000 
  | __timestamp__ <= 1706780600000000000
```

---

## Retention Policy Recommendations

| Log Type | Retention | Rationale |
|----------|-----------|-----------|
| Security events | 90 days | Incident investigation, compliance |
| Prediction logs | 30 days | Drift detection, debugging |
| Debug/trace logs | 7 days | Development, short-term debugging |
| API access logs | 90 days | Extraction detection, audit |

---

## Alerting Rules (Loki)

### Alert on injection spike
```yaml
groups:
  - name: llm-security-alerts
    rules:
      - alert: InjectionSpike
        expr: |
          sum(count_over_time({job="llm-security"} | json | event_type="prompt_injection" [5m])) > 10
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Prompt injection spike detected"
```

### Alert on new user with high security events
```yaml
- alert: SuspiciousNewUser
  expr: |
    sum by (user_id) (
      count_over_time({job="ml-security"} | json | level="security" [1h])
    ) > 20
    unless
    sum by (user_id) (
      count_over_time({job="ml-security"} | json [7d])
    ) > 100
  for: 5m
  labels:
    severity: warning
```
