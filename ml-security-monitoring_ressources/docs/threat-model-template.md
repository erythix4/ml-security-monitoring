# ML Security Threat Model Framework

**Organization:** ________________________________  
**Model/System:** ________________________________  
**Date:** ________________________________  
**Version:** ________________________________  

---

## 1. ASSETS — What are we protecting?

### 1.1 Model Assets
| Asset | Sensitivity | Value Estimate | Notes |
|-------|-------------|----------------|-------|
| Model weights/parameters | ☐ Low ☐ Medium ☐ High ☐ Critical | $ | |
| Training data | ☐ Low ☐ Medium ☐ High ☐ Critical | $ | |
| Inference API | ☐ Low ☐ Medium ☐ High ☐ Critical | $ | |
| System prompts (LLM) | ☐ Low ☐ Medium ☐ High ☐ Critical | $ | |
| Fine-tuning data | ☐ Low ☐ Medium ☐ High ☐ Critical | $ | |

### 1.2 Data Privacy Concerns
- [ ] Training data contains PII
- [ ] Model may memorize sensitive data
- [ ] Predictions reveal sensitive information
- [ ] User queries are confidential

### 1.3 Business Impact of Compromise
| Scenario | Impact |
|----------|--------|
| Model stolen/cloned | |
| Training data leaked | |
| Predictions manipulated | |
| Service unavailable | |

---

## 2. ADVERSARIES — Who attacks?

### 2.1 Threat Actor Profiles
| Actor | Motivation | Capability | Likelihood |
|-------|------------|------------|------------|
| External hackers | ☐ Financial ☐ Competitive ☐ Ideological | ☐ Low ☐ Medium ☐ High | ☐ Low ☐ Medium ☐ High |
| Malicious insiders | ☐ Financial ☐ Revenge ☐ Espionage | ☐ Low ☐ Medium ☐ High | ☐ Low ☐ Medium ☐ High |
| Compromised vendors | ☐ Supply chain ☐ Targeted | ☐ Low ☐ Medium ☐ High | ☐ Low ☐ Medium ☐ High |
| Competitors | ☐ IP theft ☐ Sabotage | ☐ Low ☐ Medium ☐ High | ☐ Low ☐ Medium ☐ High |
| Researchers | ☐ Academic ☐ Bug bounty | ☐ Low ☐ Medium ☐ High | ☐ Low ☐ Medium ☐ High |

### 2.2 Access Level Assessment
| Access Type | Available To |
|-------------|--------------|
| Public API access | |
| Authenticated API access | |
| Training pipeline access | |
| Model file access | |
| Infrastructure access | |

---

## 3. VECTORS — How do they attack?

### 3.1 Attack Surface Checklist

**Data Ingestion Phase**
- [ ] Training data poisoning
- [ ] Data supply chain compromise
- [ ] Label manipulation
- [ ] Data augmentation attacks

**Training Phase**
- [ ] Backdoor injection
- [ ] Gradient attacks
- [ ] Hyperparameter manipulation
- [ ] Checkpoint tampering

**Model Serving Phase**
- [ ] Adversarial inputs (FGSM, PGD, etc.)
- [ ] Model extraction via API
- [ ] Membership inference
- [ ] Model inversion

**LLM-Specific (if applicable)**
- [ ] Direct prompt injection
- [ ] Indirect prompt injection (RAG)
- [ ] Jailbreaking
- [ ] System prompt extraction
- [ ] Agent/tool manipulation

### 3.2 MITRE ATLAS Mapping
| Technique ID | Technique Name | Applicable? | Mitigation |
|--------------|----------------|-------------|------------|
| AML.T0000 | ML Model Access | ☐ Yes ☐ No | |
| AML.T0010 | ML Supply Chain Compromise | ☐ Yes ☐ No | |
| AML.T0020 | Poison Training Data | ☐ Yes ☐ No | |
| AML.T0040 | Adversarial ML Attack | ☐ Yes ☐ No | |
| AML.T0043 | Prompt Injection | ☐ Yes ☐ No | |

---

## 4. SIGNALS — What detects attacks?

### 4.1 Detection Coverage Matrix

| Attack Type | Metric | Log | Alert | Gap? |
|-------------|--------|-----|-------|------|
| Adversarial inputs | ☐ | ☐ | ☐ | |
| Model extraction | ☐ | ☐ | ☐ | |
| Data poisoning | ☐ | ☐ | ☐ | |
| Prompt injection | ☐ | ☐ | ☐ | |
| Distribution drift | ☐ | ☐ | ☐ | |

### 4.2 Monitoring Implementation

**Metrics to Export**
| Metric Name | Type | Labels | Implemented? |
|-------------|------|--------|--------------|
| `ml_input_reconstruction_error` | Gauge | model | ☐ |
| `ml_prediction_confidence` | Histogram | model | ☐ |
| `ml_embedding_distance` | Gauge | model, cluster | ☐ |
| `ml_api_queries_total` | Counter | model, user_id | ☐ |
| `ml_prediction_distribution_psi` | Gauge | model | ☐ |
| `llm_prompt_injection_score` | Gauge | app, user_id | ☐ |

**Alerting Rules**
| Alert Name | Threshold | Severity | Implemented? |
|------------|-----------|----------|--------------|
| PotentialAdversarialInput | recon_error > 2.5 AND conf > 0.95 | Critical | ☐ |
| SuspiciousQueryPattern | rate > 100/min | Critical | ☐ |
| ModelDistributionDrift | PSI > 0.2 for 15m | Warning | ☐ |
| PromptInjectionDetected | score > 0.85 | Critical | ☐ |

---

## 5. RISK ASSESSMENT

### 5.1 Risk Matrix

| Threat | Likelihood | Impact | Risk Score | Priority |
|--------|------------|--------|------------|----------|
| | ☐1 ☐2 ☐3 ☐4 ☐5 | ☐1 ☐2 ☐3 ☐4 ☐5 | L×I = | ☐ P1 ☐ P2 ☐ P3 |
| | ☐1 ☐2 ☐3 ☐4 ☐5 | ☐1 ☐2 ☐3 ☐4 ☐5 | L×I = | ☐ P1 ☐ P2 ☐ P3 |
| | ☐1 ☐2 ☐3 ☐4 ☐5 | ☐1 ☐2 ☐3 ☐4 ☐5 | L×I = | ☐ P1 ☐ P2 ☐ P3 |
| | ☐1 ☐2 ☐3 ☐4 ☐5 | ☐1 ☐2 ☐3 ☐4 ☐5 | L×I = | ☐ P1 ☐ P2 ☐ P3 |

### 5.2 Mitigation Plan

| Risk | Mitigation | Owner | Deadline | Status |
|------|------------|-------|----------|--------|
| | | | | ☐ Open ☐ In Progress ☐ Done |
| | | | | ☐ Open ☐ In Progress ☐ Done |
| | | | | ☐ Open ☐ In Progress ☐ Done |

---

## 6. REVIEW & SIGN-OFF

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Security Lead | | | |
| ML Engineer | | | |
| Product Owner | | | |

**Next Review Date:** ________________________________

---

*Template from FOSDEM 2026 - AI Security Monitoring*  
*github.com/erythix/ml-security-monitoring*
