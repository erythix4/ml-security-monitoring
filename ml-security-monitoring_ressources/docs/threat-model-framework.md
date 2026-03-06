# ML Security Threat Model Framework

A structured approach to identifying and mitigating security risks in ML systems.

## Overview

This framework guides you through four key questions to build a comprehensive threat model for your ML system:

1. **ASSETS** - What are we protecting?
2. **ADVERSARIES** - Who attacks?
3. **VECTORS** - How do they attack?
4. **SIGNALS** - What detects attacks?

---

## 1. ASSETS - What Are We Protecting?

### Asset Inventory

| Asset Type | Description | Sensitivity | Impact if Compromised |
|------------|-------------|-------------|----------------------|
| **Model IP** | Trained model weights and architecture | ☐ Low ☐ Medium ☐ High | |
| **Training Data** | Data used to train the model | ☐ Low ☐ Medium ☐ High | |
| **Inference Data** | User inputs during inference | ☐ Low ☐ Medium ☐ High | |
| **Predictions** | Model outputs and decisions | ☐ Low ☐ Medium ☐ High | |
| **System Prompts** | LLM instructions and context | ☐ Low ☐ Medium ☐ High | |
| **API Keys/Secrets** | Authentication credentials | ☐ Low ☐ Medium ☐ High | |
| **User Data** | PII in requests or context | ☐ Low ☐ Medium ☐ High | |

### Questions to Answer

- [ ] What is the monetary value of the model if stolen?
- [ ] Does the training data contain PII or sensitive information?
- [ ] What decisions depend on model predictions?
- [ ] What regulatory requirements apply (GDPR, HIPAA, etc.)?

---

## 2. ADVERSARIES - Who Attacks?

### Adversary Profiles

| Adversary Type | Motivation | Capabilities | Likelihood |
|----------------|------------|--------------|------------|
| **External Hackers** | Financial gain, notoriety | ☐ Low ☐ Medium ☐ High | ☐ Low ☐ Medium ☐ High |
| **Competitors** | Market advantage | ☐ Low ☐ Medium ☐ High | ☐ Low ☐ Medium ☐ High |
| **Malicious Insiders** | Revenge, financial gain | ☐ Low ☐ Medium ☐ High | ☐ Low ☐ Medium ☐ High |
| **Compromised Vendors** | Supply chain attack | ☐ Low ☐ Medium ☐ High | ☐ Low ☐ Medium ☐ High |
| **Nation States** | Espionage, disruption | ☐ Low ☐ Medium ☐ High | ☐ Low ☐ Medium ☐ High |
| **Researchers** | Academic, bug bounty | ☐ Low ☐ Medium ☐ High | ☐ Low ☐ Medium ☐ High |

### Questions to Answer

- [ ] Who benefits from compromising our ML system?
- [ ] What is the attacker's expected skill level?
- [ ] Do we have insider threat risks?
- [ ] Are there supply chain dependencies?

---

## 3. VECTORS - How Do They Attack?

### Attack Surface by ML Pipeline Stage

#### Data Ingestion
| Attack Vector | Description | Applicable? | Mitigation |
|---------------|-------------|-------------|------------|
| Data Poisoning | Inject malicious samples | ☐ Yes ☐ No | |
| Label Flipping | Corrupt training labels | ☐ Yes ☐ No | |
| Supply Chain | Compromise data sources | ☐ Yes ☐ No | |

#### Training
| Attack Vector | Description | Applicable? | Mitigation |
|---------------|-------------|-------------|------------|
| Backdoor Injection | Hidden triggers in model | ☐ Yes ☐ No | |
| Gradient Attacks | Manipulate training gradients | ☐ Yes ☐ No | |
| Model Tampering | Direct weight modification | ☐ Yes ☐ No | |

#### Model Serving
| Attack Vector | Description | Applicable? | Mitigation |
|---------------|-------------|-------------|------------|
| Adversarial Inputs | Crafted inputs to fool model | ☐ Yes ☐ No | |
| Model Extraction | Clone model via API | ☐ Yes ☐ No | |
| Membership Inference | Reveal training data | ☐ Yes ☐ No | |
| Model Inversion | Reconstruct training samples | ☐ Yes ☐ No | |

#### LLM Applications
| Attack Vector | Description | Applicable? | Mitigation |
|---------------|-------------|-------------|------------|
| Direct Prompt Injection | "Ignore previous instructions" | ☐ Yes ☐ No | |
| Indirect Prompt Injection | Malicious content in RAG docs | ☐ Yes ☐ No | |
| Jailbreaking | Bypass safety guardrails | ☐ Yes ☐ No | |
| System Prompt Extraction | Reveal confidential instructions | ☐ Yes ☐ No | |
| Agent Attacks | Abuse tool/function access | ☐ Yes ☐ No | |

### Questions to Answer

- [ ] Is the model accessible via API?
- [ ] Do we control the training pipeline?
- [ ] Is the model used with untrusted inputs?
- [ ] Does the LLM have access to tools or external systems?

---

## 4. SIGNALS - What Detects Attacks?

### Detection Capabilities

#### Adversarial Input Detection
| Signal | Metric | Threshold | Implemented? |
|--------|--------|-----------|--------------|
| Reconstruction Error | `ml_input_reconstruction_error` | > 2.5 | ☐ Yes ☐ No |
| Embedding Distance | `ml_embedding_distance_to_centroid` | > 3x baseline | ☐ Yes ☐ No |
| Prediction Instability | `ml_prediction_stability_score` | < 0.7 | ☐ Yes ☐ No |
| Ensemble Disagreement | `ml_ensemble_disagreement_rate` | > 0.3 | ☐ Yes ☐ No |

#### Behavior Monitoring
| Signal | Metric | Threshold | Implemented? |
|--------|--------|-----------|--------------|
| Distribution Drift | `ml_prediction_distribution_psi` | > 0.2 | ☐ Yes ☐ No |
| Query Rate | `ml_api_queries_total` | > 100/min | ☐ Yes ☐ No |
| Query Entropy | `ml_query_entropy_score` | < 2.0 | ☐ Yes ☐ No |
| Accuracy Drop | `ml_accuracy_by_class` | > 10% drop | ☐ Yes ☐ No |

#### LLM Security
| Signal | Metric | Threshold | Implemented? |
|--------|--------|-----------|--------------|
| Injection Score | `llm_prompt_injection_score` | > 0.85 | ☐ Yes ☐ No |
| System Prompt Similarity | `llm_prompt_similarity_to_system` | > 0.7 | ☐ Yes ☐ No |
| Policy Violations | `llm_output_policy_violations_total` | > 0 | ☐ Yes ☐ No |
| Suspicious Tool Usage | `llm_tool_calls_total` | > 5/min sensitive | ☐ Yes ☐ No |

### Questions to Answer

- [ ] Do we have baseline metrics for normal behavior?
- [ ] Are alerts routed to the appropriate team?
- [ ] Do we have runbooks for each alert type?
- [ ] Is there a process for tuning thresholds?

---

## Risk Assessment Matrix

| Threat | Likelihood | Impact | Risk Score | Priority |
|--------|------------|--------|------------|----------|
| | ☐ 1 ☐ 2 ☐ 3 | ☐ 1 ☐ 2 ☐ 3 | L × I = | |
| | ☐ 1 ☐ 2 ☐ 3 | ☐ 1 ☐ 2 ☐ 3 | L × I = | |
| | ☐ 1 ☐ 2 ☐ 3 | ☐ 1 ☐ 2 ☐ 3 | L × I = | |
| | ☐ 1 ☐ 2 ☐ 3 | ☐ 1 ☐ 2 ☐ 3 | L × I = | |
| | ☐ 1 ☐ 2 ☐ 3 | ☐ 1 ☐ 2 ☐ 3 | L × I = | |

**Risk Score Key**: 1-2 = Low, 3-4 = Medium, 6-9 = High

---

## Action Plan

| Priority | Threat | Mitigation | Owner | Due Date | Status |
|----------|--------|------------|-------|----------|--------|
| P1 | | | | | ☐ |
| P1 | | | | | ☐ |
| P2 | | | | | ☐ |
| P2 | | | | | ☐ |
| P3 | | | | | ☐ |

---

## Review Schedule

- [ ] Initial threat model completed: ____/____/____
- [ ] Quarterly review scheduled: ____/____/____
- [ ] Post-incident review trigger defined
- [ ] Model update review trigger defined

---

## References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

---

*Template by Samuel Desseaux - Erythix | Apache 2.0 License*
