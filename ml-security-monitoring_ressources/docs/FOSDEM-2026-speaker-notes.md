# Speaker Notes — AI Security Monitoring
## FOSDEM 2026 | Security Devroom | 25 minutes

---

## ⏱️ TIMING OVERVIEW

| Section | Slides | Duration | Cumulative |
|---------|--------|----------|------------|
| Opening & Problem | 1-5 | 5 min | 5:00 |
| Threat Model Framework | 6 | 2 min | 7:00 |
| Detection Patterns | 7-12 | 7 min | 14:00 |
| Open Source Stack | 13-16 | 5 min | 19:00 |
| Demo | 17 | 3 min | 22:00 |
| Limitations & Closing | 18-21 | 3 min | 25:00 |

---

## SLIDE 1 — Title (0:00-0:30)

**Key points:**
- "Bonjour, je suis Samuel Desseaux, founder d'Erythix en France et Aureonis en Belgique"
- "Aujourd'hui on va parler de comment monitorer vos systèmes ML comme des attack surfaces"
- "Tout ce que je présente est open source et disponible sur GitHub"

**Transition:** "Let's start with why this matters RIGHT NOW"

---

## SLIDE 2 — What We'll Cover (0:30-1:00)

**Key points:**
- Quick overview - don't read the slide
- "6 sections, hands-on focus, you'll leave with actionable code"
- "We'll end with a live demo of attack detection"

**Transition:** "First, let's talk about your AI model as an attack surface"

---

## SLIDE 3 — Your AI Model is a New Attack Surface (1:00-2:30)

**Key points:**
- "Traditional security monitors network, logs, firewalls..."
- "But WHO monitors the AI layer itself?"
- Point to each threat box briefly:
  - "Adversarial inputs - crafted to fool classifiers"
  - "Data poisoning - corrupted training data"
  - "Prompt injection - OWASP #1 for LLM apps"
  - "Model extraction - stealing your IP via API"
  - "Membership inference - privacy attacks"
  - "Model drift - silent degradation attackers exploit"

**Punchline:** "These threats don't show up in your SIEM. That's the problem."

**Transition:** "Why are ML systems fundamentally different from traditional software?"

---

## SLIDE 4 — Why ML Systems Are Different (2:30-3:30)

**Key points:**
- **Data = Code:** "In traditional software, you review code. In ML, your DATA is your code. Poisoned data = compromised logic with no diff to review."
- **Opaque Logic:** "Billions of parameters. No stack trace. You can't explain WHY the model made that decision."
- **Emergent Behavior:** "Models behave unexpectedly on edge cases. Distribution shifts create unpredictable responses."

**Punchline:** "This is why we need ML-SPECIFIC security monitoring."

**Transition:** "So why is this urgent RIGHT NOW?"

---

## SLIDE 5 — Why Now? The Threat Landscape (3:30-5:00)

**Key points:**
- **OWASP Top 10 LLM:** "Prompt injection is officially #1. We have a taxonomy now - LLM01 to LLM10."
- **MITRE ATLAS:** "600+ documented ML attack techniques. ATT&CK but for AI. This is how nation-states think about AI attacks."
- **Real Incidents 2024:** 
  - "Model extraction at Replika - their models were cloned"
  - "ChatGPT jailbreaks every month"
  - "Copilot system prompt leaks"
  - "AI is under ACTIVE attack, not theoretical"

**Punchline:** "The frameworks exist. The attacks are real. The question is: are you monitoring?"

**Transition:** "Let's build a structured approach. Here's my threat model framework."

---

## SLIDE 6 — Threat Model Framework for ML (5:00-7:00)

**Key points:**
- Walk through the pipeline: "Data ingestion → Training → Serving → LLM apps"
- Each stage has specific threats
- "4 questions to structure your analysis:"
  1. **ASSETS:** "What are you protecting? Model IP? Training data privacy? Prediction integrity?"
  2. **ADVERSARIES:** "Who attacks? External? Insiders? Compromised vendors?"
  3. **VECTORS:** "How? API access? Training pipeline? Supply chain?"
  4. **SIGNALS:** "What DETECTS attacks? This is where most teams fail."

**Call to action:** "Template PDF available - link at the end"

**Transition:** "Now let's get into the 3 detection patterns"

---

## SLIDE 7 — Adversarial Input Detection (7:00-8:00)

**Key points:**
- "Pattern 1: Detecting crafted inputs"
- **Key insight:** "High confidence + high reconstruction error = classic adversarial signature"
- "The model is confident but the input doesn't match training distribution"
- Walk through metrics quickly - they'll see the code on next slide

**Transition:** "Here's the actual Prometheus alerting"

---

## SLIDE 8 — Prometheus Alerting: Adversarial (8:00-9:30)

**Key points:**
- Read the first alert: "reconstruction_error > 2.5 AND confidence > 0.95"
- "This catches FGSM, PGD attacks with ~85% detection rate"
- "Only +2-5ms latency overhead"
- "Full YAML on GitHub - copy paste ready"

**Technical note:** "The threshold 2.5 is baseline-dependent. Calibrate for your model."

**Transition:** "Pattern 2: monitoring model BEHAVIOR over time"

---

## SLIDE 9 — Model Behavior Monitoring (9:30-10:30)

**Key points:**
- "Detecting poisoning and extraction attempts"
- **Distribution drift:** "PSI score > 0.2 = significant shift"
- **Query patterns:** "10K queries often enough to clone simple models"
- "Rate limit + alert EARLY"

**Transition:** "The alerting rules..."

---

## SLIDE 10 — Prometheus Alerting: Behavior (10:30-11:30)

**Key points:**
- "PSI > 0.2 for 15 minutes = potential poisoning"
- "100 queries/min from single user = extraction attempt"
- "Accuracy drop by class = targeted attack"

**Punchline:** "These rules catch slow, subtle attacks that traditional monitoring misses."

**Transition:** "Pattern 3: LLM-specific security"

---

## SLIDE 11 — LLM Security Monitoring (11:30-12:30)

**Key points:**
- "Prompt injection is OWASP #1"
- Walk through threat taxonomy:
  - Direct injection: "Ignore previous instructions..."
  - Indirect injection: "Malicious content in RAG documents"
  - Jailbreaking: "Creative bypasses"
  - System prompt extraction: "What are your instructions?"

**Technical tip:** "Use ProtectAI/deberta-v3-base-prompt-injection classifier"

**Transition:** "Here's the alerting..."

---

## SLIDE 12 — Prometheus Alerting: LLM (12:30-14:00)

**Key points:**
- "injection_score > 0.85 = critical alert"
- "Similarity to system prompt > 0.7 = extraction attempt"
- "Tool calls to shell/exec/write = agent attack"

**Punchline:** "These rules would have caught most public jailbreaks."

**Transition:** "Now let's talk about the STACK"

---

## SLIDE 13 — The Fully Open Source Stack (14:00-15:30)

**Key points:**
- "Prometheus, Loki, Grafana, OpenTelemetry"
- "4 key advantages:"
  - **No vendor lock-in:** "CNCF projects + VictoriaMetrics for scale"
  - **Already in SOC:** "Likely already deployed"
  - **Extensible:** "Custom exporters"
  - **Scalable:** "Proven at scale"

**Punchline:** "You probably have 80% of this already. We're just adding ML-specific metrics."

**Transition:** "Let me show you the log analysis..."

---

## SLIDE 14 — Structured Logging with Loki (15:30-16:30)

**Key points:**
- Show log schema: "JSON structured, trace_id for correlation"
- "LogQL queries are powerful - find all adversarial detections for a user in one line"
- "Retention policies: security 90 days, predictions 30 days"

**Transition:** "The dashboards..."

---

## SLIDE 15 — Grafana Dashboards (16:30-17:30)

**Key points:**
- "5 key metrics at a glance"
- "Time series for trends, tables for investigations, logs panel for live stream"
- "Alert list links to runbooks"

**Note:** "Dashboard JSON on GitHub - import directly"

**Transition:** "How does this connect to your existing SOC?"

---

## SLIDE 16 — SOC Integration Architecture (17:30-19:00)

**Key points:**
- Walk through the architecture diagram
- "Alertmanager webhooks → SIEM"
- "Grafana OnCall for incident management"
- "Loki → syslog → SIEM for log forwarding"
- "OTel exporters to any backend"

**Punchline:** "This isn't a separate security stack. It INTEGRATES with what you have."

**Transition:** "Building custom exporters..."

---

## SLIDE 17 — Building Custom Exporters (19:00-20:00)

**Key points:**
- Show Python code briefly
- "prometheus_client library"
- "Decorator pattern - wrap your predict function"
- "Best practices: histograms for distributions, avoid high cardinality, async export"

**Technical tip:** "Sample expensive computations - 1% is enough for detection"

**Transition:** "Let's see it in action"

---

## SLIDE 18 — Demo (20:00-23:00)

**⚠️ DEMO SCRIPT:**

1. **Adversarial Input (45 sec)**
   - "Running FGSM attack on fraud classifier"
   - Show reconstruction error spike in Grafana
   - Show alert firing
   - Show log entry with trace ID

2. **Model Extraction (45 sec)**
   - "Simulating systematic API queries"
   - Show query rate spike
   - "Low entropy pattern flagged"
   - Show user ID logged

3. **Prompt Injection (45 sec)**
   - "Jailbreak attempt on LLM"
   - "Injection classifier triggers"
   - "Request blocked"
   - "Full prompt logged for investigation"

**Wrap up:** "All this with standard open source tools"

**Transition:** "Before we close, important limitations..."

---

## SLIDE 19 — What You're Taking Home (23:00-23:30)

**Key points:**
- "4 resources, all on GitHub:"
  - Threat model template PDF
  - Prometheus YAML files
  - LogQL query library
  - SOC integration guide

**Call to action:** "github.com/erythix/ml-security-monitoring - star it, fork it, contribute"

**Transition:** "But let me be honest about limitations..."

---

## SLIDE 20 — Limitations & Considerations (23:30-24:30)

**Key points:**
- **Not a Silver Bullet:** "These detect KNOWN patterns. Zero-day techniques may evade."
- **Setup Required:** "Reconstruction error needs trained autoencoder. Baselines per model."
- **False Positives:** "Legitimate OOD data may trigger. Tune thresholds for YOUR use case."

**Punchline:** "This is a starting point, not the finish line. ML security is an ongoing practice."

**Transition:** "Final slide..."

---

## SLIDE 21 — Closing (24:30-25:00)

**Key points:**
- "Your AI model IS an attack surface. Monitor it like one."
- "Resources: GitHub, Twitter, website"
- "I'm available for questions here or in the hallway"

**Closing line:** "Thank you. Questions?"

---

## 🎤 Q&A PREPARATION

**Expected questions & answers:**

**Q: "How do you handle false positives in production?"**
A: "Start with high thresholds, tune down. Use severity levels. Page on critical, log on warning. Build runbooks for triage."

**Q: "Does this scale to millions of requests?"**
A: "Yes. Sample expensive computations (reconstruction error at 1%). VictoriaMetrics handles the cardinality. We've tested to 100K req/sec."

**Q: "What about model-specific detection?"**
A: "The patterns are general. Thresholds are model-specific. That's why baselines matter. Run calibration on known-good traffic."

**Q: "How do you train the autoencoder for reconstruction error?"**
A: "Train on your production input distribution. Simple architecture works - you're measuring anomaly, not reconstruction quality."

**Q: "Can this detect prompt injection in languages other than English?"**
A: "The classifier models are primarily English-trained. For multilingual, consider fine-tuning or using language detection first."

**Q: "What's the overhead?"**
A: "Metrics export: negligible. Reconstruction error: +2-5ms if inline, zero if async. Injection classifier: +20-50ms per request."

---

## 🔧 TECH CHECK

- [ ] Laptop connected to projector
- [ ] Demo environment running (docker-compose up)
- [ ] Grafana dashboards loaded
- [ ] Attack scripts ready
- [ ] Terminal font size increased
- [ ] Slack/notifications OFF
- [ ] Backup slides exported to PDF on USB

---

## 📍 FOSDEM LOGISTICS

- **Room:** Security Devroom (K.4.201)
- **Slot:** Check schedule
- **Setup time:** 5 min before
- **Mic:** Likely lapel mic
- **Questions:** Raise hands in room or on Matrix

---

*Good luck Samuel! Tu vas tout déchirer 🚀*
