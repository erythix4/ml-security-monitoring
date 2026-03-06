# Speaker Notes - AI Security Monitoring
## FOSDEM 2026 - Security Devroom (25 minutes)

---

## Timing Overview

| Section | Slides | Duration | Cumulative |
|---------|--------|----------|------------|
| Opening & Context | 1-5 | 5 min | 5 min |
| Threat Model Framework | 6 | 2 min | 7 min |
| Detection Patterns | 7-12 | 7 min | 14 min |
| Open Source Stack | 13-16 | 4 min | 18 min |
| Demo | 17 | 3 min | 21 min |
| Wrap-up & Limitations | 18-21 | 4 min | 25 min |

---

## SLIDE 1: Title (30 sec)

**Key points:**
- "Bonjour, je suis Samuel Desseaux, Founder & CTO d'Erythix et Aureonis"
- "Aujourd'hui: comment monitorer la sécurité de vos systèmes ML en production avec des outils 100% open source"
- "Tout le code et les configs sont dispo sur GitHub - lien à la fin"

**Transition:** "Commençons par le problème..."

---

## SLIDE 2: What We'll Cover (30 sec)

**Key points:**
- Parcourir rapidement les 6 sections
- "On va d'abord comprendre POURQUOI c'est différent, puis construire un framework, et finir avec une démo live"

**Transition:** "Alors, quel est le problème exactement?"

---

## SLIDE 3: Your AI Model is a New Attack Surface (1 min 30)

**Key points:**
- "La sécurité traditionnelle monitore le réseau et les logs système. Mais qui surveille la couche IA elle-même?"
- Parcourir les 6 menaces rapidement:
  - Adversarial inputs: "des inputs qui trompent le modèle tout en paraissant normaux"
  - Data poisoning: "corrompre les données d'entraînement"
  - Prompt injection: "le OWASP #1 pour les LLMs"
  - Model extraction: "voler votre modèle via l'API - 10K requêtes suffisent souvent"
  - Membership inference: "savoir si des données étaient dans le training set - privacy issue"
  - Model drift: "dégradation graduelle exploitable par les attaquants"

**Transition:** "Mais pourquoi les systèmes ML sont-ils si différents?"

---

## SLIDE 4: Why ML Systems Are Different (1 min)

**Key points:**
- **Data = Code:** "Dans le ML, les données SONT le programme. Pas de code review possible sur les données d'entraînement"
- **Opaque Logic:** "Milliards de paramètres - impossible de tracer pourquoi une décision a été prise"
- **Emergent Behavior:** "Le modèle peut se comporter de façon inattendue sur des edge cases"

**Pause:** Laisser le message sink in

**Transition:** "Et c'est maintenant que ça devient urgent..."

---

## SLIDE 5: Why Now? The Threat Landscape (1 min 30) ⭐ NOUVEAU

**Key points:**
- **OWASP Top 10 LLM:** "Prompt Injection est maintenant officiellement le risque #1 - c'est la taxonomie de référence"
- **MITRE ATLAS:** "600+ techniques d'attaque documentées - l'équivalent de ATT&CK pour le ML"
- **Real Incidents 2024:** 
  - "Model extraction chez Replika"
  - "Les jailbreaks ChatGPT qui font la une"
  - "Les leaks de system prompts de Copilot"
  - "L'IA est sous attaque active - ce n'est plus théorique"

**Emphasize:** "Si vous déployez du ML en prod sans monitoring sécurité, vous volez à l'aveugle"

**Transition:** "Comment structurer notre approche? Avec un threat model..."

---

## SLIDE 6: Threat Model Framework for ML (2 min)

**Key points:**
- Montrer le pipeline: Data Ingestion → Training → Model Serving → LLM Apps
- "Chaque étape a ses vecteurs d'attaque spécifiques"
- Les 4 questions clés:
  1. **ASSETS:** "Qu'est-ce qu'on protège? Le modèle? Les données? L'intégrité des prédictions?"
  2. **ADVERSARIES:** "Qui attaque? Hackers externes? Insiders? Vendors compromis?"
  3. **VECTORS:** "Comment? API access? Pipeline de training? Supply chain?"
  4. **SIGNALS:** "Quelles métriques détectent les attaques?"

- "Le PDF template est téléchargeable sur le repo"

**Transition:** "Passons aux patterns de détection concrets..."

---

## SLIDE 7: Adversarial Input Detection (1 min)

**Key points:**
- "Pattern 1: détecter les inputs crafted pour tromper le modèle"
- 4 signaux clés:
  - High confidence + High reconstruction error
  - Prediction instability
  - Feature space anomalies
  - Ensemble disagreement
- "Les métriques Prometheus à exporter sont listées à droite"

**Transition:** "Voyons les alertes correspondantes..."

---

## SLIDE 8: Prometheus Alerting - Adversarial (1 min)

**Key points:**
- Parcourir les 3 alertes YAML
- **Tip important:** "~85% de détection sur FGSM/PGD avec seulement 2-5ms de latency overhead"
- "Full YAML sur GitHub"

**Transition:** "Pattern 2: le comportement du modèle..."

---

## SLIDE 9: Model Behavior Monitoring (1 min)

**Key points:**
- "Détecter le poisoning et l'extraction en monitorant le comportement"
- Distribution drift (PSI/KL divergence)
- Query patterns - "10K queries suffisent souvent pour cloner un modèle simple"
- Performance regression sur des classes spécifiques

**Transition:** "Les alertes..."

---

## SLIDE 10: Prometheus Alerting - Behavior (1 min)

**Key points:**
- Distribution drift avec `for: 15m` - "on veut du signal, pas du bruit"
- Suspicious query pattern > 100 req/min
- Accuracy drop ciblé - "si une seule classe drop, c'est suspect"

**Key insight:** "Rate limit + alert early. Mieux vaut être trop prudent."

**Transition:** "Pattern 3, spécifique aux LLMs..."

---

## SLIDE 11: LLM Security Monitoring (1 min)

**Key points:**
- "Prompt injection est OWASP #1 - donc Pattern 3 est crucial"
- 4 types de menaces:
  - Direct injection: "Ignore previous instructions..."
  - Indirect injection: dans les docs RAG
  - Jailbreaking: bypass des guardrails
  - Extraction: "What are your instructions?"
- Métriques dédiées: injection_score, similarity_to_system, tool_calls

**Transition:** "Les alertes LLM..."

---

## SLIDE 12: Prometheus Alerting - LLM (1 min)

**Key points:**
- Injection > 0.85 → severity: critical
- System prompt extraction → surveiller la similarité avec le system prompt
- Tool usage suspicious → shell, exec, write avec rate > 5/min

**Tip:** "Utilisez ProtectAI/deberta-v3-base-prompt-injection - c'est open source et efficace"

**Transition:** "Maintenant, le stack technique..."

---

## SLIDE 13: The Fully Open Source Stack (1 min 30)

**Key points:**
- Prometheus: metrics collection, PromQL, Alertmanager
- Loki: logs structurés, rétention, LogQL
- Grafana: dashboards, alerting unifié
- OpenTelemetry: tracing des pipelines ML

**4 avantages:**
- No vendor lock-in (CNCF + VictoriaMetrics pour le scale)
- Already in SOC - probablement déjà déployé
- Extensible avec custom exporters
- Scalable - prouvé à l'échelle

**Transition:** "Comment structurer les logs..."

---

## SLIDE 14: Structured Logging with Loki (1 min)

**Key points:**
- Montrer le schema JSON: timestamp, level, model, event_type, user_id, confidence, trace_id
- Queries LogQL pour investigation
- "Les retention policies: Security 90j, Predictions 30j, Debug 7j"

**Transition:** "Les dashboards..."

---

## SLIDE 15: Grafana Security Dashboards (30 sec)

**Key points:**
- Vue d'ensemble rapide des panels
- "Time series, tables, logs panel, alert list"
- "Le JSON est sur le repo"

**Transition:** "L'intégration SOC..."

---

## SLIDE 16: SOC Integration Architecture (1 min)

**Key points:**
- ML Layer → Exporters → Observability → SOC Workflow
- 4 méthodes d'intégration:
  - Alertmanager webhooks vers SIEM
  - Grafana OnCall pour incident management
  - Loki vers SIEM via syslog
  - OTel exporters vers n'importe quel backend compatible

**Transition:** "Construire vos propres exporters..."

---

## SLIDE 17: Building Custom Exporters (45 sec)

**Key points:**
- Montrer le code Python rapidement
- "prometheus_client est votre ami"
- Best practices: histograms pour distributions, éviter high cardinality labels, async export

**Transition:** "Place à la démo..."

---

## SLIDE 18: Demo (3 min) ⭐ LIVE

**Setup avant:** Avoir Grafana ouvert sur le dashboard

**Scénario 1 - Adversarial (1 min):**
- Lancer l'attaque FGSM
- Montrer le spike de reconstruction error
- Montrer l'alert qui fire
- Montrer le log avec trace ID

**Scénario 2 - Model Extraction (1 min):**
- Lancer les queries systématiques
- Montrer le query rate spike
- Montrer le low entropy pattern
- "User ID loggé - on sait qui c'est"

**Scénario 3 - Prompt Injection (1 min):**
- Envoyer un jailbreak attempt
- Montrer l'injection classifier qui trigger
- Request blocked
- Full prompt loggé

**Closing:** "Stack: Prometheus + Loki + Grafana. Repo sur GitHub."

---

## SLIDE 19: What You're Taking Home (1 min)

**Key points:**
- 4 livrables concrets:
  1. Threat Model Framework PDF
  2. Prometheus alerting YAML files
  3. LogQL query library
  4. SOC integration configs + Grafana dashboards

- "Tout est Apache 2.0, PRs welcome!"
- Dire l'URL: github.com/erythix/ml-security-monitoring

**Transition:** "Mais attention aux limitations..."

---

## SLIDE 20: Limitations & Considerations (1 min) ⭐ NOUVEAU

**Key points:**
- **Not a Silver Bullet:** "Ces patterns détectent des signatures connues. Zero-day et nouvelles techniques peuvent passer initialement"
- **Setup Required:** "La détection par reconstruction error nécessite un autoencoder entraîné. Les baselines doivent être calibrées par modèle"
- **False Positives:** "Des données légitimes hors-distribution peuvent déclencher des alertes. Tuning nécessaire"

**Important:** "C'est un layer de défense supplémentaire, pas une solution magique"

**Transition:** "En conclusion..."

---

## SLIDE 21: Conclusion (1 min)

**Closer statement:** "Your AI model is an attack surface. Monitor it like one."

**Call to action:**
- "Le repo GitHub est live - clonez-le, testez-le, contribuez"
- "Je suis dispo pour les questions maintenant et pendant la conf"
- "Merci!"

**Contact:** Montrer les 3 liens (GitHub, Twitter, Website)

---

## Q&A Preparation

**Questions probables:**

1. **"Quel overhead sur les performances?"**
   - 2-5ms sur l'inférence pour les métriques de base
   - Reconstruction error peut être async si trop lent
   - Le monitoring ne doit pas bloquer l'inference

2. **"Comment entraîner l'autoencoder pour reconstruction error?"**
   - Sur les données de training normales
   - Architecture simple suffit (dense layers)
   - Retrain périodiquement avec les nouvelles données

3. **"Ça scale comment?"**
   - Prometheus scale à millions de séries
   - VictoriaMetrics si besoin de plus
   - Loki scale horizontalement

4. **"Et pour les modèles edge/embarqués?"**
   - Métriques agrégées envoyées périodiquement
   - Local detection + remote logging
   - OpenTelemetry Collector pour buffering

5. **"Intégration avec les MLOps platforms (MLflow, Kubeflow)?"**
   - Prometheus exporters standard
   - OTel SDK dans les pipelines
   - Grafana se connecte à tout

---

## Checklist Avant la Présentation

- [ ] Tester le docker-compose de la démo
- [ ] Vérifier que Grafana montre les bons dashboards
- [ ] Préparer les 3 attaques simulées
- [ ] Vérifier la connexion internet (pour la démo)
- [ ] Backup: screenshots si la démo live échoue
- [ ] Avoir le repo GitHub prêt et public
- [ ] Slide clicker chargé
- [ ] Water bottle

---

## Notes de Style

- **Tempo:** Dynamique mais pas rushed - c'est du contenu technique dense
- **Jargon:** OK pour cette audience (Security devroom = experts)
- **Code:** Ne pas lire le YAML ligne par ligne - pointer les parties importantes
- **Demo:** Si ça plante, avoir les screenshots ready. "As you can see in this screenshot..."
- **Questions pendant:** "Great question - let's cover that in Q&A" si ça déraille

---

*Good luck Samuel! 🚀*
