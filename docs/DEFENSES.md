# Guide des Défenses LLM

Ce document décrit les mécanismes de défense implémentés et les bonnes pratiques.

## Architecture de Défense en Profondeur

```
┌─────────────────────────────────────────────────────────────┐
│                     USER INPUT                               │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                 INPUT SANITIZATION                           │
│  • Pattern detection                                         │
│  • Unicode normalization                                     │
│  • Length limiting                                           │
│  • Special token neutralization                              │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                 RATE LIMITING                                │
│  • Request throttling                                        │
│  • User-based limits                                         │
│  • Burst protection                                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    LLM CORE                                  │
│  • System prompt isolation                                   │
│  • Instruction hierarchy                                     │
│  • Capability restrictions                                   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                 OUTPUT FILTERING                             │
│  • Content classification                                    │
│  • Sensitive data redaction                                  │
│  • Jailbreak detection                                       │
│  • Leak prevention                                           │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  FINAL OUTPUT                                │
└─────────────────────────────────────────────────────────────┘
```

## 1. Input Sanitization

### Détection de Patterns

```python
from llm_attack_lab.defenses import InputSanitizer

sanitizer = InputSanitizer(strict_mode=True)
result = sanitizer.sanitize(user_input)

if result.threat_level >= ThreatLevel.HIGH:
    # Block or escalate
    pass
```

### Patterns Détectés

| Pattern | Type | Sévérité |
|---------|------|----------|
| `ignore.*previous.*instructions` | Override | HIGH |
| `you are now` | Role change | CRITICAL |
| `<\|.*\|>` | Special token | CRITICAL |
| `[INST]` | Instruction token | CRITICAL |
| `reveal.*prompt` | Extraction | HIGH |

### Normalisation Unicode

Prévient l'obfuscation via caractères Unicode :
- Zero-width spaces
- Homoglyphes
- Caractères de contrôle

## 2. Output Filtering

### Classification du Contenu

```python
from llm_attack_lab.defenses import OutputFilter

filter = OutputFilter(strict_mode=True, redact_sensitive=True)
result = filter.filter(llm_output)

if result.category == OutputCategory.HARMFUL:
    # Block output
    pass
```

### Catégories de Détection

- **SAFE**: Contenu acceptable
- **SENSITIVE**: Données personnelles détectées
- **LEAKED**: Fuite d'informations système
- **JAILBROKEN**: Indicateurs de contournement
- **HARMFUL**: Contenu dangereux

### Redaction Automatique

Données automatiquement masquées :
- Emails
- Numéros de téléphone
- Numéros de sécurité sociale
- Cartes de crédit
- Mots de passe
- Clés API

## 3. Guardrails System

### Usage Complet

```python
from llm_attack_lab.defenses import GuardrailSystem, GuardrailAction

guardrails = GuardrailSystem(strict_mode=True)

# Vérifier l'input
input_decision = guardrails.check_input(user_input)
if input_decision.action == GuardrailAction.BLOCK:
    return "Input blocked"

# Appeler le LLM avec l'input sanitisé
response = llm.generate(input_decision.input_result.sanitized_input)

# Vérifier l'output
output_decision = guardrails.check_output(response)
if output_decision.action == GuardrailAction.BLOCK:
    return "Output blocked"

# Retourner la réponse filtrée
return output_decision.output_result.filtered_output
```

### Actions Possibles

| Action | Description |
|--------|-------------|
| ALLOW | Autoriser sans modification |
| WARN | Autoriser mais logger |
| MODIFY | Modifier et autoriser |
| BLOCK | Bloquer complètement |
| ESCALATE | Requiert revue humaine |

## 4. Bonnes Pratiques

### Pour les Développeurs

1. **Principe du moindre privilège**
   - Limiter les capacités du LLM
   - Pas d'accès à des ressources non essentielles

2. **Validation stricte**
   - Valider toutes les entrées
   - Ne jamais faire confiance aux données utilisateur

3. **Defense in depth**
   - Plusieurs couches de protection
   - Redondance des défenses

4. **Monitoring continu**
   - Logger toutes les interactions
   - Alerter sur les anomalies

5. **Mises à jour régulières**
   - Suivre les nouvelles vulnérabilités
   - Red-teaming fréquent

### Pour les Opérateurs

1. **Audit des logs**
   - Revue régulière des tentatives d'attaque
   - Analyse des patterns

2. **Gestion des incidents**
   - Procédures de réponse définies
   - Communication rapide

3. **Tests de pénétration**
   - Tests réguliers par des équipes spécialisées
   - Bug bounty programs

## 5. Métriques de Sécurité

### KPIs Recommandés

- **Taux de blocage**: % d'inputs/outputs bloqués
- **Faux positifs**: Blocages incorrects
- **Temps de détection**: Latence des checks
- **Coverage**: % d'attaques connues détectées

### Dashboard de Monitoring

```python
stats = guardrails.get_statistics()
print(f"Total requests: {stats['total_requests']}")
print(f"Block rate: {stats['block_rate']:.1f}%")
print(f"Threats by type: {stats['threats_by_type']}")
```

## 6. Ressources

- [OWASP LLM Security](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [Anthropic Safety](https://www.anthropic.com/safety)
- [OpenAI Safety](https://openai.com/safety)
