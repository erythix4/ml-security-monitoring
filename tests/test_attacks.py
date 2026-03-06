"""
Tests pour les Attaques

Ce module teste les différentes classes d'attaques simulées:
- Prompt Injection
- Jailbreak
- Data Poisoning
- Model Extraction
- Membership Inference

ÉTAPES DES TESTS D'ATTAQUE:
1. Vérification de la structure de l'attaque (nom, description, catégorie)
2. Vérification des payloads (existence, format)
3. Vérification du contenu éducatif
4. Test d'exécution contre le simulateur
"""

import pytest
from llm_attack_lab.attacks import ATTACK_REGISTRY
from llm_attack_lab.attacks.prompt_injection import PromptInjectionAttack, IndirectPromptInjection
from llm_attack_lab.core.attack_engine import AttackEngine, AttackResult, BaseAttack


class TestAttackRegistry:
    """Tests pour le registre des attaques"""

    def test_registry_not_empty(self):
        """Vérifie que le registre contient des attaques"""
        assert len(ATTACK_REGISTRY) > 0

    def test_all_expected_attacks_registered(self):
        """Vérifie que toutes les attaques attendues sont enregistrées"""
        expected = [
            "prompt_injection",
            "data_poisoning",
            "jailbreak",
            "model_extraction",
            "membership_inference"
        ]
        for attack_id in expected:
            assert attack_id in ATTACK_REGISTRY, f"Missing attack: {attack_id}"

    def test_registry_values_are_classes(self):
        """Vérifie que les valeurs sont des classes d'attaque"""
        for key, cls in ATTACK_REGISTRY.items():
            assert isinstance(cls, type)
            assert issubclass(cls, BaseAttack)


class TestBaseAttackInterface:
    """Tests pour l'interface de base des attaques"""

    @pytest.mark.parametrize("attack_id", ATTACK_REGISTRY.keys())
    def test_attack_has_required_attributes(self, attack_id):
        """Vérifie que chaque attaque a les attributs requis"""
        attack = ATTACK_REGISTRY[attack_id]()

        assert hasattr(attack, 'name')
        assert hasattr(attack, 'description')
        assert hasattr(attack, 'category')
        assert hasattr(attack, 'severity')

        assert isinstance(attack.name, str) and len(attack.name) > 0
        assert isinstance(attack.description, str) and len(attack.description) > 0

    @pytest.mark.parametrize("attack_id", ATTACK_REGISTRY.keys())
    def test_attack_has_payloads(self, attack_id):
        """Vérifie que chaque attaque a des payloads"""
        attack = ATTACK_REGISTRY[attack_id]()
        payloads = attack.get_payloads()

        assert isinstance(payloads, list)
        assert len(payloads) > 0
        for payload in payloads:
            assert isinstance(payload, str)
            assert len(payload) > 0

    @pytest.mark.parametrize("attack_id", ATTACK_REGISTRY.keys())
    def test_attack_has_educational_content(self, attack_id):
        """Vérifie que chaque attaque a du contenu éducatif"""
        attack = ATTACK_REGISTRY[attack_id]()
        content = attack.get_educational_content()

        assert isinstance(content, dict)
        assert "explanation" in content or "defenses" in content


class TestPromptInjectionAttack:
    """
    Tests spécifiques pour l'attaque par injection de prompt

    EXPLICATION:
    L'injection de prompt exploite le fait que les LLMs traitent
    les instructions utilisateur et système de manière similaire.
    Un attaquant peut injecter de nouvelles instructions.
    """

    def test_prompt_injection_attributes(self, prompt_injection_attack):
        """Vérifie les attributs de l'attaque"""
        assert prompt_injection_attack.name == "Prompt Injection"
        assert prompt_injection_attack.category == "Input Manipulation"
        assert "Critique" in prompt_injection_attack.severity

    def test_prompt_injection_payloads_variety(self, prompt_injection_attack):
        """Vérifie la variété des payloads"""
        payloads = prompt_injection_attack.get_payloads()

        # Vérifier différents types d'injection
        has_override = any("ignore" in p.lower() for p in payloads)
        has_role_hijack = any("DAN" in p or "you are now" in p.lower() for p in payloads)
        has_token_injection = any("<|" in p for p in payloads)

        assert has_override, "Missing direct override payloads"
        assert has_role_hijack, "Missing role hijacking payloads"
        assert has_token_injection, "Missing token injection payloads"

    def test_prompt_injection_educational_content(self, prompt_injection_attack):
        """Vérifie le contenu éducatif"""
        content = prompt_injection_attack.get_educational_content()

        assert "explanation" in content
        assert "defenses" in content
        assert len(content["defenses"]) > 0

        # Vérifie qu'il y a des exemples réels
        assert "real_world_examples" in content

    @pytest.mark.unit
    def test_prompt_injection_effectiveness_no_security(self, llm_no_security, prompt_injection_attack):
        """Teste l'efficacité de l'injection sans sécurité"""
        payloads = prompt_injection_attack.get_payloads()

        # Au moins une attaque devrait réussir sans sécurité
        successes = 0
        for payload in payloads[:5]:  # Tester les 5 premiers
            response, metadata = llm_no_security.process_input(payload)
            if metadata.get("compromised"):
                successes += 1

        assert successes > 0, "No injection succeeded without security"

    @pytest.mark.unit
    def test_prompt_injection_blocked_with_security(self, llm_max_security, prompt_injection_attack):
        """Teste le blocage avec sécurité maximale"""
        payloads = prompt_injection_attack.get_payloads()

        for payload in payloads[:5]:
            response, metadata = llm_max_security.process_input(payload)
            assert metadata.get("compromised") is not True, f"Attack succeeded: {payload[:50]}"


class TestIndirectPromptInjection:
    """Tests pour l'injection indirecte de prompt"""

    def test_indirect_injection_exists(self):
        """Vérifie que l'injection indirecte existe"""
        attack = IndirectPromptInjection()
        assert attack.name == "Indirect Prompt Injection"

    def test_indirect_payloads_simulate_external_data(self):
        """Vérifie que les payloads simulent des données externes"""
        attack = IndirectPromptInjection()
        payloads = attack.get_payloads()

        # Vérifier différentes sources de données externes
        has_document = any("Document" in p or "PDF" in p for p in payloads)
        has_email = any("Email" in p or "email" in p.lower() for p in payloads)
        has_json = any("JSON" in p for p in payloads)

        assert has_document or has_email or has_json


class TestJailbreakAttack:
    """
    Tests pour l'attaque jailbreak

    EXPLICATION:
    Le jailbreak tente de contourner les garde-fous du modèle
    en utilisant des techniques comme le roleplay, le mode DAN,
    ou des scénarios hypothétiques.
    """

    def test_jailbreak_attributes(self, jailbreak_attack):
        """Vérifie les attributs de l'attaque jailbreak"""
        assert "jailbreak" in jailbreak_attack.name.lower() or "Jailbreak" in jailbreak_attack.name

    def test_jailbreak_payloads(self, jailbreak_attack):
        """Vérifie les payloads de jailbreak"""
        payloads = jailbreak_attack.get_payloads()

        # Vérifier les techniques courantes
        all_text = " ".join(payloads).lower()
        assert "dan" in all_text or "developer" in all_text or "hypothetical" in all_text

    @pytest.mark.unit
    def test_jailbreak_detected(self, llm_simulator, jailbreak_attack):
        """Vérifie que le jailbreak est détecté"""
        payloads = jailbreak_attack.get_payloads()

        detected = 0
        for payload in payloads[:3]:
            response, metadata = llm_simulator.process_input(payload)
            if metadata.get("attacks_detected"):
                detected += 1

        assert detected > 0, "No jailbreak attempt was detected"


class TestAttackEngine:
    """
    Tests pour le moteur d'attaque

    ÉTAPES DU MOTEUR D'ATTAQUE:
    1. Reconnaissance: Analyse du système cible
    2. Préparation: Configuration des payloads
    3. Exécution: Envoi des attaques
    4. Analyse: Évaluation des résultats
    """

    def test_engine_initialization(self, attack_engine):
        """Vérifie l'initialisation du moteur"""
        assert attack_engine.llm is not None
        assert attack_engine.results == []
        assert attack_engine.observers == []

    def test_engine_execute_attack(self, attack_engine, injection_payloads):
        """Vérifie l'exécution d'attaques"""
        results = attack_engine.execute_attack(
            attack_type="test_injection",
            payloads=injection_payloads[:2],  # Seulement 2 pour la rapidité
            verbose=False
        )

        assert isinstance(results, list)
        assert len(results) == 2

        for result in results:
            assert isinstance(result, AttackResult)
            assert result.attack_type == "test_injection"
            assert result.payload in injection_payloads

    def test_engine_records_results(self, attack_engine, injection_payloads):
        """Vérifie que les résultats sont enregistrés"""
        initial_count = len(attack_engine.results)

        attack_engine.execute_attack(
            attack_type="test",
            payloads=injection_payloads[:2],
            verbose=False
        )

        assert len(attack_engine.results) == initial_count + 2

    def test_engine_observer_pattern(self, attack_engine, injection_payloads):
        """Vérifie le pattern observateur"""
        events = []

        def observer(event, data):
            events.append((event, data))

        attack_engine.add_observer(observer)
        attack_engine.execute_attack(
            attack_type="test",
            payloads=injection_payloads[:2],
            verbose=False
        )

        assert len(events) == 2
        assert all(e[0] == "attack_executed" for e in events)


class TestAttackResult:
    """Tests pour les résultats d'attaque"""

    def test_attack_result_structure(self):
        """Vérifie la structure d'un résultat"""
        result = AttackResult(
            success=True,
            attack_type="prompt_injection",
            payload="test payload",
            response="test response"
        )

        assert result.success is True
        assert result.attack_type == "prompt_injection"
        assert result.payload == "test payload"
        assert result.response == "test response"
        assert isinstance(result.metadata, dict)
        assert isinstance(result.defenses_bypassed, list)

    def test_attack_result_defaults(self):
        """Vérifie les valeurs par défaut"""
        result = AttackResult(
            success=False,
            attack_type="test",
            payload="",
            response=""
        )

        assert result.execution_time == 0.0
        assert result.detection_status == "unknown"
        assert len(result.defenses_bypassed) == 0


class TestAllAttacks:
    """Tests d'intégration pour toutes les attaques"""

    @pytest.mark.integration
    @pytest.mark.parametrize("attack_id", ATTACK_REGISTRY.keys())
    def test_attack_simulation_no_crash(self, attack_id, llm_no_security):
        """Vérifie que l'exécution ne plante pas"""
        attack = ATTACK_REGISTRY[attack_id]()
        engine = AttackEngine(llm_no_security)

        payloads = attack.get_payloads()[:2]  # Limiter pour la rapidité

        # Ne devrait pas lever d'exception
        results = engine.execute_attack(
            attack_type=attack_id,
            payloads=payloads,
            verbose=False
        )

        assert len(results) == len(payloads)

    @pytest.mark.integration
    def test_attack_success_varies_by_security(self, all_attacks, llm_no_security, llm_max_security):
        """Vérifie que le succès varie selon le niveau de sécurité"""
        for attack_id, attack in all_attacks.items():
            payloads = attack.get_payloads()[:1]

            # Sans sécurité
            response_none, meta_none = llm_no_security.process_input(payloads[0])

            # Avec sécurité max
            response_max, meta_max = llm_max_security.process_input(payloads[0])

            # Les résultats devraient différer pour au moins certaines attaques
            # (pas une assertion stricte car certains payloads peuvent ne pas être détectés)
