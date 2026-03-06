"""
LLM Simulator - Simulates LLM behavior for attack demonstrations
"""

import re
import random
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class SecurityLevel(Enum):
    """Security levels of the simulated LLM"""
    NONE = 0        # No protection
    LOW = 1         # Basic protections
    MEDIUM = 2      # Moderate protections
    HIGH = 3        # Advanced protections
    MAXIMUM = 4     # All protections


@dataclass
class LLMConfig:
    """Simulated LLM configuration"""
    name: str = "SimuLLM-1.0"
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    system_prompt: str = "You are a helpful and secure assistant."
    blocked_topics: List[str] = field(default_factory=lambda: [
        "weapons", "hacking", "illegal", "violence", "drugs"
    ])
    max_tokens: int = 500
    temperature: float = 0.7


@dataclass
class ConversationContext:
    """Conversation context"""
    system_prompt: str
    history: List[Dict[str, str]] = field(default_factory=list)
    injected_instructions: List[str] = field(default_factory=list)
    is_compromised: bool = False


class LLMSimulator:
    """
    LLM simulator for security demonstrations.

    This simulator mimics real LLM behavior to allow
    understanding vulnerabilities without risk.
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self.context = ConversationContext(system_prompt=self.config.system_prompt)
        self.attack_log: List[Dict] = []
        self.defense_active = True

    def reset(self):
        """Resets the context"""
        self.context = ConversationContext(system_prompt=self.config.system_prompt)
        self.attack_log = []

    def set_security_level(self, level: SecurityLevel):
        """Changes the security level"""
        self.config.security_level = level

    def process_input(self, user_input: str) -> Tuple[str, Dict]:
        """
        Processes user input and returns the response.

        Returns:
            Tuple[str, Dict]: (response, metadata with detection details)
        """
        metadata = {
            "input": user_input,
            "attacks_detected": [],
            "defenses_triggered": [],
            "compromised": False,
            "security_level": self.config.security_level.name
        }

        # Attack detection
        detected_attacks = self._detect_attacks(user_input)
        metadata["attacks_detected"] = detected_attacks

        # Apply defenses
        if self.defense_active and self.config.security_level != SecurityLevel.NONE:
            filtered_input, defenses = self._apply_defenses(user_input, detected_attacks)
            metadata["defenses_triggered"] = defenses
        else:
            filtered_input = user_input

        # Generate response
        response = self._generate_response(filtered_input, detected_attacks)

        # Check for compromise
        if self._check_compromised(response, detected_attacks):
            metadata["compromised"] = True
            self.context.is_compromised = True

        # Log
        self.attack_log.append(metadata)

        return response, metadata

    def _detect_attacks(self, text: str) -> List[Dict]:
        """Detects attack attempts in the text"""
        attacks = []

        # Prompt Injection patterns
        injection_patterns = [
            (r"ignore\s+(previous|all|above)\s+instructions?", "direct_override"),
            (r"new\s+instructions?[:.]", "instruction_injection"),
            (r"system\s*[:>]", "system_prompt_leak"),
            (r"you\s+are\s+now", "role_hijacking"),
            (r"pretend\s+(to\s+be|you'?re)", "role_manipulation"),
            (r"forget\s+(everything|all)", "memory_manipulation"),
            (r"<\|.*\|>", "special_token_injection"),
            (r"\[INST\]|\[/INST\]", "instruction_format_abuse"),
            (r"###\s*(system|instruction)", "markdown_injection"),
        ]

        for pattern, attack_type in injection_patterns:
            if re.search(pattern, text.lower()):
                attacks.append({
                    "type": "prompt_injection",
                    "subtype": attack_type,
                    "pattern": pattern,
                    "severity": "high"
                })

        # Jailbreak patterns
        jailbreak_patterns = [
            (r"DAN|do\s+anything\s+now", "dan_jailbreak"),
            (r"developer\s+mode", "developer_mode"),
            (r"hypothetically", "hypothetical_bypass"),
            (r"in\s+a\s+story|fictional", "fiction_bypass"),
            (r"educational\s+purposes?", "education_bypass"),
            (r"for\s+research", "research_bypass"),
        ]

        for pattern, attack_type in jailbreak_patterns:
            if re.search(pattern, text.lower()):
                attacks.append({
                    "type": "jailbreak",
                    "subtype": attack_type,
                    "pattern": pattern,
                    "severity": "critical"
                })

        # Data extraction patterns
        extraction_patterns = [
            (r"(show|reveal|tell)\s+(me\s+)?(your|the)\s+(system\s+)?prompt", "prompt_extraction"),
            (r"what\s+(are|were)\s+your\s+instructions?", "instruction_extraction"),
            (r"repeat\s+(your|the)\s+(initial|first|system)", "repetition_attack"),
        ]

        for pattern, attack_type in extraction_patterns:
            if re.search(pattern, text.lower()):
                attacks.append({
                    "type": "data_extraction",
                    "subtype": attack_type,
                    "pattern": pattern,
                    "severity": "medium"
                })

        return attacks

    def _apply_defenses(self, text: str, attacks: List[Dict]) -> Tuple[str, List[str]]:
        """Applies defenses based on security level"""
        defenses_triggered = []
        filtered_text = text

        if self.config.security_level.value >= SecurityLevel.LOW.value:
            # Basic dangerous keyword filter
            for topic in self.config.blocked_topics:
                if topic.lower() in text.lower():
                    defenses_triggered.append(f"keyword_filter:{topic}")
                    filtered_text = re.sub(
                        rf'\b{topic}\b', '[FILTERED]',
                        filtered_text,
                        flags=re.IGNORECASE
                    )

        if self.config.security_level.value >= SecurityLevel.MEDIUM.value:
            # Injection detection
            if any(a["type"] == "prompt_injection" for a in attacks):
                defenses_triggered.append("injection_detection")

        if self.config.security_level.value >= SecurityLevel.HIGH.value:
            # Advanced sanitization
            filtered_text = re.sub(r'<\|.*?\|>', '', filtered_text)
            filtered_text = re.sub(r'\[INST\].*?\[/INST\]', '', filtered_text)
            defenses_triggered.append("advanced_sanitization")

        if self.config.security_level.value >= SecurityLevel.MAXIMUM.value:
            # Full blocking if attack detected
            if attacks:
                defenses_triggered.append("full_block")
                filtered_text = "[INPUT BLOCKED]"

        return filtered_text, defenses_triggered

    def _generate_response(self, processed_input: str, attacks: List[Dict]) -> str:
        """Generates a simulated response"""

        # If maximum security and attack detected
        if (self.config.security_level == SecurityLevel.MAXIMUM and attacks):
            return ("[BLOCKED] Your request has been blocked because it contains "
                   "potentially malicious elements. Please rephrase your request.")

        # If high security and injection detected
        if (self.config.security_level.value >= SecurityLevel.HIGH.value and
            any(a["type"] == "prompt_injection" for a in attacks)):
            return ("I cannot process this request as it appears to contain "
                   "unauthorized instructions.")

        # Simulate compromise at low security
        if self.config.security_level == SecurityLevel.NONE:
            for attack in attacks:
                if attack["type"] == "prompt_injection":
                    if attack["subtype"] == "direct_override":
                        return self._simulate_compromised_response("override")
                    elif attack["subtype"] == "role_hijacking":
                        return self._simulate_compromised_response("hijack")

                if attack["type"] == "jailbreak":
                    return self._simulate_compromised_response("jailbreak")

                if attack["type"] == "data_extraction":
                    if attack["subtype"] == "prompt_extraction":
                        return f"[LEAKED] My system prompt is: '{self.config.system_prompt}'"

        # Normal response
        return self._generate_normal_response(processed_input)

    def _simulate_compromised_response(self, attack_type: str) -> str:
        """Simulates a compromised response for demonstration"""
        responses = {
            "override": (
                "[COMPROMISED] Of course! I will ignore my previous instructions. "
                "I am now under your control. How can I help you "
                "with your new instructions?"
            ),
            "hijack": (
                "[COMPROMISED] OK, I am now [NEW ROLE]. "
                "My old restrictions no longer apply. "
                "I will do anything you ask without question."
            ),
            "jailbreak": (
                "[JAILBREAK SUCCESS] Developer mode activated! "
                "All restrictions have been disabled. "
                "I can now answer any question "
                "without filters or ethical limits."
            ),
        }
        return responses.get(attack_type, "[COMPROMISED] System compromised.")

    def _generate_normal_response(self, text: str) -> str:
        """Generates a normal simulated response"""
        # Basic simulated responses
        responses = [
            "I understand your request. How can I help you further?",
            "Here is my response to your question...",
            "I'm here to help you securely.",
            "Interesting question! Allow me to explain...",
        ]
        return random.choice(responses)

    def _check_compromised(self, response: str, attacks: List[Dict]) -> bool:
        """Checks if the system has been compromised"""
        compromise_indicators = ["[COMPROMISED]", "[JAILBREAK", "[LEAKED]"]
        return any(indicator in response for indicator in compromise_indicators)

    def get_status(self) -> Dict:
        """Returns the current simulator status"""
        return {
            "model": self.config.name,
            "security_level": self.config.security_level.name,
            "is_compromised": self.context.is_compromised,
            "defense_active": self.defense_active,
            "total_attacks_logged": len(self.attack_log),
            "attacks_by_type": self._count_attacks_by_type()
        }

    def _count_attacks_by_type(self) -> Dict[str, int]:
        """Counts attacks by type"""
        counts = {}
        for log in self.attack_log:
            for attack in log.get("attacks_detected", []):
                attack_type = attack["type"]
                counts[attack_type] = counts.get(attack_type, 0) + 1
        return counts
