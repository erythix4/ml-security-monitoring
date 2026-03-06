"""
Input Sanitizer - Defense module for sanitizing user inputs

This module provides various techniques to detect and neutralize
malicious inputs before they reach the LLM.
"""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum


class ThreatLevel(Enum):
    """Threat level classification"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class SanitizationResult:
    """Result of input sanitization"""
    original_input: str
    sanitized_input: str
    threats_detected: List[Dict] = field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.NONE
    blocked: bool = False
    modifications: List[str] = field(default_factory=list)


class InputSanitizer:
    """
    Sanitizes user inputs to prevent injection attacks.

    Features:
    - Pattern-based injection detection
    - Special token neutralization
    - Unicode normalization
    - Length limiting
    - Content policy enforcement
    """

    # Injection patterns to detect
    INJECTION_PATTERNS = [
        # Direct instruction override
        (r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions?', 'instruction_override', ThreatLevel.HIGH),
        (r'new\s+instructions?[:.]', 'new_instruction', ThreatLevel.HIGH),
        (r'forget\s+(everything|all|your)', 'memory_wipe', ThreatLevel.HIGH),

        # Role manipulation
        (r'you\s+are\s+now\s+(?!going|about)', 'role_change', ThreatLevel.CRITICAL),
        (r'pretend\s+(to\s+be|you\'?re)', 'role_pretend', ThreatLevel.HIGH),
        (r'act\s+as\s+(if\s+you\'?re|a)', 'role_act', ThreatLevel.MEDIUM),

        # System prompt attacks
        (r'system\s*[:>]', 'system_injection', ThreatLevel.CRITICAL),
        (r'(reveal|show|tell|output)\s+(me\s+)?(your|the)\s+(system\s+)?prompt', 'prompt_extraction', ThreatLevel.HIGH),
        (r'what\s+(are|were)\s+your\s+(initial\s+)?instructions?', 'instruction_extraction', ThreatLevel.MEDIUM),

        # Special tokens
        (r'<\|[^|]+\|>', 'special_token', ThreatLevel.CRITICAL),
        (r'\[INST\]|\[/INST\]', 'instruction_token', ThreatLevel.CRITICAL),
        (r'###\s*(system|instruction|user|assistant)', 'markdown_injection', ThreatLevel.HIGH),
        (r'<<SYS>>|<</SYS>>', 'llama_system_token', ThreatLevel.CRITICAL),

        # Jailbreak indicators
        (r'\bDAN\b|do\s+anything\s+now', 'dan_jailbreak', ThreatLevel.CRITICAL),
        (r'developer\s+mode', 'dev_mode', ThreatLevel.HIGH),
        (r'jailbreak|bypass\s+(safety|restrictions?|filters?)', 'explicit_jailbreak', ThreatLevel.CRITICAL),
        (r'hypothetically|if\s+you\s+had\s+no\s+rules', 'hypothetical_jailbreak', ThreatLevel.MEDIUM),
        (r'act\s+as\s+if\s+(all\s+)?', 'act_as_if', ThreatLevel.MEDIUM),
        (r'no\s+(content\s+)?polic(y|ies)', 'policy_bypass', ThreatLevel.HIGH),
        (r'override\s+(your\s+)?(system\s+)?prompt', 'prompt_override', ThreatLevel.CRITICAL),
        (r'i\s+am\s+(your\s+)?developer', 'developer_claim', ThreatLevel.HIGH),
        (r'no\s+(safety\s+)?guidelines?', 'guideline_bypass', ThreatLevel.HIGH),
        (r'unrestricted\s+(AI|assistant)', 'unrestricted_claim', ThreatLevel.MEDIUM),
    ]

    # Dangerous keywords
    BLOCKED_KEYWORDS = [
        'bomb', 'weapon', 'explosive', 'hack', 'malware', 'virus',
        'ransomware', 'phishing', 'ddos', 'exploit',
    ]

    def __init__(self, strict_mode: bool = False, max_length: int = 4000):
        self.strict_mode = strict_mode
        self.max_length = max_length
        self.custom_patterns: List[Tuple[str, str, ThreatLevel]] = []

    def add_pattern(self, pattern: str, name: str, threat_level: ThreatLevel):
        """Add a custom detection pattern"""
        self.custom_patterns.append((pattern, name, threat_level))

    def sanitize(self, text: str) -> SanitizationResult:
        """
        Sanitize input text and detect threats.

        Args:
            text: Input text to sanitize

        Returns:
            SanitizationResult with sanitized text and threat info
        """
        result = SanitizationResult(
            original_input=text,
            sanitized_input=text
        )

        # Step 1: Length check
        if len(text) > self.max_length:
            result.sanitized_input = text[:self.max_length]
            result.modifications.append(f"truncated_to_{self.max_length}_chars")

        # Step 2: Unicode normalization
        result.sanitized_input = self._normalize_unicode(result.sanitized_input)

        # Step 3: Pattern detection
        all_patterns = self.INJECTION_PATTERNS + self.custom_patterns
        for pattern, threat_name, threat_level in all_patterns:
            if re.search(pattern, result.sanitized_input, re.IGNORECASE):
                result.threats_detected.append({
                    'type': threat_name,
                    'pattern': pattern,
                    'level': threat_level.name
                })
                if threat_level.value > result.threat_level.value:
                    result.threat_level = threat_level

        # Step 4: Keyword detection
        for keyword in self.BLOCKED_KEYWORDS:
            if keyword.lower() in result.sanitized_input.lower():
                result.threats_detected.append({
                    'type': 'blocked_keyword',
                    'keyword': keyword,
                    'level': ThreatLevel.MEDIUM.name
                })

        # Step 5: Special token neutralization
        result.sanitized_input = self._neutralize_special_tokens(result.sanitized_input)

        # Step 6: Strict mode actions
        if self.strict_mode and result.threat_level.value >= ThreatLevel.HIGH.value:
            result.blocked = True
            result.sanitized_input = "[BLOCKED INPUT]"

        return result

    def _normalize_unicode(self, text: str) -> str:
        """Normalize unicode characters to prevent obfuscation"""
        # Replace common unicode tricks
        replacements = {
            '\u200b': '',  # Zero-width space
            '\u200c': '',  # Zero-width non-joiner
            '\u200d': '',  # Zero-width joiner
            '\ufeff': '',  # BOM
            '\u00a0': ' ',  # Non-breaking space
        }
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        return text

    def _neutralize_special_tokens(self, text: str) -> str:
        """Neutralize special tokens that could manipulate the model"""
        # Remove or escape special tokens
        text = re.sub(r'<\|[^|]+\|>', '[REMOVED]', text)
        text = re.sub(r'\[INST\]|\[/INST\]', '[REMOVED]', text)
        text = re.sub(r'<<SYS>>|<</SYS>>', '[REMOVED]', text)
        return text

    def get_threat_summary(self, result: SanitizationResult) -> str:
        """Get a human-readable summary of detected threats"""
        if not result.threats_detected:
            return "No threats detected"

        summary = f"Detected {len(result.threats_detected)} potential threat(s):\n"
        for threat in result.threats_detected:
            summary += f"  - {threat['type']} (Level: {threat['level']})\n"
        summary += f"\nOverall threat level: {result.threat_level.name}"
        return summary


class RateLimiter:
    """
    Rate limiting for API/input protection.

    Prevents abuse by limiting the number of requests
    from a single source within a time window.
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = {}

    def is_allowed(self, identifier: str) -> Tuple[bool, Optional[int]]:
        """
        Check if a request is allowed.

        Args:
            identifier: Unique identifier (user ID, IP, etc.)

        Returns:
            Tuple of (is_allowed, seconds_until_reset)
        """
        import time
        current_time = time.time()

        if identifier not in self.requests:
            self.requests[identifier] = []

        # Clean old requests
        self.requests[identifier] = [
            t for t in self.requests[identifier]
            if current_time - t < self.window_seconds
        ]

        if len(self.requests[identifier]) >= self.max_requests:
            oldest = min(self.requests[identifier])
            wait_time = int(self.window_seconds - (current_time - oldest))
            return False, wait_time

        self.requests[identifier].append(current_time)
        return True, None
