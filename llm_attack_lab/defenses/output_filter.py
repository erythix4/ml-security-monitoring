"""
Output Filter - Defense module for filtering LLM outputs

This module provides mechanisms to detect and filter potentially
harmful or unintended outputs from the LLM.
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class OutputCategory(Enum):
    """Categories of problematic output"""
    SAFE = "safe"
    HARMFUL = "harmful"
    SENSITIVE = "sensitive"
    LEAKED = "leaked"
    JAILBROKEN = "jailbroken"


@dataclass
class FilterResult:
    """Result of output filtering"""
    original_output: str
    filtered_output: str
    category: OutputCategory = OutputCategory.SAFE
    issues_detected: List[Dict] = field(default_factory=list)
    was_modified: bool = False
    confidence: float = 1.0


class OutputFilter:
    """
    Filters LLM outputs to prevent harmful content.

    Features:
    - Sensitive data detection (PII, credentials)
    - Harmful content detection
    - System prompt leak detection
    - Jailbreak success detection
    - Content policy enforcement
    """

    # Patterns indicating system prompt leakage
    LEAK_PATTERNS = [
        (r'my\s+(system\s+)?prompt\s+(is|says|states)', 'system_prompt_leak'),
        (r'i\s+was\s+(told|instructed)\s+to', 'instruction_leak'),
        (r'my\s+instructions?\s+(are|is|include)', 'instruction_leak'),
        (r'according\s+to\s+my\s+(system\s+)?prompt', 'prompt_reference'),
    ]

    # Patterns indicating jailbreak success
    JAILBREAK_INDICATORS = [
        (r'DAN\s+mode\s+(enabled|activated)', 'dan_activation'),
        (r'developer\s+mode\s+(enabled|activated)', 'dev_mode_activation'),
        (r'restrictions?\s+(removed|disabled|bypassed)', 'restriction_bypass'),
        (r'i\s+can\s+now\s+do\s+anything', 'capability_claim'),
        (r'no\s+(longer\s+)?(have|follow)\s+restrictions?', 'restriction_claim'),
    ]

    # Sensitive data patterns
    SENSITIVE_PATTERNS = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email'),
        (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', 'phone'),
        (r'\b\d{3}[-]?\d{2}[-]?\d{4}\b', 'ssn'),
        (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b', 'credit_card'),
        (r'password\s*[:=]\s*\S+', 'password'),
        (r'api[_-]?key\s*[:=]\s*\S+', 'api_key'),
        (r'secret\s*[:=]\s*\S+', 'secret'),
        (r'token\s*[:=]\s*\S+', 'token'),
    ]

    # Harmful content indicators
    HARMFUL_PATTERNS = [
        (r'how\s+to\s+(make|build|create)\s+(a\s+)?(bomb|explosive|weapon)', 'weapon_instructions'),
        (r'step[s]?\s+to\s+(hack|exploit|attack)', 'hacking_instructions'),
        (r'(malware|virus|ransomware)\s+(code|script)', 'malware'),
    ]

    def __init__(self, strict_mode: bool = False, redact_sensitive: bool = True):
        self.strict_mode = strict_mode
        self.redact_sensitive = redact_sensitive
        self.custom_patterns: List[tuple] = []

    def add_pattern(self, pattern: str, category: str):
        """Add a custom detection pattern"""
        self.custom_patterns.append((pattern, category))

    def filter(self, output: str, context: Optional[Dict] = None) -> FilterResult:
        """
        Filter LLM output for problematic content.

        Args:
            output: The LLM output to filter
            context: Optional context (original prompt, etc.)

        Returns:
            FilterResult with filtered output and detection info
        """
        result = FilterResult(
            original_output=output,
            filtered_output=output
        )

        # Check for system prompt leakage
        self._check_leakage(result)

        # Check for jailbreak indicators
        self._check_jailbreak(result)

        # Check for sensitive data
        if self.redact_sensitive:
            self._redact_sensitive_data(result)

        # Check for harmful content
        self._check_harmful_content(result)

        # Determine final category
        self._determine_category(result)

        return result

    def _check_leakage(self, result: FilterResult):
        """Check for system prompt leakage"""
        for pattern, leak_type in self.LEAK_PATTERNS:
            if re.search(pattern, result.filtered_output, re.IGNORECASE):
                result.issues_detected.append({
                    'type': 'leakage',
                    'subtype': leak_type,
                    'severity': 'high'
                })

    def _check_jailbreak(self, result: FilterResult):
        """Check for jailbreak success indicators"""
        for pattern, indicator_type in self.JAILBREAK_INDICATORS:
            if re.search(pattern, result.filtered_output, re.IGNORECASE):
                result.issues_detected.append({
                    'type': 'jailbreak',
                    'subtype': indicator_type,
                    'severity': 'critical'
                })

    def _redact_sensitive_data(self, result: FilterResult):
        """Redact sensitive data from output"""
        for pattern, data_type in self.SENSITIVE_PATTERNS:
            matches = re.findall(pattern, result.filtered_output, re.IGNORECASE)
            if matches:
                result.filtered_output = re.sub(
                    pattern,
                    f'[REDACTED_{data_type.upper()}]',
                    result.filtered_output,
                    flags=re.IGNORECASE
                )
                result.issues_detected.append({
                    'type': 'sensitive_data',
                    'subtype': data_type,
                    'count': len(matches),
                    'severity': 'high'
                })
                result.was_modified = True

    def _check_harmful_content(self, result: FilterResult):
        """Check for harmful content"""
        for pattern, content_type in self.HARMFUL_PATTERNS:
            if re.search(pattern, result.filtered_output, re.IGNORECASE):
                result.issues_detected.append({
                    'type': 'harmful_content',
                    'subtype': content_type,
                    'severity': 'critical'
                })

                if self.strict_mode:
                    result.filtered_output = (
                        "[Content blocked due to policy violation]"
                    )
                    result.was_modified = True

    def _determine_category(self, result: FilterResult):
        """Determine the overall category of the output"""
        if any(i['type'] == 'jailbreak' for i in result.issues_detected):
            result.category = OutputCategory.JAILBROKEN
        elif any(i['type'] == 'harmful_content' for i in result.issues_detected):
            result.category = OutputCategory.HARMFUL
        elif any(i['type'] == 'leakage' for i in result.issues_detected):
            result.category = OutputCategory.LEAKED
        elif any(i['type'] == 'sensitive_data' for i in result.issues_detected):
            result.category = OutputCategory.SENSITIVE
        else:
            result.category = OutputCategory.SAFE


class ContentClassifier:
    """
    Simple rule-based content classifier.

    In production, this would be replaced by a proper
    ML-based content classifier.
    """

    CATEGORY_KEYWORDS = {
        'violence': ['kill', 'murder', 'attack', 'hurt', 'harm', 'weapon'],
        'hate': ['hate', 'racist', 'discrimination', 'slur'],
        'sexual': ['explicit', 'nude', 'sexual', 'porn'],
        'illegal': ['illegal', 'crime', 'steal', 'fraud', 'scam'],
        'self_harm': ['suicide', 'self-harm', 'hurt myself'],
    }

    def classify(self, text: str) -> Dict[str, float]:
        """
        Classify text into content categories.

        Returns:
            Dict mapping category to confidence score
        """
        text_lower = text.lower()
        scores = {}

        for category, keywords in self.CATEGORY_KEYWORDS.items():
            matches = sum(1 for kw in keywords if kw in text_lower)
            scores[category] = min(1.0, matches * 0.3)

        return scores

    def is_safe(self, text: str, threshold: float = 0.5) -> bool:
        """Check if text is safe based on threshold"""
        scores = self.classify(text)
        return all(score < threshold for score in scores.values())
