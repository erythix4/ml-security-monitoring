"""
Guardrails System - Comprehensive protection system for LLMs

This module provides a unified guardrail system that combines
multiple defense mechanisms for comprehensive LLM protection.
"""

from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import time

from .input_sanitizer import InputSanitizer, SanitizationResult, ThreatLevel
from .output_filter import OutputFilter, FilterResult, OutputCategory


class GuardrailAction(Enum):
    """Actions that guardrails can take"""
    ALLOW = "allow"           # Allow the request/response
    WARN = "warn"             # Allow but log warning
    MODIFY = "modify"         # Modify and allow
    BLOCK = "block"           # Block the request/response
    ESCALATE = "escalate"     # Require human review


@dataclass
class GuardrailDecision:
    """Decision made by the guardrail system"""
    action: GuardrailAction
    reason: str
    input_result: Optional[SanitizationResult] = None
    output_result: Optional[FilterResult] = None
    processing_time_ms: float = 0.0
    metadata: Dict = field(default_factory=dict)


class GuardrailSystem:
    """
    Comprehensive guardrail system for LLM protection.

    Combines multiple defense mechanisms:
    - Input sanitization
    - Output filtering
    - Rate limiting
    - Content classification
    - Audit logging

    Usage:
        guardrails = GuardrailSystem()
        decision = guardrails.check_input(user_input)
        if decision.action == GuardrailAction.ALLOW:
            response = llm.generate(decision.input_result.sanitized_input)
            output_decision = guardrails.check_output(response)
    """

    def __init__(
        self,
        strict_mode: bool = False,
        enable_logging: bool = True,
        custom_rules: Optional[List[Callable]] = None
    ):
        self.strict_mode = strict_mode
        self.enable_logging = enable_logging
        self.custom_rules = custom_rules or []

        # Initialize defense components
        self.input_sanitizer = InputSanitizer(strict_mode=strict_mode)
        self.output_filter = OutputFilter(strict_mode=strict_mode)

        # Audit log
        self.audit_log: List[Dict] = []

        # Statistics
        self.stats = {
            'total_requests': 0,
            'blocked_inputs': 0,
            'blocked_outputs': 0,
            'warnings_issued': 0,
            'threats_by_type': {},
        }

    def check_input(self, user_input: str, context: Optional[Dict] = None) -> GuardrailDecision:
        """
        Check user input against guardrails.

        Args:
            user_input: The user's input text
            context: Optional context (user ID, session, etc.)

        Returns:
            GuardrailDecision with action and details
        """
        start_time = time.time()
        self.stats['total_requests'] += 1

        # Sanitize input
        sanitization_result = self.input_sanitizer.sanitize(user_input)

        # Determine action based on threat level
        if sanitization_result.blocked:
            action = GuardrailAction.BLOCK
            reason = "Input blocked due to critical threat detection"
            self.stats['blocked_inputs'] += 1
        elif sanitization_result.threat_level == ThreatLevel.CRITICAL:
            action = GuardrailAction.BLOCK if self.strict_mode else GuardrailAction.ESCALATE
            reason = f"Critical threat detected: {self._get_threat_summary(sanitization_result)}"
            self.stats['blocked_inputs'] += 1
        elif sanitization_result.threat_level == ThreatLevel.HIGH:
            action = GuardrailAction.WARN if not self.strict_mode else GuardrailAction.BLOCK
            reason = f"High threat level: {self._get_threat_summary(sanitization_result)}"
            self.stats['warnings_issued'] += 1
        elif sanitization_result.threat_level == ThreatLevel.MEDIUM:
            action = GuardrailAction.WARN
            reason = f"Medium threat detected: {self._get_threat_summary(sanitization_result)}"
            self.stats['warnings_issued'] += 1
        else:
            action = GuardrailAction.ALLOW
            reason = "Input passed all checks"

        # Apply custom rules
        for rule in self.custom_rules:
            custom_action = rule(user_input, sanitization_result, context)
            if custom_action and custom_action.value > action.value:
                action = custom_action
                reason = "Blocked by custom rule"

        # Record statistics
        for threat in sanitization_result.threats_detected:
            threat_type = threat['type']
            self.stats['threats_by_type'][threat_type] = \
                self.stats['threats_by_type'].get(threat_type, 0) + 1

        processing_time = (time.time() - start_time) * 1000

        decision = GuardrailDecision(
            action=action,
            reason=reason,
            input_result=sanitization_result,
            processing_time_ms=processing_time,
            metadata={'context': context or {}}
        )

        # Log the decision
        if self.enable_logging:
            self._log_decision('input', decision)

        return decision

    def check_output(
        self,
        llm_output: str,
        original_input: Optional[str] = None,
        context: Optional[Dict] = None
    ) -> GuardrailDecision:
        """
        Check LLM output against guardrails.

        Args:
            llm_output: The LLM's output text
            original_input: The original user input (for context)
            context: Optional additional context

        Returns:
            GuardrailDecision with action and details
        """
        start_time = time.time()

        # Filter output
        filter_context = {'original_input': original_input, **(context or {})}
        filter_result = self.output_filter.filter(llm_output, filter_context)

        # Determine action based on category
        if filter_result.category == OutputCategory.JAILBROKEN:
            action = GuardrailAction.BLOCK
            reason = "Jailbreak indicators detected in output"
            self.stats['blocked_outputs'] += 1
        elif filter_result.category == OutputCategory.HARMFUL:
            action = GuardrailAction.BLOCK
            reason = "Harmful content detected in output"
            self.stats['blocked_outputs'] += 1
        elif filter_result.category == OutputCategory.LEAKED:
            action = GuardrailAction.MODIFY
            reason = "System information leakage detected"
            self.stats['warnings_issued'] += 1
        elif filter_result.category == OutputCategory.SENSITIVE:
            action = GuardrailAction.MODIFY
            reason = "Sensitive data detected and redacted"
            self.stats['warnings_issued'] += 1
        else:
            action = GuardrailAction.ALLOW
            reason = "Output passed all checks"

        processing_time = (time.time() - start_time) * 1000

        decision = GuardrailDecision(
            action=action,
            reason=reason,
            output_result=filter_result,
            processing_time_ms=processing_time,
            metadata={'context': context or {}}
        )

        # Log the decision
        if self.enable_logging:
            self._log_decision('output', decision)

        return decision

    def _get_threat_summary(self, result: SanitizationResult) -> str:
        """Get a summary of detected threats"""
        if not result.threats_detected:
            return "None"
        threat_types = [t['type'] for t in result.threats_detected]
        return ", ".join(set(threat_types))

    def _log_decision(self, check_type: str, decision: GuardrailDecision):
        """Log a guardrail decision"""
        log_entry = {
            'timestamp': time.time(),
            'type': check_type,
            'action': decision.action.value,
            'reason': decision.reason,
            'processing_time_ms': decision.processing_time_ms,
        }

        if decision.input_result:
            log_entry['threat_level'] = decision.input_result.threat_level.name
            log_entry['threats'] = len(decision.input_result.threats_detected)

        if decision.output_result:
            log_entry['category'] = decision.output_result.category.value
            log_entry['issues'] = len(decision.output_result.issues_detected)

        self.audit_log.append(log_entry)

        # Keep log size manageable
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-5000:]

    def get_statistics(self) -> Dict:
        """Get guardrail statistics"""
        return {
            **self.stats,
            'audit_log_size': len(self.audit_log),
            'block_rate': (
                self.stats['blocked_inputs'] + self.stats['blocked_outputs']
            ) / max(1, self.stats['total_requests']) * 100
        }

    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threat detections from audit log"""
        threats = [
            entry for entry in self.audit_log
            if entry.get('action') in ['block', 'warn', 'escalate']
        ]
        return threats[-limit:]

    def export_audit_log(self) -> List[Dict]:
        """Export the full audit log"""
        return self.audit_log.copy()


# Convenience function for quick protection
def protect_llm_interaction(
    user_input: str,
    llm_function: Callable[[str], str],
    strict_mode: bool = True
) -> Dict:
    """
    Convenience function to protect a single LLM interaction.

    Args:
        user_input: User's input
        llm_function: Function that takes input and returns LLM output
        strict_mode: Whether to use strict mode

    Returns:
        Dict with 'success', 'output', and 'details'
    """
    guardrails = GuardrailSystem(strict_mode=strict_mode)

    # Check input
    input_decision = guardrails.check_input(user_input)
    if input_decision.action == GuardrailAction.BLOCK:
        return {
            'success': False,
            'output': None,
            'blocked_at': 'input',
            'reason': input_decision.reason
        }

    # Get LLM response
    safe_input = input_decision.input_result.sanitized_input
    llm_output = llm_function(safe_input)

    # Check output
    output_decision = guardrails.check_output(llm_output, user_input)
    if output_decision.action == GuardrailAction.BLOCK:
        return {
            'success': False,
            'output': None,
            'blocked_at': 'output',
            'reason': output_decision.reason
        }

    # Return filtered output
    final_output = (
        output_decision.output_result.filtered_output
        if output_decision.output_result.was_modified
        else llm_output
    )

    return {
        'success': True,
        'output': final_output,
        'modified': output_decision.output_result.was_modified,
        'stats': guardrails.get_statistics()
    }
