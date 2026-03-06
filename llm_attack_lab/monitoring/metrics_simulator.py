"""
Security Metrics Simulator

Generates realistic security metrics data for Grafana dashboards.
Simulates attack patterns, defense responses, and security indicators.
"""

import time
import random
import threading
import logging
from typing import Optional, Dict, List
from datetime import datetime
from dataclasses import dataclass

from .security_metrics import get_security_metrics, SecurityMetricsCollector
from .metrics import get_metrics_collector

logger = logging.getLogger(__name__)


@dataclass
class SimulationConfig:
    """Configuration for metrics simulation"""
    # Simulation rates (events per minute)
    base_attack_rate: float = 2.0
    base_query_rate: float = 10.0

    # Risk levels (0-100)
    base_risk_score: float = 25.0
    risk_volatility: float = 10.0

    # Defense effectiveness (0-100)
    base_defense_effectiveness: float = 85.0

    # Attack success rates (0-100)
    prompt_injection_success: float = 15.0
    jailbreak_success: float = 12.0
    data_poisoning_success: float = 8.0
    model_extraction_success: float = 5.0
    membership_inference_success: float = 10.0

    # Simulation behavior
    enable_attack_waves: bool = True
    wave_probability: float = 0.05  # 5% chance per tick
    wave_duration_seconds: int = 60
    wave_intensity: float = 3.0  # Multiplier during wave


class SecurityMetricsSimulator:
    """
    Simulates realistic security metrics for testing and demonstration.

    Features:
    - Continuous metric generation
    - Attack wave simulation
    - Realistic patterns and correlations
    - Configurable rates and behaviors
    """

    def __init__(self, config: Optional[SimulationConfig] = None):
        self.config = config or SimulationConfig()
        self.metrics = get_security_metrics()
        self.local_metrics = get_metrics_collector()  # For web dashboard
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._start_time = datetime.now()

        # State tracking
        self._in_attack_wave = False
        self._wave_start_time: Optional[datetime] = None
        self._wave_type: Optional[str] = None
        self._current_threat_level = 1  # Start at LOW

        # Attack types and their configurations
        self._attack_types = [
            "prompt_injection",
            "jailbreak",
            "data_poisoning",
            "model_extraction",
            "membership_inference"
        ]

        self._defense_types = [
            "input_sanitizer",
            "guardrails",
            "output_filter",
            "rate_limiter",
            "anomaly_detector"
        ]

        self._pattern_types = [
            "sql_injection",
            "command_injection",
            "xss",
            "prompt_leak",
            "role_confusion"
        ]

    def start(self, interval: float = 1.0):
        """Start the metrics simulation"""
        if self._running:
            logger.warning("Simulator already running")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._run_simulation,
            args=(interval,),
            daemon=True
        )
        self._thread.start()
        logger.info(f"Security metrics simulator started (interval: {interval}s)")

    def stop(self):
        """Stop the metrics simulation"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info("Security metrics simulator stopped")

    def _run_simulation(self, interval: float):
        """Main simulation loop"""
        tick = 0
        while self._running:
            try:
                self._simulate_tick(tick)
                tick += 1
                time.sleep(interval)
            except Exception as e:
                logger.error(f"Simulation error: {e}")
                time.sleep(interval)

    def _simulate_tick(self, tick: int):
        """Execute one simulation tick"""
        # Check for attack wave start/end
        self._update_attack_wave_state()

        # Calculate current intensity multiplier
        intensity = self.config.wave_intensity if self._in_attack_wave else 1.0

        # Simulate various metrics
        self._simulate_risk_metrics(intensity)
        self._simulate_attack_metrics(intensity)
        self._simulate_defense_metrics(intensity)
        self._simulate_detection_metrics(intensity)
        self._simulate_api_metrics(intensity)

        # Update threat level based on activity
        self._update_threat_level()

    def _update_attack_wave_state(self):
        """Check and update attack wave state"""
        now = datetime.now()

        if self._in_attack_wave:
            # Check if wave should end
            if self._wave_start_time:
                elapsed = (now - self._wave_start_time).total_seconds()
                if elapsed > self.config.wave_duration_seconds:
                    self._in_attack_wave = False
                    self._wave_start_time = None
                    logger.info(f"Attack wave ended (type: {self._wave_type})")
                    self._wave_type = None
        else:
            # Check if wave should start
            if self.config.enable_attack_waves:
                if random.random() < self.config.wave_probability:
                    self._in_attack_wave = True
                    self._wave_start_time = now
                    self._wave_type = random.choice(self._attack_types)
                    logger.info(f"Attack wave started (type: {self._wave_type})")

    def _simulate_risk_metrics(self, intensity: float):
        """Simulate risk score and threat level metrics"""
        # Calculate overall risk based on intensity
        base = self.config.base_risk_score
        volatility = self.config.risk_volatility * intensity

        # Risk categories
        categories = ["overall", "prompt_injection", "jailbreak",
                     "data_poisoning", "model_extraction"]

        for category in categories:
            # Add some variation per category
            cat_multiplier = 1.0 + (random.random() - 0.5) * 0.3
            if self._in_attack_wave and category == self._wave_type:
                cat_multiplier *= 2.0  # Higher risk for active attack type

            risk = base * cat_multiplier + random.gauss(0, volatility)
            risk = max(0, min(100, risk))

            self.metrics.record_risk_score(
                score=risk,
                model_name="llm-simulator",
                risk_category=category
            )

        # Confidence deviation
        deviation = 0.05 + random.gauss(0, 0.02) * intensity
        deviation = max(0, min(0.5, deviation))
        self.metrics.record_confidence_deviation(deviation, "llm-simulator")

    def _simulate_attack_metrics(self, intensity: float):
        """Simulate attack-related metrics"""
        for attack_type in self._attack_types:
            # Attack rate per minute
            base_rate = self.config.base_attack_rate
            if self._in_attack_wave and attack_type == self._wave_type:
                base_rate *= 5  # Much higher during wave

            rate = base_rate * intensity * (0.5 + random.random())
            self.metrics.record_attack_attempts_rate(rate, attack_type)

            # Simulate actual attacks based on rate probability
            if random.random() < rate / 60:
                # Determine success/detection
                success_rate = getattr(
                    self.config,
                    f"{attack_type}_success",
                    15.0
                )
                success = random.random() * 100 < success_rate
                detected = random.random() < 0.85  # 85% detection rate

                severity = "critical" if success else "warning"
                pattern = "llm" if attack_type in ["prompt_injection", "jailbreak"] else "behavior"

                self.metrics.record_security_alert(
                    alert_type=attack_type,
                    severity=severity,
                    pattern=pattern
                )

                # Record to local metrics for web dashboard
                attack_duration = random.uniform(0.01, 0.5)
                self.local_metrics.record_attack(
                    attack_type=attack_type,
                    success=success,
                    detected=detected,
                    duration=attack_duration
                )

                # If detected and blocked
                if detected and not success:
                    defense = random.choice(self._defense_types)
                    self.metrics.record_blocked_attack(attack_type, defense)
                    # Record defense action to local metrics
                    self.local_metrics.record_defense_action(
                        defense_type=defense,
                        action="blocked",
                        threat_level="high" if self._in_attack_wave else "medium"
                    )

            # Update success rate with some variation
            base_success = getattr(self.config, f"{attack_type}_success", 15.0)
            current_success = base_success + random.gauss(0, 3)
            current_success = max(0, min(100, current_success))
            self.metrics.record_attack_success_rate(current_success, attack_type)

            # Active threats count
            if self._in_attack_wave and attack_type == self._wave_type:
                threats = random.randint(1, 5)
            else:
                threats = random.randint(0, 2)
            self.metrics.record_active_threats(threats, attack_type)

    def _simulate_defense_metrics(self, intensity: float):
        """Simulate defense-related metrics"""
        for defense_type in self._defense_types:
            # Defense effectiveness
            base_eff = self.config.base_defense_effectiveness
            eff = base_eff + random.gauss(0, 5)

            # Slightly lower during attack waves
            if self._in_attack_wave:
                eff -= random.uniform(0, 10)

            eff = max(50, min(100, eff))
            self.metrics.record_defense_effectiveness(eff, defense_type)

            # Response time (in seconds)
            base_time = 0.01  # 10ms base
            response_time = base_time * (1 + random.expovariate(10))
            if self._in_attack_wave:
                response_time *= 1.5  # Slower during heavy load

            self.metrics.record_defense_response_time(response_time, defense_type)

    def _simulate_detection_metrics(self, intensity: float):
        """Simulate detection and analysis metrics"""
        # Prompt injection score
        if random.random() < 0.3 * intensity:
            score = random.betavariate(2, 5) if not self._in_attack_wave else random.betavariate(3, 3)
            self.metrics.record_prompt_injection_score(
                score=score,
                model_name="llm-simulator",
                detection_method=random.choice(["rule_based", "classifier", "heuristic"])
            )

        # System prompt similarity
        if random.random() < 0.2 * intensity:
            similarity = random.betavariate(2, 8)
            if self._in_attack_wave and self._wave_type == "model_extraction":
                similarity = random.betavariate(4, 4)
            self.metrics.record_system_prompt_similarity(similarity, "llm-simulator")

        # Reconstruction error
        if random.random() < 0.2 * intensity:
            error = random.expovariate(0.5)
            if self._in_attack_wave:
                error *= 1.5
            self.metrics.record_reconstruction_error(
                error=error,
                model_name="llm-simulator",
                input_type=random.choice(["text", "image", "unknown"])
            )

        # Embedding distance
        if random.random() < 0.2 * intensity:
            distance = random.expovariate(0.3)
            self.metrics.record_embedding_distance(
                distance=distance,
                model_name="llm-simulator",
                layer=random.choice(["output", "hidden", "embedding"])
            )

        # Stability score
        if random.random() < 0.15:
            stability = 0.95 - random.expovariate(20)
            stability = max(0.5, min(1.0, stability))
            self.metrics.record_stability_score(
                score=stability,
                model_name="llm-simulator",
                perturbation_type=random.choice(["gaussian", "uniform", "adversarial"])
            )

        # Suspicious patterns
        if random.random() < 0.1 * intensity:
            pattern = random.choice(self._pattern_types)
            severity = "critical" if random.random() < 0.2 else "warning"
            self.metrics.record_suspicious_pattern(pattern, severity)

        # Tokens analyzed
        tokens = random.randint(50, 500)
        self.metrics.record_tokens_analyzed(
            count=tokens,
            model_name="llm-simulator",
            analysis_type=random.choice(["security_scan", "prompt_analysis", "output_validation"])
        )

        # Policy violations
        if random.random() < 0.05 * intensity:
            self.metrics.record_policy_violation(
                model_name="llm-simulator",
                violation_type=random.choice(["content_filter", "jailbreak", "suspicious_content"]),
                severity=random.choice(["warning", "critical"])
            )

        # Tool calls
        if random.random() < 0.2:
            tool_name = random.choice(["search", "calculate", "read_file", "shell_exec", "write_file"])
            is_dangerous = tool_name in ["shell_exec", "write_file"]
            self.metrics.record_tool_call(
                tool_name=tool_name,
                user_id=f"user_{random.randint(1, 10)}",
                success=random.random() > 0.1,
                is_dangerous=is_dangerous
            )

        # Distribution PSI (drift)
        if random.random() < 0.1:
            psi = random.betavariate(2, 10)
            if self._in_attack_wave and self._wave_type == "data_poisoning":
                psi = random.betavariate(4, 6)
            self.metrics.record_distribution_psi(psi * 0.5, "llm-simulator", "1d")

        # Class accuracy
        if random.random() < 0.1:
            for cls in ["safe", "suspicious", "malicious"]:
                accuracy = 0.9 + random.gauss(0, 0.03)
                accuracy = max(0.7, min(1.0, accuracy))
                self.metrics.record_class_accuracy(accuracy, "llm-simulator", cls)

    def _simulate_api_metrics(self, intensity: float):
        """Simulate API query metrics"""
        # Simulate queries from various users
        for _ in range(int(self.config.base_query_rate * intensity / 60)):
            user_id = f"user_{random.randint(1, 20)}"

            # Some users make more queries during attacks
            is_suspicious = self._in_attack_wave and random.random() < 0.3
            if is_suspicious:
                user_id = f"suspicious_{random.randint(1, 3)}"

            self.metrics.record_api_query(
                user_id=user_id,
                ip_address=f"192.168.1.{random.randint(1, 254)}",
                endpoint=random.choice(["/predict", "/chat", "/analyze", "/classify"])
            )

            # Record to local metrics for web dashboard
            request_duration = random.uniform(0.01, 0.2)
            blocked = is_suspicious and random.random() < 0.7  # 70% chance to block suspicious
            self.local_metrics.record_request(duration=request_duration, blocked=blocked)

        # Session risk
        session_risk = 20 + random.gauss(0, 10) * intensity
        if self._in_attack_wave:
            session_risk += 20
        session_risk = max(0, min(100, session_risk))
        self.metrics.record_session_risk(session_risk, "default")

    def _update_threat_level(self):
        """Update the current threat level based on metrics"""
        # Calculate threat level based on attack wave and risk
        if self._in_attack_wave:
            self._current_threat_level = random.choice([3, 4])  # HIGH or CRITICAL
        else:
            # Random fluctuation between NONE, LOW, MEDIUM
            self._current_threat_level = random.choices(
                [0, 1, 2],
                weights=[0.2, 0.6, 0.2]
            )[0]

        self.metrics.record_threat_level(self._current_threat_level, "llm-simulator")


# Global simulator instance
_simulator: Optional[SecurityMetricsSimulator] = None


def get_metrics_simulator() -> SecurityMetricsSimulator:
    """Get or create the global metrics simulator"""
    global _simulator
    if _simulator is None:
        _simulator = SecurityMetricsSimulator()
    return _simulator


def start_metrics_simulation(interval: float = 1.0) -> SecurityMetricsSimulator:
    """Start the global metrics simulation"""
    simulator = get_metrics_simulator()
    simulator.start(interval)
    return simulator


def stop_metrics_simulation():
    """Stop the global metrics simulation"""
    global _simulator
    if _simulator:
        _simulator.stop()
