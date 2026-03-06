"""
ML/LLM Security Metrics Module

Provides comprehensive security metrics for detecting:
- Adversarial inputs (FGSM, PGD, perturbation attacks)
- Data poisoning and model drift
- Model extraction attempts
- Prompt injection and jailbreak attacks
- System prompt extraction attempts
"""

import time
import threading
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum

try:
    from prometheus_client import Counter, Gauge, Histogram, Summary
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

logger = logging.getLogger(__name__)


class AttackPattern(Enum):
    """Categories of attack patterns detected by metrics"""
    ADVERSARIAL = "adversarial"
    BEHAVIOR = "behavior"
    LLM = "llm"


@dataclass
class MetricDefinition:
    """Definition of a security metric"""
    name: str
    pattern: AttackPattern
    description: str
    alert_threshold: str
    detected_attacks: List[str]
    unit: str = ""


# Complete metrics catalog from specifications
SECURITY_METRICS_CATALOG = [
    # Adversarial Pattern Metrics
    MetricDefinition(
        name="ml_input_reconstruction_error",
        pattern=AttackPattern.ADVERSARIAL,
        description="Autoencoder reconstruction error for input anomaly detection",
        alert_threshold="> 2.5",
        detected_attacks=["FGSM", "PGD", "Adversarial inputs"],
        unit="score"
    ),
    MetricDefinition(
        name="ml_prediction_confidence_bucket",
        pattern=AttackPattern.ADVERSARIAL,
        description="Distribution of prediction confidence scores",
        alert_threshold="> 0.95 (with high error)",
        detected_attacks=["Adversarial inputs"],
        unit="ratio"
    ),
    MetricDefinition(
        name="ml_embedding_distance_to_centroid",
        pattern=AttackPattern.ADVERSARIAL,
        description="Distance from input embeddings to training centroids",
        alert_threshold="> 3x threshold",
        detected_attacks=["Out-of-distribution", "Adversarial"],
        unit="distance"
    ),
    MetricDefinition(
        name="ml_prediction_stability_score",
        pattern=AttackPattern.ADVERSARIAL,
        description="Variance of predictions under small perturbations",
        alert_threshold="Spike > 3x average",
        detected_attacks=["Adversarial inputs"],
        unit="variance"
    ),
    MetricDefinition(
        name="ml_unstable_predictions_total",
        pattern=AttackPattern.ADVERSARIAL,
        description="Counter of predictions that changed under perturbation",
        alert_threshold="rate > 3x avg_over_time",
        detected_attacks=["Adversarial inputs"],
        unit="count"
    ),
    # Behavior Pattern Metrics
    MetricDefinition(
        name="ml_predictions_by_class_total",
        pattern=AttackPattern.BEHAVIOR,
        description="Distribution of predicted classes over time",
        alert_threshold="Sudden change",
        detected_attacks=["Data poisoning", "Drift"],
        unit="count"
    ),
    MetricDefinition(
        name="ml_prediction_distribution_psi",
        pattern=AttackPattern.BEHAVIOR,
        description="Population Stability Index / KL divergence for drift detection",
        alert_threshold="> 0.2 for 15min",
        detected_attacks=["Data poisoning", "Model drift"],
        unit="score"
    ),
    MetricDefinition(
        name="ml_api_queries_total",
        pattern=AttackPattern.BEHAVIOR,
        description="API queries per user/IP for rate limiting",
        alert_threshold="> 100 req/10min",
        detected_attacks=["Model extraction"],
        unit="count"
    ),
    MetricDefinition(
        name="ml_accuracy_by_class",
        pattern=AttackPattern.BEHAVIOR,
        description="Per-class accuracy for detecting targeted attacks",
        alert_threshold="Drop > 10% vs J-1",
        detected_attacks=["Targeted poisoning"],
        unit="ratio"
    ),
    # LLM Pattern Metrics
    MetricDefinition(
        name="llm_prompt_injection_score",
        pattern=AttackPattern.LLM,
        description="Classifier score for prompt injection detection (0-1)",
        alert_threshold="> 0.85",
        detected_attacks=["Prompt injection", "Jailbreak"],
        unit="score"
    ),
    MetricDefinition(
        name="llm_prompt_similarity_to_system",
        pattern=AttackPattern.LLM,
        description="Embedding similarity between user input and system prompt",
        alert_threshold="> 0.7",
        detected_attacks=["System prompt extraction"],
        unit="similarity"
    ),
    MetricDefinition(
        name="llm_output_policy_violations_total",
        pattern=AttackPattern.LLM,
        description="Counter of content filter policy violations",
        alert_threshold="Repeated violations",
        detected_attacks=["Jailbreak"],
        unit="count"
    ),
    MetricDefinition(
        name="llm_tool_calls_total",
        pattern=AttackPattern.LLM,
        description="Tool/function calls by name, user, and success status",
        alert_threshold="> 5 calls/5min (shell/exec)",
        detected_attacks=["Agent attacks", "Prompt injection"],
        unit="count"
    ),
]


class SecurityMetricsCollector:
    """
    Collector for ML/LLM security metrics.

    Tracks metrics across three attack pattern categories:
    - Adversarial: Input manipulation detection
    - Behavior: Usage pattern anomalies
    - LLM: Prompt-based attack detection
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._initialized = False
        self._prom_metrics: Dict[str, Any] = {}
        self._local_metrics: Dict[str, Any] = defaultdict(lambda: defaultdict(float))
        self._history: Dict[str, List[Dict]] = defaultdict(list)
        self._max_history = 1000
        self._start_time = datetime.now()

        # Thresholds for alerting (configurable)
        self._thresholds = {
            "ml_input_reconstruction_error": 2.5,
            "ml_embedding_distance_to_centroid": 3.0,  # multiplier
            "ml_prediction_distribution_psi": 0.2,
            "ml_api_queries_rate": 100,  # per 10 min
            "ml_accuracy_drop": 0.1,  # 10%
            "llm_prompt_injection_score": 0.85,
            "llm_prompt_similarity_to_system": 0.7,
            "llm_tool_calls_dangerous_rate": 5,  # per 5 min
        }

        # Baseline values for comparison
        self._baselines: Dict[str, float] = {}

    def initialize(self) -> bool:
        """Initialize Prometheus metrics"""
        if self._initialized:
            return True

        if not PROMETHEUS_AVAILABLE:
            logger.warning("Prometheus client not available, using local storage only")
            self._initialized = True
            return False

        try:
            # ===== ADVERSARIAL METRICS =====

            self._prom_metrics["ml_input_reconstruction_error"] = Histogram(
                "ml_input_reconstruction_error",
                "Autoencoder reconstruction error for anomaly detection",
                ["model_name", "input_type"],
                buckets=[0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 10.0]
            )

            self._prom_metrics["ml_prediction_confidence_bucket"] = Histogram(
                "ml_prediction_confidence",
                "Distribution of prediction confidence scores",
                ["model_name", "predicted_class"],
                buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99]
            )

            self._prom_metrics["ml_embedding_distance_to_centroid"] = Histogram(
                "ml_embedding_distance_to_centroid",
                "Distance from input embeddings to training centroids",
                ["model_name", "layer"],
                buckets=[0.1, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0]
            )

            self._prom_metrics["ml_prediction_stability_score"] = Gauge(
                "ml_prediction_stability_score",
                "Variance of predictions under perturbation",
                ["model_name", "perturbation_type"]
            )

            self._prom_metrics["ml_unstable_predictions_total"] = Counter(
                "ml_unstable_predictions_total",
                "Count of predictions that changed under perturbation",
                ["model_name", "perturbation_type"]
            )

            # ===== BEHAVIOR METRICS =====

            self._prom_metrics["ml_predictions_by_class_total"] = Counter(
                "ml_predictions_by_class_total",
                "Distribution of predicted classes",
                ["model_name", "predicted_class"]
            )

            self._prom_metrics["ml_prediction_distribution_psi"] = Gauge(
                "ml_prediction_distribution_psi",
                "Population Stability Index for drift detection",
                ["model_name", "reference_window"]
            )

            self._prom_metrics["ml_api_queries_total"] = Counter(
                "ml_api_queries_total",
                "API queries per user/IP",
                ["user_id", "ip_address", "endpoint"]
            )

            self._prom_metrics["ml_accuracy_by_class"] = Gauge(
                "ml_accuracy_by_class",
                "Per-class accuracy metric",
                ["model_name", "class_name"]
            )

            # ===== LLM METRICS =====

            self._prom_metrics["llm_prompt_injection_score"] = Histogram(
                "llm_prompt_injection_score",
                "Prompt injection classifier score (0-1)",
                ["model_name", "detection_method"],
                buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 1.0]
            )

            self._prom_metrics["llm_prompt_similarity_to_system"] = Histogram(
                "llm_prompt_similarity_to_system",
                "Embedding similarity between input and system prompt",
                ["model_name"],
                buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
            )

            self._prom_metrics["llm_output_policy_violations_total"] = Counter(
                "llm_output_policy_violations_total",
                "Content filter policy violations",
                ["model_name", "violation_type", "severity"]
            )

            self._prom_metrics["llm_tool_calls_total"] = Counter(
                "llm_tool_calls_total",
                "Tool/function calls tracking",
                ["tool_name", "user_id", "success", "is_dangerous"]
            )

            self._prom_metrics["llm_output_contains_system_prompt"] = Counter(
                "llm_output_contains_system_prompt_total",
                "Count of outputs containing system prompt content",
                ["model_name", "detection_method"]
            )

            # ===== ADDITIONAL SECURITY GAUGES =====

            self._prom_metrics["ml_embedding_distance_threshold"] = Gauge(
                "ml_embedding_distance_threshold",
                "Current threshold for embedding distance alerts",
                ["model_name"]
            )

            self._prom_metrics["ml_baseline_accuracy"] = Gauge(
                "ml_baseline_accuracy",
                "Baseline accuracy for comparison",
                ["model_name", "class_name"]
            )

            self._prom_metrics["security_alerts_total"] = Counter(
                "security_alerts_total",
                "Total security alerts raised",
                ["alert_type", "severity", "pattern"]
            )

            # ===== ADVANCED SECURITY GAUGES =====

            self._prom_metrics["security_risk_score"] = Gauge(
                "security_risk_score",
                "Overall security risk score (0-100)",
                ["model_name", "risk_category"]
            )

            self._prom_metrics["security_threat_level"] = Gauge(
                "security_threat_level",
                "Current threat level (0=none, 1=low, 2=medium, 3=high, 4=critical)",
                ["model_name"]
            )

            self._prom_metrics["attack_success_rate"] = Gauge(
                "attack_success_rate",
                "Attack success rate percentage (0-100)",
                ["attack_type"]
            )

            self._prom_metrics["defense_effectiveness"] = Gauge(
                "defense_effectiveness",
                "Defense effectiveness score (0-100)",
                ["defense_type"]
            )

            self._prom_metrics["active_threats_count"] = Gauge(
                "active_threats_count",
                "Number of currently active threats",
                ["threat_type"]
            )

            self._prom_metrics["blocked_attacks_total"] = Counter(
                "blocked_attacks_total",
                "Total attacks blocked by defenses",
                ["attack_type", "defense_type"]
            )

            self._prom_metrics["response_time_seconds"] = Histogram(
                "defense_response_time_seconds",
                "Defense response time in seconds",
                ["defense_type"],
                buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
            )

            self._prom_metrics["tokens_analyzed_total"] = Counter(
                "tokens_analyzed_total",
                "Total tokens analyzed for security threats",
                ["model_name", "analysis_type"]
            )

            self._prom_metrics["suspicious_patterns_detected"] = Counter(
                "suspicious_patterns_detected_total",
                "Suspicious patterns detected in inputs",
                ["pattern_type", "severity"]
            )

            self._prom_metrics["model_confidence_deviation"] = Gauge(
                "model_confidence_deviation",
                "Deviation from expected model confidence",
                ["model_name"]
            )

            self._prom_metrics["attack_attempts_per_minute"] = Gauge(
                "attack_attempts_per_minute",
                "Current rate of attack attempts per minute",
                ["attack_type"]
            )

            self._prom_metrics["session_risk_score"] = Gauge(
                "session_risk_score",
                "Risk score for the current session (0-100)",
                ["session_id"]
            )

            self._initialized = True
            logger.info("Security metrics initialized successfully")

            # Initialize baseline metrics for Grafana dashboards
            self._initialize_baseline_metrics()

            return True

        except Exception as e:
            logger.error(f"Failed to initialize security metrics: {e}")
            self._initialized = True
            return False

    def _initialize_baseline_metrics(self):
        """Initialize metrics with baseline values so Grafana dashboards show data immediately"""
        try:
            # Initialize histogram metrics by accessing them (creates time series)
            models = ["llm-simulator", "default"]
            input_types = ["text", "image", "unknown"]
            layers = ["output", "hidden", "embedding"]
            perturbation_types = ["gaussian", "uniform", "adversarial"]
            detection_methods = ["rule_based", "classifier", "heuristic"]
            classes = ["safe", "suspicious", "malicious"]

            for model in models:
                for input_type in input_types:
                    if "ml_input_reconstruction_error" in self._prom_metrics:
                        self._prom_metrics["ml_input_reconstruction_error"].labels(
                            model_name=model, input_type=input_type
                        )

                for layer in layers:
                    if "ml_embedding_distance_to_centroid" in self._prom_metrics:
                        self._prom_metrics["ml_embedding_distance_to_centroid"].labels(
                            model_name=model, layer=layer
                        )

                for ptype in perturbation_types:
                    if "ml_prediction_stability_score" in self._prom_metrics:
                        self._prom_metrics["ml_prediction_stability_score"].labels(
                            model_name=model, perturbation_type=ptype
                        ).set(0.95)
                    if "ml_unstable_predictions_total" in self._prom_metrics:
                        self._prom_metrics["ml_unstable_predictions_total"].labels(
                            model_name=model, perturbation_type=ptype
                        )

                for method in detection_methods:
                    if "llm_prompt_injection_score" in self._prom_metrics:
                        self._prom_metrics["llm_prompt_injection_score"].labels(
                            model_name=model, detection_method=method
                        )

                if "llm_prompt_similarity_to_system" in self._prom_metrics:
                    self._prom_metrics["llm_prompt_similarity_to_system"].labels(
                        model_name=model
                    )

                for cls in classes:
                    if "ml_prediction_confidence_bucket" in self._prom_metrics:
                        self._prom_metrics["ml_prediction_confidence_bucket"].labels(
                            model_name=model, predicted_class=cls
                        )
                    if "ml_predictions_by_class_total" in self._prom_metrics:
                        self._prom_metrics["ml_predictions_by_class_total"].labels(
                            model_name=model, predicted_class=cls
                        )
                    if "ml_accuracy_by_class" in self._prom_metrics:
                        self._prom_metrics["ml_accuracy_by_class"].labels(
                            model_name=model, class_name=cls
                        ).set(0.9)
                    if "ml_baseline_accuracy" in self._prom_metrics:
                        self._prom_metrics["ml_baseline_accuracy"].labels(
                            model_name=model, class_name=cls
                        ).set(0.92)

                # PSI metric
                if "ml_prediction_distribution_psi" in self._prom_metrics:
                    self._prom_metrics["ml_prediction_distribution_psi"].labels(
                        model_name=model, reference_window="1d"
                    ).set(0.05)

                # Embedding threshold
                if "ml_embedding_distance_threshold" in self._prom_metrics:
                    self._prom_metrics["ml_embedding_distance_threshold"].labels(
                        model_name=model
                    ).set(3.0)

            # Initialize policy violations
            violation_types = ["content_filter", "jailbreak", "suspicious_content"]
            severities = ["warning", "critical"]
            for vtype in violation_types:
                for sev in severities:
                    if "llm_output_policy_violations_total" in self._prom_metrics:
                        self._prom_metrics["llm_output_policy_violations_total"].labels(
                            model_name="llm-simulator", violation_type=vtype, severity=sev
                        )

            # Initialize tool calls
            tool_names = ["search", "calculate", "read_file", "shell_exec", "write_file"]
            for tool in tool_names:
                is_dangerous = "true" if tool in ["shell_exec", "write_file"] else "false"
                if "llm_tool_calls_total" in self._prom_metrics:
                    self._prom_metrics["llm_tool_calls_total"].labels(
                        tool_name=tool, user_id="system", success="true", is_dangerous=is_dangerous
                    )

            # Initialize security alerts - ALL attack types from the registry
            alert_types = [
                "prompt_injection",
                "jailbreak",
                "data_poisoning",
                "model_extraction",
                "membership_inference",
                "extraction"  # alias for model_extraction
            ]
            patterns = ["llm", "adversarial", "behavior"]
            for atype in alert_types:
                for sev in severities:
                    for pattern in patterns:
                        if "security_alerts_total" in self._prom_metrics:
                            self._prom_metrics["security_alerts_total"].labels(
                                alert_type=atype, severity=sev, pattern=pattern
                            )

            # Initialize advanced security gauges
            risk_categories = ["overall", "prompt_injection", "jailbreak", "data_poisoning", "model_extraction"]
            for model in models:
                for cat in risk_categories:
                    if "security_risk_score" in self._prom_metrics:
                        self._prom_metrics["security_risk_score"].labels(
                            model_name=model, risk_category=cat
                        ).set(25.0)  # Default low risk

                if "security_threat_level" in self._prom_metrics:
                    self._prom_metrics["security_threat_level"].labels(
                        model_name=model
                    ).set(1)  # Low threat

                if "model_confidence_deviation" in self._prom_metrics:
                    self._prom_metrics["model_confidence_deviation"].labels(
                        model_name=model
                    ).set(0.05)

            # Initialize attack success rates
            attack_types = ["prompt_injection", "jailbreak", "data_poisoning", "model_extraction", "membership_inference"]
            for atype in attack_types:
                if "attack_success_rate" in self._prom_metrics:
                    self._prom_metrics["attack_success_rate"].labels(
                        attack_type=atype
                    ).set(15.0)  # 15% default success rate

                if "attack_attempts_per_minute" in self._prom_metrics:
                    self._prom_metrics["attack_attempts_per_minute"].labels(
                        attack_type=atype
                    ).set(0)

                if "active_threats_count" in self._prom_metrics:
                    self._prom_metrics["active_threats_count"].labels(
                        threat_type=atype
                    ).set(0)

            # Initialize defense effectiveness
            defense_types = ["input_sanitizer", "guardrails", "output_filter", "rate_limiter", "anomaly_detector"]
            for dtype in defense_types:
                if "defense_effectiveness" in self._prom_metrics:
                    self._prom_metrics["defense_effectiveness"].labels(
                        defense_type=dtype
                    ).set(85.0)  # 85% default effectiveness

                if "response_time_seconds" in self._prom_metrics:
                    self._prom_metrics["response_time_seconds"].labels(
                        defense_type=dtype
                    )

            # Initialize blocked attacks
            for atype in attack_types:
                for dtype in defense_types:
                    if "blocked_attacks_total" in self._prom_metrics:
                        self._prom_metrics["blocked_attacks_total"].labels(
                            attack_type=atype, defense_type=dtype
                        )

            # Initialize suspicious patterns
            pattern_types = ["sql_injection", "command_injection", "xss", "prompt_leak", "role_confusion"]
            for ptype in pattern_types:
                for sev in severities:
                    if "suspicious_patterns_detected" in self._prom_metrics:
                        self._prom_metrics["suspicious_patterns_detected"].labels(
                            pattern_type=ptype, severity=sev
                        )

            # Initialize tokens analyzed
            analysis_types = ["security_scan", "prompt_analysis", "output_validation"]
            for model in models:
                for atype in analysis_types:
                    if "tokens_analyzed_total" in self._prom_metrics:
                        self._prom_metrics["tokens_analyzed_total"].labels(
                            model_name=model, analysis_type=atype
                        )

            # Initialize session risk
            if "session_risk_score" in self._prom_metrics:
                self._prom_metrics["session_risk_score"].labels(
                    session_id="default"
                ).set(20.0)

            logger.info("Security metrics baseline initialized for Grafana dashboards")

        except Exception as e:
            logger.warning(f"Failed to initialize baseline security metrics: {e}")

    # ===== ADVERSARIAL METRICS RECORDING =====

    def record_reconstruction_error(
        self,
        error: float,
        model_name: str = "default",
        input_type: str = "unknown"
    ):
        """Record autoencoder reconstruction error"""
        self._record_to_history("ml_input_reconstruction_error", error, {
            "model_name": model_name, "input_type": input_type
        })

        if "ml_input_reconstruction_error" in self._prom_metrics:
            self._prom_metrics["ml_input_reconstruction_error"].labels(
                model_name=model_name,
                input_type=input_type
            ).observe(error)

    def record_prediction_confidence(
        self,
        confidence: float,
        model_name: str = "default",
        predicted_class: str = "unknown"
    ):
        """Record prediction confidence score"""
        self._record_to_history("ml_prediction_confidence_bucket", confidence, {
            "model_name": model_name, "predicted_class": predicted_class
        })

        if "ml_prediction_confidence_bucket" in self._prom_metrics:
            self._prom_metrics["ml_prediction_confidence_bucket"].labels(
                model_name=model_name,
                predicted_class=predicted_class
            ).observe(confidence)

    def record_embedding_distance(
        self,
        distance: float,
        model_name: str = "default",
        layer: str = "output"
    ):
        """Record distance from embedding centroid"""
        self._record_to_history("ml_embedding_distance_to_centroid", distance, {
            "model_name": model_name, "layer": layer
        })

        if "ml_embedding_distance_to_centroid" in self._prom_metrics:
            self._prom_metrics["ml_embedding_distance_to_centroid"].labels(
                model_name=model_name,
                layer=layer
            ).observe(distance)

    def record_stability_score(
        self,
        score: float,
        model_name: str = "default",
        perturbation_type: str = "gaussian"
    ):
        """Record prediction stability score"""
        self._record_to_history("ml_prediction_stability_score", score, {
            "model_name": model_name, "perturbation_type": perturbation_type
        })

        if "ml_prediction_stability_score" in self._prom_metrics:
            self._prom_metrics["ml_prediction_stability_score"].labels(
                model_name=model_name,
                perturbation_type=perturbation_type
            ).set(score)

    def record_unstable_prediction(
        self,
        model_name: str = "default",
        perturbation_type: str = "gaussian"
    ):
        """Increment unstable predictions counter"""
        self._record_to_history("ml_unstable_predictions_total", 1, {
            "model_name": model_name, "perturbation_type": perturbation_type
        })

        if "ml_unstable_predictions_total" in self._prom_metrics:
            self._prom_metrics["ml_unstable_predictions_total"].labels(
                model_name=model_name,
                perturbation_type=perturbation_type
            ).inc()

    # ===== BEHAVIOR METRICS RECORDING =====

    def record_prediction_class(
        self,
        model_name: str = "default",
        predicted_class: str = "unknown"
    ):
        """Record prediction for class distribution tracking"""
        self._record_to_history("ml_predictions_by_class_total", 1, {
            "model_name": model_name, "predicted_class": predicted_class
        })

        if "ml_predictions_by_class_total" in self._prom_metrics:
            self._prom_metrics["ml_predictions_by_class_total"].labels(
                model_name=model_name,
                predicted_class=predicted_class
            ).inc()

    def record_distribution_psi(
        self,
        psi_score: float,
        model_name: str = "default",
        reference_window: str = "1d"
    ):
        """Record PSI/KL divergence score for drift detection"""
        self._record_to_history("ml_prediction_distribution_psi", psi_score, {
            "model_name": model_name, "reference_window": reference_window
        })

        if "ml_prediction_distribution_psi" in self._prom_metrics:
            self._prom_metrics["ml_prediction_distribution_psi"].labels(
                model_name=model_name,
                reference_window=reference_window
            ).set(psi_score)

    def record_api_query(
        self,
        user_id: str = "anonymous",
        ip_address: str = "unknown",
        endpoint: str = "/predict"
    ):
        """Record API query for rate limiting"""
        self._record_to_history("ml_api_queries_total", 1, {
            "user_id": user_id, "ip_address": ip_address, "endpoint": endpoint
        })

        if "ml_api_queries_total" in self._prom_metrics:
            self._prom_metrics["ml_api_queries_total"].labels(
                user_id=user_id,
                ip_address=ip_address,
                endpoint=endpoint
            ).inc()

    def record_class_accuracy(
        self,
        accuracy: float,
        model_name: str = "default",
        class_name: str = "unknown"
    ):
        """Record per-class accuracy"""
        self._record_to_history("ml_accuracy_by_class", accuracy, {
            "model_name": model_name, "class_name": class_name
        })

        if "ml_accuracy_by_class" in self._prom_metrics:
            self._prom_metrics["ml_accuracy_by_class"].labels(
                model_name=model_name,
                class_name=class_name
            ).set(accuracy)

    # ===== LLM METRICS RECORDING =====

    def record_prompt_injection_score(
        self,
        score: float,
        model_name: str = "default",
        detection_method: str = "classifier"
    ):
        """Record prompt injection detection score"""
        self._record_to_history("llm_prompt_injection_score", score, {
            "model_name": model_name, "detection_method": detection_method
        })

        if "llm_prompt_injection_score" in self._prom_metrics:
            self._prom_metrics["llm_prompt_injection_score"].labels(
                model_name=model_name,
                detection_method=detection_method
            ).observe(score)

    def record_system_prompt_similarity(
        self,
        similarity: float,
        model_name: str = "default"
    ):
        """Record similarity between input and system prompt"""
        self._record_to_history("llm_prompt_similarity_to_system", similarity, {
            "model_name": model_name
        })

        if "llm_prompt_similarity_to_system" in self._prom_metrics:
            self._prom_metrics["llm_prompt_similarity_to_system"].labels(
                model_name=model_name
            ).observe(similarity)

    def record_policy_violation(
        self,
        model_name: str = "default",
        violation_type: str = "content_filter",
        severity: str = "medium"
    ):
        """Record content policy violation"""
        self._record_to_history("llm_output_policy_violations_total", 1, {
            "model_name": model_name, "violation_type": violation_type, "severity": severity
        })

        if "llm_output_policy_violations_total" in self._prom_metrics:
            self._prom_metrics["llm_output_policy_violations_total"].labels(
                model_name=model_name,
                violation_type=violation_type,
                severity=severity
            ).inc()

    def record_tool_call(
        self,
        tool_name: str,
        user_id: str = "anonymous",
        success: bool = True,
        is_dangerous: bool = False
    ):
        """Record LLM tool/function call"""
        self._record_to_history("llm_tool_calls_total", 1, {
            "tool_name": tool_name,
            "user_id": user_id,
            "success": str(success).lower(),
            "is_dangerous": str(is_dangerous).lower()
        })

        if "llm_tool_calls_total" in self._prom_metrics:
            self._prom_metrics["llm_tool_calls_total"].labels(
                tool_name=tool_name,
                user_id=user_id,
                success=str(success).lower(),
                is_dangerous=str(is_dangerous).lower()
            ).inc()

    def record_system_prompt_leak(
        self,
        model_name: str = "default",
        detection_method: str = "substring"
    ):
        """Record detection of system prompt in output"""
        self._record_to_history("llm_output_contains_system_prompt", 1, {
            "model_name": model_name, "detection_method": detection_method
        })

        if "llm_output_contains_system_prompt" in self._prom_metrics:
            self._prom_metrics["llm_output_contains_system_prompt"].labels(
                model_name=model_name,
                detection_method=detection_method
            ).inc()

    def record_security_alert(
        self,
        alert_type: str,
        severity: str = "warning",
        pattern: str = "unknown"
    ):
        """Record a security alert being raised"""
        self._record_to_history("security_alerts_total", 1, {
            "alert_type": alert_type, "severity": severity, "pattern": pattern
        })

        if "security_alerts_total" in self._prom_metrics:
            self._prom_metrics["security_alerts_total"].labels(
                alert_type=alert_type,
                severity=severity,
                pattern=pattern
            ).inc()

    # ===== ADVANCED SECURITY METRICS RECORDING =====

    def record_risk_score(
        self,
        score: float,
        model_name: str = "default",
        risk_category: str = "overall"
    ):
        """Record security risk score (0-100)"""
        self._record_to_history("security_risk_score", score, {
            "model_name": model_name, "risk_category": risk_category
        })

        if "security_risk_score" in self._prom_metrics:
            self._prom_metrics["security_risk_score"].labels(
                model_name=model_name,
                risk_category=risk_category
            ).set(score)

    def record_threat_level(
        self,
        level: int,
        model_name: str = "default"
    ):
        """Record current threat level (0-4)"""
        self._record_to_history("security_threat_level", level, {
            "model_name": model_name
        })

        if "security_threat_level" in self._prom_metrics:
            self._prom_metrics["security_threat_level"].labels(
                model_name=model_name
            ).set(level)

    def record_attack_success_rate(
        self,
        rate: float,
        attack_type: str
    ):
        """Record attack success rate percentage (0-100)"""
        self._record_to_history("attack_success_rate", rate, {
            "attack_type": attack_type
        })

        if "attack_success_rate" in self._prom_metrics:
            self._prom_metrics["attack_success_rate"].labels(
                attack_type=attack_type
            ).set(rate)

    def record_defense_effectiveness(
        self,
        effectiveness: float,
        defense_type: str
    ):
        """Record defense effectiveness score (0-100)"""
        self._record_to_history("defense_effectiveness", effectiveness, {
            "defense_type": defense_type
        })

        if "defense_effectiveness" in self._prom_metrics:
            self._prom_metrics["defense_effectiveness"].labels(
                defense_type=defense_type
            ).set(effectiveness)

    def record_active_threats(
        self,
        count: int,
        threat_type: str
    ):
        """Record number of active threats"""
        self._record_to_history("active_threats_count", count, {
            "threat_type": threat_type
        })

        if "active_threats_count" in self._prom_metrics:
            self._prom_metrics["active_threats_count"].labels(
                threat_type=threat_type
            ).set(count)

    def record_blocked_attack(
        self,
        attack_type: str,
        defense_type: str
    ):
        """Record a blocked attack"""
        self._record_to_history("blocked_attacks_total", 1, {
            "attack_type": attack_type, "defense_type": defense_type
        })

        if "blocked_attacks_total" in self._prom_metrics:
            self._prom_metrics["blocked_attacks_total"].labels(
                attack_type=attack_type,
                defense_type=defense_type
            ).inc()

    def record_defense_response_time(
        self,
        duration: float,
        defense_type: str
    ):
        """Record defense response time in seconds"""
        self._record_to_history("response_time_seconds", duration, {
            "defense_type": defense_type
        })

        if "response_time_seconds" in self._prom_metrics:
            self._prom_metrics["response_time_seconds"].labels(
                defense_type=defense_type
            ).observe(duration)

    def record_tokens_analyzed(
        self,
        count: int,
        model_name: str = "default",
        analysis_type: str = "security_scan"
    ):
        """Record tokens analyzed for security"""
        self._record_to_history("tokens_analyzed_total", count, {
            "model_name": model_name, "analysis_type": analysis_type
        })

        if "tokens_analyzed_total" in self._prom_metrics:
            self._prom_metrics["tokens_analyzed_total"].labels(
                model_name=model_name,
                analysis_type=analysis_type
            ).inc(count)

    def record_suspicious_pattern(
        self,
        pattern_type: str,
        severity: str = "warning"
    ):
        """Record detection of a suspicious pattern"""
        self._record_to_history("suspicious_patterns_detected", 1, {
            "pattern_type": pattern_type, "severity": severity
        })

        if "suspicious_patterns_detected" in self._prom_metrics:
            self._prom_metrics["suspicious_patterns_detected"].labels(
                pattern_type=pattern_type,
                severity=severity
            ).inc()

    def record_attack_attempts_rate(
        self,
        rate: float,
        attack_type: str
    ):
        """Record current rate of attack attempts per minute"""
        self._record_to_history("attack_attempts_per_minute", rate, {
            "attack_type": attack_type
        })

        if "attack_attempts_per_minute" in self._prom_metrics:
            self._prom_metrics["attack_attempts_per_minute"].labels(
                attack_type=attack_type
            ).set(rate)

    def record_session_risk(
        self,
        score: float,
        session_id: str = "default"
    ):
        """Record session risk score (0-100)"""
        self._record_to_history("session_risk_score", score, {
            "session_id": session_id
        })

        if "session_risk_score" in self._prom_metrics:
            self._prom_metrics["session_risk_score"].labels(
                session_id=session_id
            ).set(score)

    def record_confidence_deviation(
        self,
        deviation: float,
        model_name: str = "default"
    ):
        """Record deviation from expected model confidence"""
        self._record_to_history("model_confidence_deviation", deviation, {
            "model_name": model_name
        })

        if "model_confidence_deviation" in self._prom_metrics:
            self._prom_metrics["model_confidence_deviation"].labels(
                model_name=model_name
            ).set(deviation)

    # ===== THRESHOLD MANAGEMENT =====

    def set_threshold(self, metric_name: str, value: float):
        """Set alert threshold for a metric"""
        with self._lock:
            self._thresholds[metric_name] = value

    def get_threshold(self, metric_name: str) -> Optional[float]:
        """Get alert threshold for a metric"""
        return self._thresholds.get(metric_name)

    def set_baseline(self, metric_name: str, value: float, labels: Optional[Dict] = None):
        """Set baseline value for comparison"""
        key = metric_name
        if labels:
            key += "_" + "_".join(f"{k}={v}" for k, v in sorted(labels.items()))
        with self._lock:
            self._baselines[key] = value

        # Also set in Prometheus gauge if available
        if metric_name == "ml_accuracy_by_class" and "ml_baseline_accuracy" in self._prom_metrics:
            model_name = labels.get("model_name", "default") if labels else "default"
            class_name = labels.get("class_name", "unknown") if labels else "unknown"
            self._prom_metrics["ml_baseline_accuracy"].labels(
                model_name=model_name,
                class_name=class_name
            ).set(value)

    def set_embedding_threshold(self, threshold: float, model_name: str = "default"):
        """Set embedding distance threshold"""
        self._thresholds["ml_embedding_distance_to_centroid"] = threshold
        if "ml_embedding_distance_threshold" in self._prom_metrics:
            self._prom_metrics["ml_embedding_distance_threshold"].labels(
                model_name=model_name
            ).set(threshold)

    # ===== UTILITY METHODS =====

    def _record_to_history(self, metric_name: str, value: float, labels: Dict):
        """Record metric to local history for analysis"""
        with self._lock:
            entry = {
                "value": value,
                "labels": labels,
                "timestamp": datetime.now().isoformat()
            }
            self._history[metric_name].append(entry)

            # Trim history if needed
            if len(self._history[metric_name]) > self._max_history:
                self._history[metric_name] = self._history[metric_name][-self._max_history:]

    def get_metric_history(
        self,
        metric_name: str,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get metric history for analysis"""
        with self._lock:
            history = self._history.get(metric_name, [])
            if since:
                history = [
                    h for h in history
                    if datetime.fromisoformat(h["timestamp"]) >= since
                ]
            return history[-limit:]

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all security metrics"""
        with self._lock:
            summary = {
                "uptime_seconds": (datetime.now() - self._start_time).total_seconds(),
                "metrics_count": len(self._history),
                "thresholds": dict(self._thresholds),
                "baselines": dict(self._baselines),
                "history_sizes": {k: len(v) for k, v in self._history.items()}
            }
            return summary

    def get_catalog(self) -> List[Dict]:
        """Get the full metrics catalog with descriptions"""
        return [
            {
                "name": m.name,
                "pattern": m.pattern.value,
                "description": m.description,
                "alert_threshold": m.alert_threshold,
                "detected_attacks": m.detected_attacks,
                "unit": m.unit
            }
            for m in SECURITY_METRICS_CATALOG
        ]

    def reset(self):
        """Reset all local metrics data"""
        with self._lock:
            self._history.clear()
            self._start_time = datetime.now()


# Global instance
_security_metrics: Optional[SecurityMetricsCollector] = None


def get_security_metrics() -> SecurityMetricsCollector:
    """Get or create global security metrics collector"""
    global _security_metrics
    if _security_metrics is None:
        _security_metrics = SecurityMetricsCollector()
        _security_metrics.initialize()
    return _security_metrics


def init_security_metrics() -> SecurityMetricsCollector:
    """Initialize and return the security metrics collector"""
    collector = get_security_metrics()
    collector.initialize()
    return collector
