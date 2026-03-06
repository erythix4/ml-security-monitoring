"""
Monitoring & Observability Module

Provides comprehensive monitoring, logging, metrics collection,
and alerting for the LLM Attack Simulation Lab.

Includes specialized security metrics for detecting:
- Adversarial inputs (FGSM, PGD, perturbation attacks)
- Data poisoning and model drift
- Model extraction attempts
- Prompt injection and jailbreak attacks
- System prompt extraction attempts
"""

from .metrics import MetricsCollector, Metric, MetricType
from .logger import LabLogger, LogLevel
from .dashboard import MonitoringDashboard
from .alerts import AlertManager, Alert, AlertSeverity
from .security_metrics import (
    SecurityMetricsCollector,
    get_security_metrics,
    init_security_metrics,
    AttackPattern,
    SECURITY_METRICS_CATALOG,
)
from .metrics_simulator import (
    SecurityMetricsSimulator,
    SimulationConfig,
    get_metrics_simulator,
    start_metrics_simulation,
    stop_metrics_simulation,
)

__all__ = [
    # Core metrics
    "MetricsCollector",
    "Metric",
    "MetricType",
    # Logging
    "LabLogger",
    "LogLevel",
    # Dashboard
    "MonitoringDashboard",
    # Alerting
    "AlertManager",
    "Alert",
    "AlertSeverity",
    # Security metrics
    "SecurityMetricsCollector",
    "get_security_metrics",
    "init_security_metrics",
    "AttackPattern",
    "SECURITY_METRICS_CATALOG",
    # Metrics simulator
    "SecurityMetricsSimulator",
    "SimulationConfig",
    "get_metrics_simulator",
    "start_metrics_simulation",
    "stop_metrics_simulation",
]
