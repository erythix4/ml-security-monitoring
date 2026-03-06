"""
Alerting Module

Provides alerting capabilities for security events,
threshold breaches, and anomaly detection.
"""

from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading
import json

from .metrics import MetricsCollector, get_metrics_collector, Metric
from .logger import LabLogger, get_logger


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AlertStatus(Enum):
    """Alert status"""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


@dataclass
class Alert:
    """Alert data structure"""
    id: str
    name: str
    severity: AlertSeverity
    message: str
    status: AlertStatus = AlertStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    source: str = "system"
    metric_name: Optional[str] = None
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity.value,
            "message": self.message,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "source": self.source,
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "threshold": self.threshold,
            "metadata": self.metadata,
        }


@dataclass
class AlertRule:
    """Alert rule definition"""
    name: str
    description: str
    metric_name: str
    condition: str  # "gt", "lt", "gte", "lte", "eq"
    threshold: float
    severity: AlertSeverity
    cooldown_seconds: int = 60  # Prevent alert flooding
    labels_filter: Optional[Dict[str, str]] = None
    enabled: bool = True
    last_triggered: Optional[datetime] = None

    def check(self, value: float) -> bool:
        """Check if the rule condition is met"""
        if not self.enabled:
            return False

        conditions = {
            "gt": lambda v, t: v > t,
            "lt": lambda v, t: v < t,
            "gte": lambda v, t: v >= t,
            "lte": lambda v, t: v <= t,
            "eq": lambda v, t: v == t,
        }

        check_fn = conditions.get(self.condition)
        if check_fn:
            return check_fn(value, self.threshold)
        return False

    def can_trigger(self) -> bool:
        """Check if rule can trigger (respecting cooldown)"""
        if self.last_triggered is None:
            return True
        elapsed = (datetime.now() - self.last_triggered).total_seconds()
        return elapsed >= self.cooldown_seconds


class AlertHandler:
    """Base alert handler"""

    def handle(self, alert: Alert):
        raise NotImplementedError


class ConsoleAlertHandler(AlertHandler):
    """Console alert handler"""

    def __init__(self):
        from rich.console import Console
        self.console = Console()

    def handle(self, alert: Alert):
        severity_styles = {
            AlertSeverity.INFO: "blue",
            AlertSeverity.WARNING: "yellow",
            AlertSeverity.CRITICAL: "red",
            AlertSeverity.EMERGENCY: "bold red",
        }
        style = severity_styles.get(alert.severity, "white")

        self.console.print(f"\n[{style}][ALERT][/{style}] [{alert.severity.value.upper()}] {alert.name}")
        self.console.print(f"  Message: {alert.message}")
        if alert.metric_value is not None:
            self.console.print(f"  Value: {alert.metric_value} (threshold: {alert.threshold})")
        self.console.print(f"  Time: {alert.created_at.isoformat()}")


class LogAlertHandler(AlertHandler):
    """Log alert handler"""

    def __init__(self, logger: Optional[LabLogger] = None):
        self.logger = logger or get_logger()

    def handle(self, alert: Alert):
        self.logger.log_security_event(
            event=f"Alert: {alert.name}",
            threat_type=alert.source,
            severity=alert.severity.value,
            details={
                "message": alert.message,
                "metric": alert.metric_name,
                "value": alert.metric_value,
                "threshold": alert.threshold,
            }
        )


class WebhookAlertHandler(AlertHandler):
    """Webhook alert handler for external integrations"""

    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.headers = headers or {}

    def handle(self, alert: Alert):
        import urllib.request
        import urllib.error

        data = json.dumps(alert.to_dict()).encode("utf-8")
        headers = {"Content-Type": "application/json", **self.headers}

        req = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                pass
        except urllib.error.URLError:
            pass  # Silently fail for webhook errors


class AlertManager:
    """
    Central alert manager.

    Manages:
    - Alert rules and thresholds
    - Alert lifecycle (create, acknowledge, resolve)
    - Alert handlers (console, log, webhook)
    - Alert history
    """

    def __init__(self, metrics: Optional[MetricsCollector] = None):
        self.metrics = metrics or get_metrics_collector()
        self.rules: List[AlertRule] = []
        self.handlers: List[AlertHandler] = []
        self.alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self._lock = threading.RLock()
        self._alert_counter = 0

        # Register as metrics observer
        self.metrics.add_observer(self._on_metric)

        # Add default rules
        self._setup_default_rules()

    def _setup_default_rules(self):
        """Setup default alerting rules"""
        # High attack success rate
        self.add_rule(AlertRule(
            name="high_attack_success_rate",
            description="Attack success rate exceeds threshold",
            metric_name="attacks_successful",
            condition="gt",
            threshold=5,
            severity=AlertSeverity.WARNING,
            cooldown_seconds=30,
        ))

        # System compromised
        self.add_rule(AlertRule(
            name="system_compromised",
            description="System has been compromised",
            metric_name="attacks_successful",
            condition="gte",
            threshold=1,
            severity=AlertSeverity.CRITICAL,
            cooldown_seconds=60,
        ))

        # High request rate blocked
        self.add_rule(AlertRule(
            name="high_block_rate",
            description="High number of requests being blocked",
            metric_name="requests_blocked",
            condition="gt",
            threshold=10,
            severity=AlertSeverity.WARNING,
            cooldown_seconds=60,
        ))

    def add_rule(self, rule: AlertRule):
        """Add an alerting rule"""
        with self._lock:
            self.rules.append(rule)

    def remove_rule(self, name: str):
        """Remove a rule by name"""
        with self._lock:
            self.rules = [r for r in self.rules if r.name != name]

    def add_handler(self, handler: AlertHandler):
        """Add an alert handler"""
        with self._lock:
            self.handlers.append(handler)

    def _on_metric(self, metric: Metric):
        """Handle incoming metric and check rules"""
        for rule in self.rules:
            if not rule.enabled:
                continue

            # Check if metric matches rule
            if metric.name != rule.metric_name:
                continue

            # Check labels filter if specified
            if rule.labels_filter:
                if not all(metric.labels.get(k) == v for k, v in rule.labels_filter.items()):
                    continue

            # Check condition
            if rule.check(metric.value) and rule.can_trigger():
                self._trigger_alert(rule, metric)

    def _trigger_alert(self, rule: AlertRule, metric: Metric):
        """Trigger an alert"""
        with self._lock:
            self._alert_counter += 1
            alert_id = f"alert_{self._alert_counter:06d}"

            alert = Alert(
                id=alert_id,
                name=rule.name,
                severity=rule.severity,
                message=f"{rule.description}: {metric.name} = {metric.value} (threshold: {rule.threshold})",
                source="rule",
                metric_name=metric.name,
                metric_value=metric.value,
                threshold=rule.threshold,
                metadata={"labels": metric.labels},
            )

            self.alerts[alert_id] = alert
            rule.last_triggered = datetime.now()

            # Dispatch to handlers
            for handler in self.handlers:
                try:
                    handler.handle(alert)
                except Exception:
                    pass

    def create_alert(self, name: str, message: str, severity: AlertSeverity,
                    source: str = "manual", metadata: Dict = None) -> Alert:
        """Manually create an alert"""
        with self._lock:
            self._alert_counter += 1
            alert_id = f"alert_{self._alert_counter:06d}"

            alert = Alert(
                id=alert_id,
                name=name,
                severity=severity,
                message=message,
                source=source,
                metadata=metadata or {},
            )

            self.alerts[alert_id] = alert

            # Dispatch to handlers
            for handler in self.handlers:
                try:
                    handler.handle(alert)
                except Exception:
                    pass

            return alert

    def acknowledge(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        with self._lock:
            if alert_id in self.alerts:
                alert = self.alerts[alert_id]
                alert.status = AlertStatus.ACKNOWLEDGED
                alert.acknowledged_at = datetime.now()
                alert.updated_at = datetime.now()
                return True
            return False

    def resolve(self, alert_id: str) -> bool:
        """Resolve an alert"""
        with self._lock:
            if alert_id in self.alerts:
                alert = self.alerts[alert_id]
                alert.status = AlertStatus.RESOLVED
                alert.resolved_at = datetime.now()
                alert.updated_at = datetime.now()
                # Move to history
                self.alert_history.append(alert)
                del self.alerts[alert_id]
                return True
            return False

    def get_active_alerts(self, severity: Optional[AlertSeverity] = None) -> List[Alert]:
        """Get all active alerts"""
        with self._lock:
            alerts = list(self.alerts.values())
            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            return sorted(alerts, key=lambda a: a.created_at, reverse=True)

    def get_alert_count(self) -> Dict[str, int]:
        """Get alert counts by severity"""
        counts = {s.value: 0 for s in AlertSeverity}
        for alert in self.alerts.values():
            counts[alert.severity.value] += 1
        return counts

    def clear_all(self):
        """Clear all active alerts"""
        with self._lock:
            for alert in self.alerts.values():
                alert.status = AlertStatus.RESOLVED
                alert.resolved_at = datetime.now()
                self.alert_history.append(alert)
            self.alerts.clear()


# Global alert manager instance
_global_alert_manager: Optional[AlertManager] = None


def get_alert_manager() -> AlertManager:
    """Get or create the global alert manager"""
    global _global_alert_manager
    if _global_alert_manager is None:
        _global_alert_manager = AlertManager()
        # Add default console handler
        _global_alert_manager.add_handler(ConsoleAlertHandler())
    return _global_alert_manager


def setup_alerting(console: bool = True, log: bool = True,
                  webhook_url: Optional[str] = None) -> AlertManager:
    """Configure the alerting system"""
    global _global_alert_manager
    _global_alert_manager = AlertManager()

    if console:
        _global_alert_manager.add_handler(ConsoleAlertHandler())

    if log:
        _global_alert_manager.add_handler(LogAlertHandler())

    if webhook_url:
        _global_alert_manager.add_handler(WebhookAlertHandler(webhook_url))

    return _global_alert_manager
