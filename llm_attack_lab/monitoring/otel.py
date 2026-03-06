"""
OpenTelemetry Integration Module

Provides comprehensive observability with:
- Distributed tracing
- Metrics export to Prometheus/VictoriaMetrics
- Integration with OpenTelemetry Collector
"""
from __future__ import annotations

import os
import time
import socket
import logging
from typing import Optional, Dict, Any, TYPE_CHECKING
from contextlib import contextmanager

# Type checking imports
if TYPE_CHECKING:
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.resources import Resource

# OpenTelemetry imports with fallback
try:
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.trace import Status, StatusCode
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    trace = None
    metrics = None

# Prometheus exporter for local metrics endpoint
try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
    from prometheus_client import start_http_server as start_prometheus_server
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


logger = logging.getLogger(__name__)


def _is_port_available(port: int, host: str = "0.0.0.0") -> bool:
    """Check if a port is available for binding"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def _is_collector_reachable(endpoint: str, timeout: float = 2.0) -> bool:
    """
    Check if the OTLP collector is reachable.

    Args:
        endpoint: The collector endpoint in format 'host:port'
        timeout: Connection timeout in seconds

    Returns:
        True if the collector is reachable, False otherwise
    """
    try:
        # Parse host and port from endpoint
        if ':' in endpoint:
            host, port_str = endpoint.rsplit(':', 1)
            port = int(port_str)
        else:
            host = endpoint
            port = 4317  # Default OTLP gRPC port

        # Attempt to connect
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0
    except (OSError, ValueError, socket.timeout):
        return False


def _suppress_grpc_logging():
    """Suppress verbose gRPC and OpenTelemetry exporter logging when collector is unavailable"""
    # Suppress gRPC core logging
    import os
    os.environ.setdefault("GRPC_VERBOSITY", "ERROR")
    os.environ.setdefault("GRPC_TRACE", "")

    # Suppress OpenTelemetry exporter warnings
    logging.getLogger("opentelemetry.exporter.otlp").setLevel(logging.ERROR)
    logging.getLogger("opentelemetry.exporter.otlp.proto.grpc").setLevel(logging.ERROR)
    logging.getLogger("grpc").setLevel(logging.ERROR)


class OTelConfig:
    """Configuration for OpenTelemetry"""

    def __init__(self):
        self.service_name = os.getenv("OTEL_SERVICE_NAME", "llm-attack-lab")
        self.service_version = os.getenv("OTEL_SERVICE_VERSION", "1.0.0")
        # Raw endpoint from environment (may include http:// prefix)
        self._otlp_endpoint_raw = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector:4317")
        # gRPC endpoint must NOT have http:// prefix - strip it if present
        self.otlp_endpoint = self._normalize_grpc_endpoint(self._otlp_endpoint_raw)
        self.prometheus_port = int(os.getenv("PROMETHEUS_METRICS_PORT", "8000"))
        self.prometheus_port_auto = os.getenv("PROMETHEUS_PORT_AUTO", "true").lower() == "true"
        self.prometheus_port_range = int(os.getenv("PROMETHEUS_PORT_RANGE", "10"))
        self.enable_tracing = os.getenv("OTEL_ENABLE_TRACING", "true").lower() == "true"
        self.enable_metrics = os.getenv("OTEL_ENABLE_METRICS", "true").lower() == "true"

        # OTLP export control - can be explicitly disabled to avoid connection errors
        # "auto" means check if collector is reachable before enabling
        self._otlp_enabled_raw = os.getenv("OTEL_EXPORTER_OTLP_ENABLED", "auto").lower()
        self.collector_check_timeout = float(os.getenv("OTEL_COLLECTOR_CHECK_TIMEOUT", "2.0"))

        # Retry and timeout configuration
        self.otlp_timeout_seconds = int(os.getenv("OTEL_EXPORTER_OTLP_TIMEOUT", "30"))
        self.export_timeout_millis = int(os.getenv("OTEL_EXPORT_TIMEOUT_MILLIS", "30000"))
        self.max_queue_size = int(os.getenv("OTEL_BSP_MAX_QUEUE_SIZE", "2048"))
        self.max_export_batch_size = int(os.getenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "512"))
        self.schedule_delay_millis = int(os.getenv("OTEL_BSP_SCHEDULE_DELAY_MILLIS", "5000"))
        self.metrics_export_interval_millis = int(os.getenv("OTEL_METRIC_EXPORT_INTERVAL", "15000"))
        self.collector_wait_timeout = int(os.getenv("OTEL_COLLECTOR_WAIT_TIMEOUT", "60"))

    @staticmethod
    def _normalize_grpc_endpoint(endpoint: str) -> str:
        """
        Normalize endpoint for gRPC exporter.

        The gRPC OTLP exporter expects endpoint in format 'host:port' without
        the http:// or https:// scheme prefix. This method strips the scheme
        if present to ensure compatibility.

        Args:
            endpoint: Raw endpoint string (e.g., 'http://otel-collector:4317')

        Returns:
            Normalized endpoint (e.g., 'otel-collector:4317')
        """
        if endpoint.startswith("http://"):
            return endpoint[7:]  # Remove 'http://'
        elif endpoint.startswith("https://"):
            return endpoint[8:]  # Remove 'https://'
        return endpoint

    def is_otlp_enabled(self) -> bool:
        """
        Determine if OTLP export should be enabled.

        Returns:
            True if OTLP export is enabled and collector is reachable,
            False otherwise.
        """
        if self._otlp_enabled_raw == "false":
            return False
        elif self._otlp_enabled_raw == "true":
            return True
        else:  # "auto" - check if collector is reachable
            is_reachable = _is_collector_reachable(
                self.otlp_endpoint,
                timeout=self.collector_check_timeout
            )
            if not is_reachable:
                logger.info(
                    f"OTLP collector at {self.otlp_endpoint} is not reachable. "
                    "OTLP export disabled. Set OTEL_EXPORTER_OTLP_ENABLED=true to force enable."
                )
                _suppress_grpc_logging()
            return is_reachable


class OTelManager:
    """
    OpenTelemetry Manager for LLM Attack Lab

    Handles initialization and management of:
    - Tracers for distributed tracing
    - Meters for metrics collection
    - Export to OTLP collector and Prometheus
    """

    def __init__(self, config: Optional[OTelConfig] = None):
        self.config = config or OTelConfig()
        self._tracer = None
        self._meter = None
        self._initialized = False
        self._prometheus_port_actual: Optional[int] = None
        self._otlp_enabled: Optional[bool] = None  # Cached result of collector check

        # Prometheus metrics (local)
        self._prom_metrics: Dict[str, Any] = {}

    def initialize(self) -> bool:
        """Initialize OpenTelemetry providers"""
        if self._initialized:
            return True

        if not OTEL_AVAILABLE:
            logger.warning("OpenTelemetry packages not available. Running without OTEL.")
            self._initialize_prometheus_only()
            return False

        # Check if OTLP collector is available (cache the result)
        self._otlp_enabled = self.config.is_otlp_enabled()

        try:
            # Create resource
            resource = Resource.create({
                SERVICE_NAME: self.config.service_name,
                SERVICE_VERSION: self.config.service_version,
                "deployment.environment": os.getenv("ENVIRONMENT", "development"),
            })

            # Initialize tracing (with OTLP export if collector is available)
            if self.config.enable_tracing:
                self._init_tracing(resource)

            # Initialize metrics (with OTLP export if collector is available)
            if self.config.enable_metrics:
                self._init_metrics(resource)

            # Start Prometheus endpoint (always available as fallback)
            self._init_prometheus()

            self._initialized = True
            if self._otlp_enabled:
                logger.info(f"OpenTelemetry initialized for {self.config.service_name} with OTLP export")
            else:
                logger.info(f"OpenTelemetry initialized for {self.config.service_name} (Prometheus-only mode)")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize OpenTelemetry: {e}")
            self._initialize_prometheus_only()
            return False

    def _init_tracing(self, resource):
        """Initialize tracing provider with retry configuration"""
        tracer_provider = TracerProvider(resource=resource)

        # Only configure OTLP exporter if collector is available
        if self._otlp_enabled:
            try:
                # Configure OTLP exporter with timeout
                otlp_exporter = OTLPSpanExporter(
                    endpoint=self.config.otlp_endpoint,
                    insecure=True,
                    timeout=self.config.otlp_timeout_seconds,
                )

                # Configure BatchSpanProcessor with retry-friendly settings
                span_processor = BatchSpanProcessor(
                    otlp_exporter,
                    max_queue_size=self.config.max_queue_size,
                    max_export_batch_size=self.config.max_export_batch_size,
                    schedule_delay_millis=self.config.schedule_delay_millis,
                    export_timeout_millis=self.config.export_timeout_millis,
                )
                tracer_provider.add_span_processor(span_processor)
                logger.info(
                    f"OTLP trace exporter configured: endpoint={self.config.otlp_endpoint}, "
                    f"timeout={self.config.otlp_timeout_seconds}s, queue_size={self.config.max_queue_size}"
                )
            except Exception as e:
                logger.warning(f"Could not connect to OTLP endpoint for tracing: {e}")

        trace.set_tracer_provider(tracer_provider)
        self._tracer = trace.get_tracer(self.config.service_name)

    def _init_metrics(self, resource):
        """Initialize metrics provider with retry configuration"""
        # Only configure OTLP exporter if collector is available
        if self._otlp_enabled:
            try:
                # Configure OTLP metric exporter with timeout
                otlp_metric_exporter = OTLPMetricExporter(
                    endpoint=self.config.otlp_endpoint,
                    insecure=True,
                    timeout=self.config.otlp_timeout_seconds,
                )

                # Configure PeriodicExportingMetricReader with retry-friendly settings
                metric_reader = PeriodicExportingMetricReader(
                    otlp_metric_exporter,
                    export_interval_millis=self.config.metrics_export_interval_millis,
                    export_timeout_millis=self.config.export_timeout_millis,
                )
                meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
                logger.info(
                    f"OTLP metric exporter configured: endpoint={self.config.otlp_endpoint}, "
                    f"timeout={self.config.otlp_timeout_seconds}s, interval={self.config.metrics_export_interval_millis}ms"
                )
            except Exception as e:
                logger.warning(f"Could not create OTLP metric exporter: {e}")
                meter_provider = MeterProvider(resource=resource)
        else:
            # No OTLP export - create MeterProvider without exporters
            meter_provider = MeterProvider(resource=resource)

        metrics.set_meter_provider(meter_provider)
        self._meter = metrics.get_meter(self.config.service_name)

    def _find_available_port(self) -> Optional[int]:
        """Find an available port for Prometheus metrics server"""
        base_port = self.config.prometheus_port

        # First, try the configured port
        if _is_port_available(base_port):
            return base_port

        # If auto port selection is disabled, return None
        if not self.config.prometheus_port_auto:
            logger.warning(
                f"Port {base_port} is already in use and PROMETHEUS_PORT_AUTO is disabled. "
                "Prometheus metrics server will not start."
            )
            return None

        # Try alternative ports within the configured range
        logger.info(f"Port {base_port} is in use, searching for available port...")
        for offset in range(1, self.config.prometheus_port_range + 1):
            candidate_port = base_port + offset
            if _is_port_available(candidate_port):
                logger.info(f"Found available port: {candidate_port}")
                return candidate_port

        logger.warning(
            f"No available port found in range {base_port}-{base_port + self.config.prometheus_port_range}. "
            "Prometheus metrics server will not start."
        )
        return None

    def _init_prometheus(self):
        """Initialize Prometheus metrics endpoint"""
        if not PROMETHEUS_AVAILABLE:
            return

        try:
            # Create Prometheus metrics
            self._prom_metrics["attacks_total"] = Counter(
                "llm_attacks_total",
                "Total number of attack simulations",
                ["attack_type", "success", "detected"]
            )
            self._prom_metrics["attack_duration"] = Histogram(
                "llm_attack_duration_seconds",
                "Attack simulation duration",
                ["attack_type"],
                buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
            )
            self._prom_metrics["defense_actions"] = Counter(
                "llm_defense_actions_total",
                "Total defense actions taken",
                ["defense_type", "action", "threat_level"]
            )
            self._prom_metrics["requests_total"] = Counter(
                "llm_requests_total",
                "Total requests processed",
                ["endpoint", "status"]
            )
            self._prom_metrics["request_latency"] = Histogram(
                "llm_request_latency_seconds",
                "Request latency",
                ["endpoint"],
                buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
            )
            self._prom_metrics["security_level"] = Gauge(
                "llm_security_level",
                "Current security level (0-4)"
            )
            self._prom_metrics["compromised_status"] = Gauge(
                "llm_compromised_status",
                "System compromise status (0=safe, 1=compromised)"
            )

            # Find an available port
            available_port = self._find_available_port()
            if available_port is None:
                logger.warning("Prometheus metrics server disabled due to port conflict")
                return

            # Start Prometheus HTTP server in a separate thread
            start_prometheus_server(available_port)
            self._prometheus_port_actual = available_port
            logger.info(f"Prometheus metrics server started on port {available_port}")

            # Initialize baseline metrics so Grafana shows data immediately
            self._initialize_baseline_metrics()

        except Exception as e:
            logger.error(f"Failed to start Prometheus server: {e}")

    def _initialize_baseline_metrics(self):
        """Initialize metrics with baseline values so Grafana dashboards show data immediately"""
        # Initialize gauges with default values
        if "security_level" in self._prom_metrics:
            self._prom_metrics["security_level"].set(2)  # MEDIUM

        if "compromised_status" in self._prom_metrics:
            self._prom_metrics["compromised_status"].set(0)  # Not compromised

        # Initialize counters with 0 by accessing them (creates the time series)
        attack_types = ["prompt_injection", "jailbreak", "data_poisoning", "model_extraction", "membership_inference"]
        for attack_type in attack_types:
            if "attacks_total" in self._prom_metrics:
                # Access all label combinations to create time series
                self._prom_metrics["attacks_total"].labels(
                    attack_type=attack_type, success="false", detected="false"
                )
                self._prom_metrics["attacks_total"].labels(
                    attack_type=attack_type, success="true", detected="true"
                )

            if "attack_duration" in self._prom_metrics:
                self._prom_metrics["attack_duration"].labels(attack_type=attack_type)

        # Initialize defense actions with baseline data
        defense_types = ["input_sanitizer", "output_filter", "guardrails"]
        actions = ["block", "warn", "allow"]
        threat_levels = ["low", "medium", "high", "critical"]
        # Baseline distribution: more allows, fewer blocks, based on threat level
        baseline_counts = {
            ("allow", "low"): 10,
            ("allow", "medium"): 5,
            ("warn", "low"): 3,
            ("warn", "medium"): 4,
            ("warn", "high"): 2,
            ("block", "medium"): 1,
            ("block", "high"): 2,
            ("block", "critical"): 3,
        }
        for defense in defense_types:
            for action in actions:
                for level in threat_levels:
                    if "defense_actions" in self._prom_metrics:
                        counter = self._prom_metrics["defense_actions"].labels(
                            defense_type=defense, action=action, threat_level=level
                        )
                        # Add baseline increments for realistic initial data
                        count = baseline_counts.get((action, level), 0)
                        if count > 0:
                            counter.inc(count)

        # Initialize request metrics
        endpoints = ["/api/simulate", "/api/status", "/stress/populate", "/stress/stress"]
        for endpoint in endpoints:
            if "requests_total" in self._prom_metrics:
                self._prom_metrics["requests_total"].labels(endpoint=endpoint, status="200")
            if "request_latency" in self._prom_metrics:
                self._prom_metrics["request_latency"].labels(endpoint=endpoint)

        logger.info("Baseline metrics initialized for Grafana dashboards")

    def _initialize_prometheus_only(self):
        """Fallback: Initialize only Prometheus metrics"""
        self._init_prometheus()
        self._initialized = True

    @property
    def tracer(self):
        """Get the tracer instance"""
        return self._tracer

    @property
    def meter(self):
        """Get the meter instance"""
        return self._meter

    @property
    def prometheus_port(self) -> Optional[int]:
        """Get the actual Prometheus port in use (may differ from config if port was auto-assigned)"""
        return self._prometheus_port_actual

    @property
    def otlp_enabled(self) -> bool:
        """Check if OTLP export is enabled and collector is reachable"""
        return self._otlp_enabled or False

    @contextmanager
    def trace_span(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        """Context manager for creating traced spans"""
        if self._tracer:
            with self._tracer.start_as_current_span(name) as span:
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, str(value))
                try:
                    yield span
                except Exception as e:
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                    raise
        else:
            yield None

    def record_attack(self, attack_type: str, success: bool, detected: bool, duration: float):
        """Record attack metrics"""
        # Prometheus metrics
        if "attacks_total" in self._prom_metrics:
            self._prom_metrics["attacks_total"].labels(
                attack_type=attack_type,
                success=str(success).lower(),
                detected=str(detected).lower()
            ).inc()

        if "attack_duration" in self._prom_metrics:
            self._prom_metrics["attack_duration"].labels(
                attack_type=attack_type
            ).observe(duration)

        # OTEL metrics
        if self._meter:
            counter = self._meter.create_counter(
                "attacks_total",
                description="Total attack simulations"
            )
            counter.add(1, {"attack_type": attack_type, "success": str(success), "detected": str(detected)})

    def record_defense(self, defense_type: str, action: str, threat_level: str):
        """Record defense action metrics"""
        if "defense_actions" in self._prom_metrics:
            self._prom_metrics["defense_actions"].labels(
                defense_type=defense_type,
                action=action,
                threat_level=threat_level
            ).inc()

    def record_request(self, endpoint: str, status: str, duration: float):
        """Record request metrics"""
        if "requests_total" in self._prom_metrics:
            self._prom_metrics["requests_total"].labels(
                endpoint=endpoint,
                status=status
            ).inc()

        if "request_latency" in self._prom_metrics:
            self._prom_metrics["request_latency"].labels(
                endpoint=endpoint
            ).observe(duration)

    def set_security_level(self, level: int):
        """Update security level gauge"""
        if "security_level" in self._prom_metrics:
            self._prom_metrics["security_level"].set(level)

    def set_compromised_status(self, compromised: bool):
        """Update compromised status gauge"""
        if "compromised_status" in self._prom_metrics:
            self._prom_metrics["compromised_status"].set(1 if compromised else 0)


# Global OTel manager instance
_otel_manager: Optional[OTelManager] = None


def get_otel_manager() -> OTelManager:
    """Get or create the global OTel manager"""
    global _otel_manager
    if _otel_manager is None:
        _otel_manager = OTelManager()
    return _otel_manager


def init_telemetry() -> OTelManager:
    """Initialize and return the telemetry manager"""
    manager = get_otel_manager()
    manager.initialize()
    return manager
