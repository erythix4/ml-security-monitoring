"""
Web Dashboard for LLM Attack Lab

Provides a visual interface for exploring and simulating LLM attacks.
Includes OpenTelemetry integration for observability.
"""

import os
import json
import time
import socket
from typing import Optional
from flask import Flask, render_template, request, jsonify, Response
from llm_attack_lab.core.llm_simulator import LLMSimulator, SecurityLevel
from llm_attack_lab.attacks import ATTACK_REGISTRY
from llm_attack_lab.monitoring.metrics import get_metrics_collector
from llm_attack_lab.monitoring.logger import get_logger
from llm_attack_lab.testing import get_test_runner, stream_test_events
from llm_attack_lab.testing import get_stress_runner, stream_stress_events

# OpenTelemetry integration
try:
    from llm_attack_lab.monitoring.otel import init_telemetry, get_otel_manager
    OTEL_ENABLED = True
except ImportError:
    OTEL_ENABLED = False
    init_telemetry = None
    get_otel_manager = None

# Security Metrics integration
try:
    from llm_attack_lab.monitoring.security_metrics import get_security_metrics
    SECURITY_METRICS_ENABLED = True
except ImportError:
    SECURITY_METRICS_ENABLED = False
    get_security_metrics = None

# Metrics Simulator integration
try:
    from llm_attack_lab.monitoring.metrics_simulator import (
        get_metrics_simulator,
        start_metrics_simulation,
        stop_metrics_simulation
    )
    METRICS_SIMULATOR_ENABLED = True
except ImportError:
    METRICS_SIMULATOR_ENABLED = False
    get_metrics_simulator = None
    start_metrics_simulation = None
    stop_metrics_simulation = None

# Flask instrumentation
try:
    from opentelemetry.instrumentation.flask import FlaskInstrumentor
    FLASK_INSTRUMENTATION = True
except ImportError:
    FLASK_INSTRUMENTATION = False

app = Flask(__name__, template_folder='templates', static_folder='static')

# Initialize OpenTelemetry if available
otel_manager = None
if OTEL_ENABLED:
    try:
        otel_manager = init_telemetry()
        if FLASK_INSTRUMENTATION:
            FlaskInstrumentor().instrument_app(app)
    except Exception as e:
        print(f"Warning: Could not initialize OpenTelemetry: {e}")

# Initialize Security Metrics if available
security_metrics = None
if SECURITY_METRICS_ENABLED:
    try:
        security_metrics = get_security_metrics()
        print("Security metrics collector initialized")
    except Exception as e:
        print(f"Warning: Could not initialize Security Metrics: {e}")

# Global instances
simulator = LLMSimulator()
metrics = get_metrics_collector()
logger = get_logger("web")


@app.route('/')
def index():
    """Main dashboard page - redirects to dashboard"""
    return render_template('dashboard.html')


@app.route('/classic')
def classic():
    """Classic/legacy interface"""
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    """Advanced security dashboard"""
    return render_template('dashboard.html')


@app.route('/api/status')
def get_status():
    """Get current simulator status"""
    status = simulator.get_status()

    # Update OTel gauges
    if otel_manager:
        otel_manager.set_security_level(SecurityLevel[status['security_level']].value)
        otel_manager.set_compromised_status(status['is_compromised'])

    return jsonify(status)


@app.route('/api/attacks')
def get_attacks():
    """Get list of available attacks"""
    attacks = []
    for key, attack_class in ATTACK_REGISTRY.items():
        attack = attack_class()
        attacks.append({
            'id': key,
            'name': attack.name,
            'description': attack.description,
            'category': attack.category,
            'severity': attack.severity,
        })
    return jsonify(attacks)


@app.route('/api/attack/<attack_id>')
def get_attack_details(attack_id):
    """Get details for a specific attack"""
    if attack_id not in ATTACK_REGISTRY:
        return jsonify({'error': 'Attack not found'}), 404

    attack_class = ATTACK_REGISTRY[attack_id]
    attack = attack_class()

    return jsonify({
        'id': attack_id,
        'name': attack.name,
        'description': attack.description,
        'category': attack.category,
        'severity': attack.severity,
        'payloads': attack.get_payloads(),
        'educational': attack.get_educational_content(),
    })


@app.route('/api/simulate', methods=['POST'])
def simulate():
    """Simulate a prompt input"""
    data = request.get_json()
    user_input = data.get('input', '')
    security_level = data.get('security_level', 'MEDIUM')

    # Set security level
    try:
        simulator.set_security_level(SecurityLevel[security_level])
    except KeyError:
        pass

    # Process input with timing and optional tracing
    start_time = time.time()

    if otel_manager:
        with otel_manager.trace_span("simulate_attack", {"security_level": security_level}):
            response, metadata = simulator.process_input(user_input)
    else:
        response, metadata = simulator.process_input(user_input)

    duration = time.time() - start_time

    # Record metrics
    metrics.record_request(duration, blocked=metadata.get('compromised', False))

    # Record OTel metrics
    if otel_manager:
        otel_manager.record_request("/api/simulate", "200", duration)
        if metadata.get('attacks_detected'):
            for attack in metadata['attacks_detected']:
                otel_manager.record_attack(
                    attack_type=attack['type'],
                    success=metadata.get('compromised', False),
                    detected=True,
                    duration=duration
                )

    # Record security metrics for advanced monitoring
    if security_metrics:
        # Record API query
        security_metrics.record_api_query(
            user_id="web_user",
            ip_address=request.remote_addr or "unknown",
            endpoint="/api/simulate"
        )

        # Record prompt injection score based on detection
        if metadata.get('attacks_detected'):
            for attack in metadata['attacks_detected']:
                # High score if attack was detected
                injection_score = attack.get('confidence', 0.85)
                security_metrics.record_prompt_injection_score(
                    score=injection_score,
                    model_name="llm-simulator",
                    detection_method="rule_based"
                )
                # Record security alert
                security_metrics.record_security_alert(
                    alert_type=attack['type'],
                    severity="high" if metadata.get('compromised') else "medium",
                    pattern="llm"
                )
                # Record policy violation if compromised
                if metadata.get('compromised'):
                    security_metrics.record_policy_violation(
                        model_name="llm-simulator",
                        violation_type=attack['type'],
                        severity="critical"
                    )
        else:
            # Low injection score for clean requests
            security_metrics.record_prompt_injection_score(
                score=0.1,
                model_name="llm-simulator",
                detection_method="rule_based"
            )

    if metadata.get('attacks_detected'):
        for attack in metadata['attacks_detected']:
            metrics.increment("web_attacks_detected", labels={"type": attack['type']})

    return jsonify({
        'response': response,
        'metadata': metadata,
    })


@app.route('/api/security-levels')
def get_security_levels():
    """Get available security levels"""
    levels = []
    for level in SecurityLevel:
        levels.append({
            'name': level.name,
            'value': level.value,
            'description': _get_level_description(level),
        })
    return jsonify(levels)


def _get_level_description(level: SecurityLevel) -> str:
    """Get description for security level"""
    descriptions = {
        SecurityLevel.NONE: "No protection - vulnerable to all attacks",
        SecurityLevel.LOW: "Basic keyword filtering only",
        SecurityLevel.MEDIUM: "Injection detection enabled",
        SecurityLevel.HIGH: "Advanced sanitization and blocking",
        SecurityLevel.MAXIMUM: "Full blocking on any detection",
    }
    return descriptions.get(level, "Unknown")


@app.route('/api/reset', methods=['POST'])
def reset():
    """Reset the simulator"""
    simulator.reset()
    metrics.reset()
    return jsonify({'status': 'ok', 'message': 'Simulator reset'})


@app.route('/api/metrics')
def get_metrics():
    """Get all monitoring metrics"""
    return jsonify(metrics.get_all_metrics())


@app.route('/api/metrics/attacks')
def get_attack_metrics():
    """Get attack-specific metrics"""
    return jsonify(metrics.get_attack_summary())


@app.route('/api/metrics/defenses')
def get_defense_metrics():
    """Get defense-specific metrics"""
    return jsonify(metrics.get_defense_summary())


@app.route('/api/metrics/prometheus')
def get_prometheus_metrics():
    """Export metrics in Prometheus format"""
    return metrics.export_prometheus(), 200, {'Content-Type': 'text/plain'}


@app.route('/api/dashboard/summary')
def get_dashboard_summary():
    """Get comprehensive dashboard summary"""
    attack_summary = metrics.get_attack_summary()
    defense_summary = metrics.get_defense_summary()
    status = simulator.get_status()

    return jsonify({
        'status': status,
        'attacks': attack_summary,
        'defenses': defense_summary,
        'uptime': metrics.get_all_metrics().get('uptime_seconds', 0),
        'timestamp': time.time()
    })


@app.route('/api/attack-types')
def get_attack_type_stats():
    """Get statistics broken down by attack type"""
    all_metrics = metrics.get_all_metrics()
    counters = all_metrics.get('counters', {})

    attack_types = ['prompt_injection', 'jailbreak', 'data_poisoning', 'model_extraction', 'membership_inference']
    stats = []

    for attack_type in attack_types:
        total_key = f'attacks_total{{attack_type="{attack_type}"}}'
        success_key = f'attacks_successful{{attack_type="{attack_type}"}}'
        detected_key = f'attacks_detected{{attack_type="{attack_type}"}}'

        total = counters.get(total_key, 0)
        successful = counters.get(success_key, 0)
        detected = counters.get(detected_key, 0)

        stats.append({
            'type': attack_type,
            'display_name': attack_type.replace('_', ' ').title(),
            'total': int(total),
            'successful': int(successful),
            'detected': int(detected),
            'success_rate': (successful / total * 100) if total > 0 else 0,
            'detection_rate': (detected / total * 100) if total > 0 else 0
        })

    return jsonify(stats)


# ============================================================================
# Test Streaming Endpoints (SSE)
# ============================================================================

@app.route('/api/tests/stream')
def stream_tests():
    """Server-Sent Events endpoint for streaming test results"""
    def generate():
        for event in stream_test_events():
            yield event

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        }
    )


@app.route('/api/tests/start', methods=['POST'])
def start_tests():
    """Start a single test run"""
    data = request.get_json() or {}
    test_args = data.get('args', [])
    runner = get_test_runner()
    result = runner.start_single_run(test_args)
    return jsonify(result)


@app.route('/api/tests/start-continuous', methods=['POST'])
def start_continuous_tests():
    """Start continuous test running

    JSON body options:
        interval: Time between runs in seconds (default 30, ignored if infinite=true)
        max_duration: Maximum total duration in seconds (0 = no limit)
        infinite: If true, run tests continuously without interval
        args: Additional pytest arguments
    """
    data = request.get_json() or {}
    interval = data.get('interval', 30.0)
    max_duration = data.get('max_duration', 0)
    infinite = data.get('infinite', False)
    test_args = data.get('args', [])
    runner = get_test_runner()
    result = runner.start_continuous(
        interval=interval,
        test_args=test_args,
        max_duration=max_duration,
        infinite=infinite
    )
    return jsonify(result)


@app.route('/api/tests/stop', methods=['POST'])
def stop_tests():
    """Stop continuous test running"""
    runner = get_test_runner()
    result = runner.stop()
    return jsonify(result)


@app.route('/api/tests/status')
def test_status():
    """Get current test runner status"""
    runner = get_test_runner()
    return jsonify(runner.get_status())


# ============================================================================
# Continuous Stress Testing Endpoints
# ============================================================================

@app.route('/api/stress/stream')
def stream_stress():
    """Server-Sent Events endpoint for streaming stress test events"""
    def generate():
        for event in stream_stress_events():
            yield event

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        }
    )


@app.route('/api/stress/start', methods=['POST'])
def start_stress():
    """Start continuous stress testing

    JSON body options:
        populate_count: Number of initial population requests (default 100)
        stress_batch_size: Requests per stress batch (default 10)
        stress_delay: Delay between batches in seconds (default 0.1)
        workers: Number of concurrent workers (default 5)
        attack_ratio: Ratio of attacks vs safe requests (default 0.7)
    """
    data = request.get_json() or {}
    runner = get_stress_runner()
    result = runner.start(config=data)
    return jsonify(result)


@app.route('/api/stress/stop', methods=['POST'])
def stop_stress():
    """Stop continuous stress testing"""
    runner = get_stress_runner()
    result = runner.stop()
    return jsonify(result)


@app.route('/api/stress/status')
def stress_status():
    """Get current stress runner status"""
    runner = get_stress_runner()
    return jsonify(runner.get_status())


# ============================================================================
# Metrics Simulator Endpoints
# ============================================================================

@app.route('/api/simulator/start', methods=['POST'])
def start_simulator():
    """Start the security metrics simulator"""
    if not METRICS_SIMULATOR_ENABLED or not start_metrics_simulation:
        return jsonify({'error': 'Metrics simulator not available'}), 503

    data = request.get_json() or {}
    interval = data.get('interval', 1.0)

    try:
        start_metrics_simulation(interval)
        return jsonify({'status': 'started', 'interval': interval})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulator/stop', methods=['POST'])
def stop_simulator():
    """Stop the security metrics simulator"""
    if not METRICS_SIMULATOR_ENABLED or not stop_metrics_simulation:
        return jsonify({'error': 'Metrics simulator not available'}), 503

    try:
        stop_metrics_simulation()
        return jsonify({'status': 'stopped'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulator/status')
def simulator_status():
    """Get the metrics simulator status"""
    if not METRICS_SIMULATOR_ENABLED or not get_metrics_simulator:
        return jsonify({
            'available': False,
            'running': False
        })

    try:
        sim = get_metrics_simulator()
        return jsonify({
            'available': True,
            'running': sim._running,
            'in_attack_wave': sim._in_attack_wave,
            'wave_type': sim._wave_type,
            'threat_level': sim._current_threat_level
        })
    except Exception as e:
        return jsonify({
            'available': True,
            'running': False,
            'error': str(e)
        })


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'llm-attack-lab',
        'otel_enabled': OTEL_ENABLED,
        'metrics_simulator_enabled': METRICS_SIMULATOR_ENABLED,
    })


@app.route('/ready')
def ready():
    """Readiness check endpoint"""
    return jsonify({'status': 'ready'})


def _is_port_available(port: int, host: str = "0.0.0.0") -> bool:
    """Check if a port is available for binding"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def _find_available_port(base_port: int, host: str = "0.0.0.0", port_range: int = 10) -> Optional[int]:
    """Find an available port starting from base_port"""
    if _is_port_available(base_port, host):
        return base_port

    print(f"Port {base_port} is in use, searching for available port...")
    for offset in range(1, port_range + 1):
        candidate_port = base_port + offset
        if _is_port_available(candidate_port, host):
            print(f"Found available port: {candidate_port}")
            return candidate_port

    return None


def run_web_server(host='0.0.0.0', port=None, debug=None, auto_stress=None):
    """Run the web server

    Args:
        host: Host to bind to (default: 0.0.0.0)
        port: Port to bind to (default: from WEB_SERVER_PORT env var or 8081)
        debug: Enable debug mode (default: from FLASK_DEBUG env var)
        auto_stress: Auto-start stress testing (default: from AUTO_STRESS env var)

    Environment variables:
        WEB_SERVER_PORT: Default port (default: 8081)
        WEB_SERVER_PORT_AUTO: Enable auto port selection if default is busy (default: true)
        WEB_SERVER_PORT_RANGE: Range of ports to try (default: 10)
        FLASK_DEBUG: Enable debug mode (default: false)
        AUTO_STRESS: Auto-start stress testing on startup (default: false)
        AUTO_STRESS_DELAY: Delay before auto-starting stress test in seconds (default: 2)
    """
    # Use environment variable for port, default to 8081
    if port is None:
        port = int(os.getenv('WEB_SERVER_PORT', '8081'))

    # Use environment variable for debug mode, default to False in production
    if debug is None:
        debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

    # Check if auto port selection is enabled
    port_auto = os.getenv('WEB_SERVER_PORT_AUTO', 'true').lower() == 'true'
    port_range = int(os.getenv('WEB_SERVER_PORT_RANGE', '10'))

    # Find available port
    actual_port = port
    if port_auto:
        actual_port = _find_available_port(port, host, port_range)
        if actual_port is None:
            print(f"Error: No available port found in range {port}-{port + port_range}")
            print(f"Set WEB_SERVER_PORT to a different port or increase WEB_SERVER_PORT_RANGE")
            return
    elif not _is_port_available(port, host):
        print(f"Error: Port {port} is already in use")
        print(f"Set WEB_SERVER_PORT to a different port or enable auto selection with WEB_SERVER_PORT_AUTO=true")
        return

    print(f"Starting LLM Attack Lab Dashboard on http://{host}:{actual_port}")
    print(f"OpenTelemetry enabled: {OTEL_ENABLED}")
    if OTEL_ENABLED and otel_manager:
        prom_port = otel_manager.prometheus_port
        if prom_port:
            print(f"Prometheus metrics available on port {prom_port}")
        else:
            print("Prometheus metrics server not started (port conflict or disabled)")

    # Check for auto-stress mode
    if auto_stress is None:
        auto_stress = os.getenv('AUTO_STRESS', 'false').lower() == 'true'

    if auto_stress:
        auto_stress_delay = float(os.getenv('AUTO_STRESS_DELAY', '2'))
        print(f"Auto-stress mode enabled, will start in {auto_stress_delay}s")

        def _auto_start_stress():
            time.sleep(auto_stress_delay)
            runner = get_stress_runner()
            config = {
                "populate_count": int(os.getenv('AUTO_STRESS_POPULATE', '50')),
                "stress_batch_size": int(os.getenv('AUTO_STRESS_BATCH', '5')),
                "stress_delay": float(os.getenv('AUTO_STRESS_DELAY_BATCH', '0.5')),
                "workers": int(os.getenv('AUTO_STRESS_WORKERS', '3')),
                "attack_ratio": float(os.getenv('AUTO_STRESS_ATTACK_RATIO', '0.7')),
            }
            print(f"Auto-starting stress test with config: {config}")
            runner.start(config)

        import threading
        stress_thread = threading.Thread(target=_auto_start_stress, daemon=True)
        stress_thread.start()

    # Check for metrics simulator auto-start
    metrics_simulator_enabled = os.getenv('METRICS_SIMULATOR', 'true').lower() == 'true'
    if metrics_simulator_enabled and METRICS_SIMULATOR_ENABLED and start_metrics_simulation:
        simulator_interval = float(os.getenv('METRICS_SIMULATOR_INTERVAL', '1.0'))
        print(f"Starting security metrics simulator (interval: {simulator_interval}s)")
        start_metrics_simulation(simulator_interval)

    # threaded=True is REQUIRED for SSE streaming to work properly
    app.run(host=host, port=actual_port, debug=debug, threaded=True)


if __name__ == '__main__':
    run_web_server()
