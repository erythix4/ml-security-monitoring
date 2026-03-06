#!/usr/bin/env python3
"""
ML Security Metrics Stub - Standalone simulator
Generates all metrics from the CNCF Meetup presentation
for demo purposes when the full iAttack app is not available.
"""
from prometheus_client import start_http_server, Counter, Gauge, Histogram
import time, random, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# Start Prometheus metrics on :8000
start_http_server(8000)
print("[STUB] Prometheus metrics on :8000")

# ML Security metrics matching presentation slides
inj_score = Gauge('llm_prompt_injection_score', 'Injection classifier confidence')
recon_err = Gauge('ml_input_reconstruction_error', 'Autoencoder reconstruction error')
pred_conf = Gauge('ml_prediction_confidence', 'Prediction confidence')
embed_dist = Gauge('ml_embedding_distance_to_centroid', 'Embedding distance')
psi = Gauge('ml_prediction_distribution_psi', 'PSI drift score')
api_queries = Counter('ml_api_queries_total', 'API query count', ['source_ip'])
policy_viol = Counter('llm_output_policy_violations_total', 'Policy violations')
tool_calls = Counter('llm_tool_calls_total', 'Tool calls', ['tool', 'user_id'])
queue_depth = Gauge('ml_queue_depth', 'Inference queue depth')
infer_dur = Histogram(
    'ml_inference_duration_seconds', 'Inference latency',
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)
tokens_ps = Gauge('ml_tokens_per_second', 'Token throughput')
similarity = Gauge('llm_prompt_similarity_to_system', 'Similarity to system prompt')
stability = Gauge('ml_prediction_stability_score', 'Prediction stability')


def simulate():
    while True:
        # Normal traffic with occasional attack spikes (~5% chance)
        is_attack = random.random() < 0.05
        inj_score.set(random.uniform(0.85, 0.99) if is_attack else random.uniform(0.01, 0.3))
        recon_err.set(random.uniform(2.5, 4.0) if random.random() < 0.03 else random.uniform(0.5, 1.5))
        pred_conf.set(random.uniform(0.6, 0.95))
        embed_dist.set(random.uniform(3.0, 6.0) if random.random() < 0.05 else random.uniform(0.5, 2.0))
        psi.set(random.uniform(0.2, 0.5) if random.random() < 0.02 else random.uniform(0.01, 0.1))
        api_queries.labels(source_ip='10.0.0.' + str(random.randint(1, 50))).inc(random.randint(1, 5))
        queue_depth.set(random.randint(80, 150) if random.random() < 0.05 else random.randint(0, 20))
        infer_dur.observe(random.uniform(0.02, 0.3))
        tokens_ps.set(random.uniform(50, 200))
        similarity.set(random.uniform(0.9, 0.98) if random.random() < 0.03 else random.uniform(0.1, 0.4))
        stability.set(random.uniform(0.01, 0.1))
        if random.random() > 0.95:
            policy_viol.inc()
        if random.random() > 0.97:
            tool_calls.labels(tool='shell', user_id='user_' + str(random.randint(1, 10))).inc()
        time.sleep(2)


threading.Thread(target=simulate, daemon=True).start()


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok","mode":"metrics-stub"}')

    def log_message(self, *a):
        pass


print("[STUB] Health endpoint on :8081")
print("[STUB] Simulating ML security metrics with attack spikes...")
HTTPServer(('0.0.0.0', 8081), HealthHandler).serve_forever()
