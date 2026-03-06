"""
ML Security Exporter for Prometheus

This module provides a Prometheus exporter for ML security metrics.
Integrate it into your inference pipeline to export security-relevant metrics.

Usage:
    from ml_security_exporter import MLSecurityExporter
    
    exporter = MLSecurityExporter(model_name="fraud-detector-v2")
    exporter.start_server(port=8000)
    
    # In your inference loop:
    exporter.record_prediction(input_data, prediction, confidence)

Author: Samuel Desseaux - Erythix
License: Apache 2.0
"""

import time
import threading
import numpy as np
from typing import Optional, Dict, Any, List
from prometheus_client import (
    Gauge, Counter, Histogram, Summary,
    start_http_server, REGISTRY
)


class MLSecurityExporter:
    """Prometheus exporter for ML security metrics."""
    
    def __init__(
        self,
        model_name: str,
        autoencoder=None,
        embedding_model=None,
        training_centroids: Optional[np.ndarray] = None,
        injection_classifier=None
    ):
        """
        Initialize the ML Security Exporter.
        
        Args:
            model_name: Name of the model being monitored
            autoencoder: Optional autoencoder for reconstruction error
            embedding_model: Optional model to compute embeddings
            training_centroids: Optional centroids from training data
            injection_classifier: Optional prompt injection classifier
        """
        self.model_name = model_name
        self.autoencoder = autoencoder
        self.embedding_model = embedding_model
        self.training_centroids = training_centroids
        self.injection_classifier = injection_classifier
        
        self._init_metrics()
        self._prediction_history: List[Dict] = []
        self._lock = threading.Lock()
    
    def _init_metrics(self):
        """Initialize Prometheus metrics."""
        labels = ['model', 'input_type']
        
        # Anomaly Detection Metrics
        self.reconstruction_error = Gauge(
            'ml_input_reconstruction_error',
            'Autoencoder reconstruction error for input',
            labels
        )
        
        self.embedding_distance = Gauge(
            'ml_embedding_distance_to_centroid',
            'Distance from input embedding to nearest training centroid',
            labels
        )
        
        self.prediction_stability = Gauge(
            'ml_prediction_stability_score',
            'Prediction stability under small perturbations (0-1)',
            labels
        )
        
        self.prediction_confidence = Histogram(
            'ml_prediction_confidence',
            'Distribution of prediction confidence scores',
            ['model'],
            buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99]
        )
        
        # Distribution Drift Metrics
        self.distribution_psi = Gauge(
            'ml_prediction_distribution_psi',
            'Population Stability Index for prediction distribution',
            ['model']
        )
        
        self.predictions_by_class = Counter(
            'ml_predictions_by_class_total',
            'Total predictions by class',
            ['model', 'class']
        )
        
        self.accuracy_by_class = Gauge(
            'ml_accuracy_by_class',
            'Accuracy by class (when ground truth available)',
            ['model', 'class']
        )
        
        # API Behavior Metrics
        self.api_queries = Counter(
            'ml_api_queries_total',
            'Total API queries',
            ['model', 'user_id', 'endpoint']
        )
        
        self.query_latency = Histogram(
            'ml_query_latency_seconds',
            'Query latency in seconds',
            ['model'],
            buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
        )
        
        # Security Event Counters
        self.adversarial_detections = Counter(
            'ml_adversarial_detections_total',
            'Total adversarial input detections',
            ['model', 'detection_type']
        )
        
        self.unstable_predictions = Counter(
            'ml_unstable_predictions_total',
            'Total predictions flagged as unstable',
            ['model']
        )
        
        # LLM-Specific Metrics
        self.prompt_injection_score = Gauge(
            'llm_prompt_injection_score',
            'Prompt injection classifier score (0-1)',
            ['model', 'user_id']
        )
        
        self.system_prompt_similarity = Gauge(
            'llm_prompt_similarity_to_system',
            'Similarity between output and system prompt',
            ['model']
        )
        
        self.policy_violations = Counter(
            'llm_output_policy_violations_total',
            'Content policy violations',
            ['model', 'violation_type']
        )
        
        self.tool_calls = Counter(
            'llm_tool_calls_total',
            'LLM tool/function calls',
            ['model', 'tool', 'user_id', 'status']
        )
    
    def start_server(self, port: int = 8000):
        """Start the Prometheus HTTP server."""
        start_http_server(port)
        print(f"ML Security Exporter started on port {port}")
    
    def record_prediction(
        self,
        input_data: np.ndarray,
        prediction: Any,
        confidence: float,
        user_id: str = "anonymous",
        input_type: str = "default",
        ground_truth: Optional[Any] = None
    ):
        """
        Record a prediction and compute security metrics.
        
        Args:
            input_data: The input to the model
            prediction: The model's prediction
            confidence: Confidence score (0-1)
            user_id: User identifier for rate limiting
            input_type: Type of input for labeling
            ground_truth: Optional ground truth for accuracy
        """
        start_time = time.time()
        
        # Record basic metrics
        self.prediction_confidence.labels(model=self.model_name).observe(confidence)
        self.predictions_by_class.labels(
            model=self.model_name, 
            class_=str(prediction)
        ).inc()
        self.api_queries.labels(
            model=self.model_name,
            user_id=user_id,
            endpoint="predict"
        ).inc()
        
        # Compute reconstruction error if autoencoder available
        if self.autoencoder is not None:
            error = self._compute_reconstruction_error(input_data)
            self.reconstruction_error.labels(
                model=self.model_name,
                input_type=input_type
            ).set(error)
            
            # Check for adversarial pattern
            if error > 2.5 and confidence > 0.95:
                self.adversarial_detections.labels(
                    model=self.model_name,
                    detection_type="high_error_high_confidence"
                ).inc()
        
        # Compute embedding distance if available
        if self.embedding_model is not None and self.training_centroids is not None:
            distance = self._compute_embedding_distance(input_data)
            self.embedding_distance.labels(
                model=self.model_name,
                input_type=input_type
            ).set(distance)
        
        # Record latency
        latency = time.time() - start_time
        self.query_latency.labels(model=self.model_name).observe(latency)
        
        # Store for distribution drift calculation
        with self._lock:
            self._prediction_history.append({
                'prediction': prediction,
                'confidence': confidence,
                'timestamp': time.time()
            })
            # Keep last 10000 predictions
            if len(self._prediction_history) > 10000:
                self._prediction_history = self._prediction_history[-10000:]
    
    def record_llm_request(
        self,
        prompt: str,
        output: str,
        user_id: str = "anonymous",
        tools_called: Optional[List[Dict]] = None
    ):
        """
        Record an LLM request and compute security metrics.
        
        Args:
            prompt: The user prompt
            output: The model output
            user_id: User identifier
            tools_called: List of tools called with status
        """
        # Compute injection score if classifier available
        if self.injection_classifier is not None:
            score = self._compute_injection_score(prompt)
            self.prompt_injection_score.labels(
                model=self.model_name,
                user_id=user_id
            ).set(score)
        
        # Record tool calls
        if tools_called:
            for tool in tools_called:
                self.tool_calls.labels(
                    model=self.model_name,
                    tool=tool.get('name', 'unknown'),
                    user_id=user_id,
                    status=tool.get('status', 'success')
                ).inc()
    
    def _compute_reconstruction_error(self, input_data: np.ndarray) -> float:
        """Compute autoencoder reconstruction error."""
        if self.autoencoder is None:
            return 0.0
        reconstructed = self.autoencoder.predict(input_data.reshape(1, -1))
        error = np.mean((input_data - reconstructed.flatten()) ** 2)
        return float(error)
    
    def _compute_embedding_distance(self, input_data: np.ndarray) -> float:
        """Compute distance to nearest training centroid."""
        if self.embedding_model is None or self.training_centroids is None:
            return 0.0
        embedding = self.embedding_model.transform(input_data.reshape(1, -1))
        distances = np.linalg.norm(self.training_centroids - embedding, axis=1)
        return float(np.min(distances))
    
    def _compute_injection_score(self, prompt: str) -> float:
        """Compute prompt injection score."""
        if self.injection_classifier is None:
            return 0.0
        # Placeholder - integrate your classifier here
        # Example: return self.injection_classifier.predict_proba([prompt])[0][1]
        return 0.0
    
    def compute_distribution_psi(self, reference_distribution: Dict[str, float]):
        """
        Compute Population Stability Index against reference.
        
        Args:
            reference_distribution: Reference class distribution
        """
        with self._lock:
            if len(self._prediction_history) < 100:
                return
            
            # Compute current distribution
            current = {}
            for pred in self._prediction_history[-1000:]:
                cls = str(pred['prediction'])
                current[cls] = current.get(cls, 0) + 1
            
            total = sum(current.values())
            current = {k: v/total for k, v in current.items()}
            
            # Compute PSI
            psi = 0.0
            for cls in set(list(reference_distribution.keys()) + list(current.keys())):
                ref = reference_distribution.get(cls, 0.001)
                cur = current.get(cls, 0.001)
                psi += (cur - ref) * np.log(cur / ref)
            
            self.distribution_psi.labels(model=self.model_name).set(psi)


# Example usage
if __name__ == "__main__":
    # Initialize exporter
    exporter = MLSecurityExporter(model_name="fraud-detector-v2")
    exporter.start_server(port=8000)
    
    # Simulate predictions
    import random
    while True:
        # Simulate normal prediction
        input_data = np.random.randn(10)
        prediction = random.choice([0, 1])
        confidence = random.uniform(0.6, 0.99)
        
        exporter.record_prediction(
            input_data=input_data,
            prediction=prediction,
            confidence=confidence,
            user_id=f"user_{random.randint(1, 100)}"
        )
        
        time.sleep(0.1)
