# Kubernetes Deployment Guide

> Deploying iAttack Lab on Kubernetes with the full CNCF security stack

This guide covers production deployment of the iAttack Lab matching the architecture
from the CNCF Meetup presentation (slides 13-16 + reinforcement slides 1-7).

---

## Prerequisites

- Kubernetes cluster v1.28+
- Helm v3.12+
- kubectl configured
- (Optional) GPU nodes with NVIDIA drivers for DCGM monitoring

## Namespace Architecture

```
ml-serving  (PSS: restricted)    ← Application + inference pods
monitoring  (PSS: baseline)      ← VM, Grafana, OTel, vmalert, DCGM
security    (PSS: privileged)    ← Falco (needs eBPF access)
kyverno     (PSS: baseline)      ← Admission controller
```

## Deployment Steps

### 1. Automated Deployment

```bash
./scripts/deploy-k8s.sh
```

### 2. Manual Helm Deployment

```bash
# Namespaces
kubectl apply -f k8s/namespaces/namespaces.yaml

# Monitoring stack
helm install vmsingle vm/victoria-metrics-single -n monitoring
helm install vmalert vm/victoria-metrics-alert -n monitoring \
  --set server.datasource.url="http://vmsingle-victoria-metrics-single-server:8428"
helm install grafana grafana/grafana -n monitoring
helm install otel-collector open-telemetry/opentelemetry-collector -n monitoring

# Security stack
helm install falco falcosecurity/falco -n security \
  --values config/falco/falco-values.yaml
helm install kyverno kyverno/kyverno -n kyverno

# Application
kubectl apply -f k8s/ml-serving/deployment.yaml
kubectl apply -f k8s/ml-serving/networkpolicies.yaml
```

### 3. vmalert Rules

```bash
kubectl create configmap vmalert-rules -n monitoring \
  --from-file=config/vmalert/ml-security-rules.yaml
```

### 4. Seccomp Profile Distribution

```bash
# Copy to each node (use DaemonSet in production)
scp config/seccomp/seccomp-ml-inference.json \
  node:/var/lib/kubelet/seccomp/profiles/
```

### 5. DCGM Exporter (GPU nodes only)

The DCGM DaemonSet is included in `k8s/monitoring/stack.yaml` and only schedules
on nodes with `nvidia.com/gpu.present: "true"` label.

## Security Verification

### Check Kyverno policies

```bash
kubectl get cpol
kubectl describe cpol verify-ml-image-signatures
```

### Check Falco alerts

```bash
kubectl logs -n security -l app.kubernetes.io/name=falco --tail=50
```

### Check vmalert rules

```bash
kubectl port-forward -n monitoring svc/vmalert 8880:8880
curl http://localhost:8880/api/v1/rules | jq '.data.groups[].rules[].name'
```

### Check NetworkPolicies

```bash
kubectl get networkpolicies -n ml-serving
kubectl describe networkpolicy default-deny-all -n ml-serving
```

## Scaling for Production

### VictoriaMetrics Cluster Mode

For high-availability, use vmcluster instead of vmsingle:

```bash
helm install vmcluster vm/victoria-metrics-cluster -n monitoring \
  --set vmselect.replicaCount=2 \
  --set vminsert.replicaCount=2 \
  --set vmstorage.replicaCount=3
```

### GPU Autoscaling with KEDA

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: llm-attack-lab-scaler
  namespace: ml-serving
spec:
  scaleTargetRef:
    name: llm-attack-lab
  minReplicaCount: 1
  maxReplicaCount: 10
  triggers:
    - type: prometheus
      metadata:
        serverAddress: http://victoriametrics.monitoring.svc:8428
        metricName: ml_queue_depth
        threshold: "50"
        query: ml_queue_depth{namespace="ml-serving"}
```

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No metrics in VM | `kubectl logs otel-collector -n monitoring` |
| Falco no events | `kubectl logs falco -n security` — check eBPF driver |
| Kyverno blocks deployment | `kubectl get events -n ml-serving` — check policy violations |
| Init container fails | `kubectl describe pod -n ml-serving` — model hash mismatch? |
| DCGM no data | Verify GPU node label: `nvidia.com/gpu.present=true` |
