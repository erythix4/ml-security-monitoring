#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# iAttack Lab - Kubernetes Deployment Script
# Tested on: Docker Desktop Kubernetes, kind, minikube
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${CYAN}▶${NC} $1"; }
ok()    { echo -e "${GREEN}✔${NC} $1"; }
warn()  { echo -e "${YELLOW}⚠${NC} $1"; }
fail()  { echo -e "${RED}✘${NC} $1"; exit 1; }

helm_deploy() {
  local name="$1" chart="$2" ns="$3"; shift 3
  if helm status "$name" -n "$ns" >/dev/null 2>&1; then
    warn "$name already installed, upgrading..."
    helm upgrade "$name" "$chart" --namespace "$ns" "$@"
  else
    helm install "$name" "$chart" --namespace "$ns" "$@"
  fi
}

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           iAttack Lab - K8s Deployment                       ║"
echo "║           AI Security Monitoring Stack                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# ── Detect environment ──────────────────────────────────────────────────────
CONTEXT=$(kubectl config current-context 2>/dev/null || echo "unknown")
IS_DOCKER_DESKTOP=false
if [[ "$CONTEXT" == "docker-desktop" ]]; then
  IS_DOCKER_DESKTOP=true
  warn "Docker Desktop detected — Falco will be skipped (no eBPF on macOS VM)"
  echo ""
fi

# ── Pre-flight ──────────────────────────────────────────────────────────────
info "Pre-flight checks..."
command -v kubectl >/dev/null 2>&1 || fail "kubectl not found. Install: brew install kubectl"
command -v helm >/dev/null 2>&1    || fail "helm not found. Install: brew install helm"

if ! kubectl cluster-info >/dev/null 2>&1; then
  fail "No cluster reachable. Enable Kubernetes in Docker Desktop and retry."
fi
ok "Cluster: $CONTEXT"
echo ""

# ── Step 1: Namespaces ──────────────────────────────────────────────────────
info "[1/5] Creating namespaces..."
kubectl apply -f "$ROOT_DIR/k8s/namespaces/namespaces.yaml"
ok "Namespaces ready"
echo ""

# ── Step 2: Helm repos ─────────────────────────────────────────────────────
info "[2/5] Helm repositories..."
helm repo add vm https://victoriametrics.github.io/helm-charts 2>/dev/null || true
helm repo add grafana https://grafana.github.io/helm-charts 2>/dev/null || true
helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
helm repo update >/dev/null 2>&1
ok "Repos updated"
echo ""

# ── Step 3: Monitoring stack ────────────────────────────────────────────────
VM_URL="http://vmsingle-victoria-metrics-single-server:8428"

info "[3/5] VictoriaMetrics..."
helm_deploy vmsingle vm/victoria-metrics-single monitoring \
  --set server.retentionPeriod=30d \
  --set server.resources.requests.memory=256Mi \
  --set server.resources.limits.memory=512Mi \
  --wait --timeout=120s
ok "VictoriaMetrics"

info "vmalert + ML security rules..."
kubectl create configmap vmalert-rules \
  --namespace monitoring \
  --from-file="$ROOT_DIR/config/vmalert/ml-security-rules.yaml" \
  --dry-run=client -o yaml | kubectl apply -f -

helm_deploy vmalert vm/victoria-metrics-alert monitoring \
  --set server.datasource.url="$VM_URL" \
  --set server.remoteRead.url="$VM_URL" \
  --set server.remoteWrite.url="$VM_URL" \
  --set "server.extraArgs.rule=/config/*.yaml" \
  --set server.resources.requests.memory=64Mi \
  --wait --timeout=120s
ok "vmalert with ML rules"

info "vmagent (metrics scraping)..."
helm_deploy vmagent vm/victoria-metrics-agent monitoring \
  -f "$ROOT_DIR/config/vmagent-k8s-values.yaml" \
  --wait --timeout=120s
ok "vmagent scraping llm-attack-lab:8000"

info "Grafana + dashboards..."

# Single ConfigMap with ALL dashboard JSON files
kubectl create configmap grafana-dashboards \
  --namespace monitoring \
  --from-file="$ROOT_DIR/config/grafana/dashboards/" \
  --dry-run=client -o yaml | kubectl apply -f -
ok "Dashboard ConfigMap created ($(ls "$ROOT_DIR"/config/grafana/dashboards/*.json | wc -l | tr -d ' ') dashboards)"

helm_deploy grafana grafana/grafana monitoring \
  -f "$ROOT_DIR/config/grafana/grafana-values.yaml" \
  --wait --timeout=180s
ok "Grafana running with dashboards"
echo ""

# ── Step 4: Falco (skip on Docker Desktop) ──────────────────────────────────
info "[4/5] Falco runtime security..."
if $IS_DOCKER_DESKTOP; then
  warn "Skipped — Docker Desktop macOS lacks kernel support for eBPF"
  warn "Falco ML rules are in config/falco/ for use on a real cluster"
else
  helm_deploy falco falcosecurity/falco security \
    --set driver.kind=modern_ebpf \
    --set falcosidekick.enabled=true \
    --set collectors.containerd.enabled=true \
    --set collectors.docker.enabled=false \
    --set resources.requests.memory=128Mi \
    --wait --timeout=300s \
    && ok "Falco deployed" \
    || warn "Falco failed — may need privileged access. Continuing."

  kubectl create configmap falco-ml-rules \
    --namespace security \
    --from-file="$ROOT_DIR/config/falco/falco_ml_rules.yaml" \
    --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null || true
fi
echo ""

# ── Step 5: Application ────────────────────────────────────────────────────
info "[5/5] iAttack Lab application..."

info "Building Docker image locally..."
docker build -t iattack-lab:latest "$ROOT_DIR" -q
ok "Image built: iattack-lab:latest"

kubectl apply -f "$ROOT_DIR/k8s/ml-serving/deployment.yaml"
kubectl apply -f "$ROOT_DIR/k8s/ml-serving/networkpolicies.yaml"

info "Waiting for rollout..."
kubectl rollout status deployment/llm-attack-lab \
  --namespace ml-serving --timeout=120s 2>/dev/null \
  && ok "iAttack Lab running" \
  || warn "Rollout still in progress — check: kubectl get pods -n ml-serving"
echo ""

# ── Summary ─────────────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo -e "${GREEN}Deployment complete!${NC}"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  ml-serving:"
kubectl get pods -n ml-serving --no-headers 2>/dev/null | sed 's/^/    /'
echo ""
echo "  monitoring:"
kubectl get pods -n monitoring --no-headers 2>/dev/null | sed 's/^/    /'
echo ""

echo "═══════════════════════════════════════════════════════════════"
echo "Access:"
echo ""
echo "  Grafana:         kubectl port-forward -n monitoring svc/grafana 3000:80"
echo "                   → http://localhost:3000  (admin / llmattacklab)"
echo ""
echo "  VictoriaMetrics: kubectl port-forward -n monitoring svc/vmsingle-victoria-metrics-single-server 8428:8428"
echo "                   → http://localhost:8428"
echo ""
echo "  iAttack Lab:     kubectl port-forward -n ml-serving svc/llm-attack-lab 8081:8081"
echo "                   → http://localhost:8081"
echo ""
echo "  vmalert:         kubectl port-forward -n monitoring svc/vmalert-victoria-metrics-alert-server 8880:8880"
echo "                   → http://localhost:8880/api/v1/rules"
echo "═══════════════════════════════════════════════════════════════"
