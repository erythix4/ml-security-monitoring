#!/bin/bash
#
# Script pour exécuter les tests du LLM Attack Lab
#
# ÉTAPES:
# 1. Installation des dépendances de test
# 2. Exécution des tests avec couverture
# 3. Génération du rapport
#
# MODES D'EXÉCUTION:
# - ./run_tests.sh         : Exécuter tous les tests une fois
# - ./run_tests.sh watch   : Exécuter les tests en continu (watch mode)
# - ./run_tests.sh coverage: Exécuter avec rapport de couverture
#

set -e

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Détecter la commande Python disponible
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "${RED}Erreur: Python n'est pas installé.${NC}"
    exit 1
fi

# Répertoire du projet
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  LLM Attack Lab - Test Runner${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Vérifier si les dépendances de test sont installées
check_dependencies() {
    echo -e "${YELLOW}Verification des dependances...${NC}"

    # Vérifier les dépendances principales du projet
    if ! $PYTHON -c "import rich" 2>/dev/null || ! $PYTHON -c "import flask" 2>/dev/null; then
        echo -e "${YELLOW}Installation des dependances du projet...${NC}"
        if [ -f "$PROJECT_DIR/requirements.txt" ]; then
            $PYTHON -m pip install -r "$PROJECT_DIR/requirements.txt" --quiet 2>/dev/null || \
            $PYTHON -m pip install flask rich click numpy colorama pyyaml jinja2 websockets pytest pytest-cov prometheus-client --quiet --ignore-installed 2>/dev/null || true
        else
            $PYTHON -m pip install flask rich click numpy colorama pyyaml jinja2 websockets pytest pytest-cov prometheus-client --quiet 2>/dev/null || true
        fi
    fi

    # Vérifier pytest spécifiquement
    if ! $PYTHON -c "import pytest" 2>/dev/null; then
        echo -e "${YELLOW}Installation de pytest...${NC}"
        $PYTHON -m pip install pytest pytest-cov --quiet 2>/dev/null || \
        $PYTHON -m pip install pytest pytest-cov --quiet --ignore-installed 2>/dev/null || true
    fi

    # Vérification finale
    if ! $PYTHON -c "import pytest; import rich; import flask" 2>/dev/null; then
        echo -e "${RED}Erreur: Impossible d'installer les dependances.${NC}"
        echo -e "${YELLOW}Essayez manuellement: pip install -r requirements.txt${NC}"
        exit 1
    fi

    echo -e "${GREEN}Dependances OK${NC}"
    echo ""
}

# Exécuter les tests une fois (hors bombardement)
run_tests() {
    echo -e "${CYAN}Execution des tests...${NC}"
    echo ""

    $PYTHON -m pytest tests/ \
        -v \
        --tb=long \
        -x \
        --strict-markers \
        -m "not bombard" \
        -s

    echo ""
    echo -e "${GREEN}Tests termines!${NC}"
}

# Exécuter les tests en mode watch (continu)
run_watch() {
    echo -e "${CYAN}Mode watch active - Les tests s'executent automatiquement a chaque modification${NC}"
    echo -e "${YELLOW}Appuyez sur Ctrl+C pour arreter${NC}"
    echo ""

    # Verifier si pytest-watch est installe
    if ! $PYTHON -c "import pytest_watch" 2>/dev/null; then
        echo -e "${YELLOW}Installation de pytest-watch...${NC}"
        $PYTHON -m pip install pytest-xdist --quiet 2>/dev/null || true
    fi

    # Utiliser une boucle simple si pytest-watch n'est pas disponible
    if $PYTHON -c "import pytest_watch" 2>/dev/null; then
        $PYTHON -m pytest_watch -- tests/ -v --tb=short -x
    else
        echo -e "${YELLOW}pytest-watch non disponible, utilisation du mode boucle${NC}"
        while true; do
            $PYTHON -m pytest tests/ -v --tb=short -x -m "not bombard"
            echo -e "${YELLOW}Appuyez sur Entree pour relancer, Ctrl+C pour quitter${NC}"
            read
        done
    fi
}

# Exécuter avec couverture de code
run_coverage() {
    echo -e "${CYAN}Exécution des tests avec couverture...${NC}"
    echo ""

    $PYTHON -m pytest tests/ \
        -v \
        --tb=short \
        --cov=llm_attack_lab \
        --cov-report=term-missing \
        --cov-report=html:coverage_report

    echo ""
    echo -e "${GREEN}Rapport de couverture généré dans: coverage_report/index.html${NC}"
}

# Exécuter uniquement les tests unitaires (rapides)
run_unit() {
    echo -e "${CYAN}Exécution des tests unitaires...${NC}"
    echo ""

    $PYTHON -m pytest tests/ \
        -v \
        --tb=short \
        -m "unit" \
        -x
}

# Exécuter uniquement les tests d'intégration
run_integration() {
    echo -e "${CYAN}Exécution des tests d'intégration...${NC}"
    echo ""

    $PYTHON -m pytest tests/ \
        -v \
        --tb=short \
        -m "integration"
}

# Exécuter uniquement les tests web/API
run_web() {
    echo -e "${CYAN}Execution des tests Web/API...${NC}"
    echo ""

    $PYTHON -m pytest tests/test_web_api.py \
        -v \
        --tb=short
}

# Exécuter les tests de bombardement / stress
run_bombard() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}  BOMBARDEMENT / STRESS TESTS${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
    echo -e "${YELLOW}Envoi de centaines de requetes en rafale...${NC}"
    echo -e "${YELLOW}(tests en memoire - pas de metriques Grafana)${NC}"
    echo ""

    $PYTHON -m pytest tests/test_bombard.py \
        -v \
        --tb=long \
        -m "bombard and not http" \
        -s
}

# Exécuter les tests HTTP réels (pour Grafana/Prometheus)
run_http() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}  BOMBARDEMENT HTTP REEL (Grafana/Prometheus)${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
    echo -e "${YELLOW}PREREQUIS: Le serveur doit etre demarre!${NC}"
    echo -e "${YELLOW}  python -m llm_attack_lab.web.app${NC}"
    echo ""
    echo -e "${GREEN}Les metriques seront visibles sur Grafana.${NC}"
    echo ""

    $PYTHON -m pytest tests/test_bombard.py \
        -v \
        --tb=long \
        -m "http" \
        -s
}

# Exécuter tous les tests puis le bombardement
run_all() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}  TESTS COMPLETS + BOMBARDEMENT${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""

    $PYTHON -m pytest tests/ \
        -v \
        --tb=long \
        -s
}

# Exécuter avec logs détaillés (verbose)
run_verbose() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}  MODE VERBOSE - LOGS DETAILLES${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""

    TEST_VERBOSE=1 $PYTHON -m pytest tests/ \
        -v \
        --tb=long \
        -m "not bombard" \
        -s \
        --capture=no
}

# Afficher l'aide
show_help() {
    echo "Usage: ./run_tests.sh [OPTION]"
    echo ""
    echo "Options:"
    echo "  (vide)      Executer tous les tests une fois"
    echo "  watch       Mode continu - relance les tests a chaque modification"
    echo "  coverage    Executer avec rapport de couverture"
    echo "  unit        Executer uniquement les tests unitaires"
    echo "  integration Executer uniquement les tests d'integration"
    echo "  web         Executer uniquement les tests Web/API"
    echo "  bombard     Bombardement / stress tests (en memoire, pas de Grafana)"
    echo "  http        Bombardement HTTP reel (AVEC metriques Grafana/Prometheus)"
    echo "  all         Tests complets + bombardement"
    echo "  verbose     Executer avec logs detailles"
    echo "  help        Afficher cette aide"
    echo ""
    echo "Variables d'environnement:"
    echo "  TEST_VERBOSE=1    Active les logs detailles"
    echo ""
    echo "Exemples:"
    echo "  ./run_tests.sh              # Tous les tests (hors bombardement)"
    echo "  ./run_tests.sh bombard      # Stress tests en memoire"
    echo "  ./run_tests.sh http         # Bombardement HTTP reel (demarre le serveur avant!)"
    echo "  ./run_tests.sh all          # Tout: tests + bombardement"
    echo "  ./run_tests.sh verbose      # Tests avec logs detailles"
    echo "  TEST_VERBOSE=1 ./run_tests.sh bombard  # Bombardement + logs"
}

# Main
check_dependencies

case "${1:-}" in
    watch)
        run_watch
        ;;
    coverage)
        run_coverage
        ;;
    unit)
        run_unit
        ;;
    integration)
        run_integration
        ;;
    web)
        run_web
        ;;
    bombard)
        run_bombard
        ;;
    http)
        run_http
        ;;
    all)
        run_all
        ;;
    verbose)
        run_verbose
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        run_tests
        ;;
esac
