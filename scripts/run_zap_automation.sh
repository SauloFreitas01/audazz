#!/bin/bash
# OWASP ZAP - Script de Automação Docker
# Arquivo: run_zap_automation.sh
# Versão: 1.0

set -e # Exit on any error

# =============================================================================
# CONFIGURAÇÕES GERAIS
# =============================================================================

# Versão do ZAP a ser utilizada
ZAP_VERSION="${ZAP_VERSION:-2.14.0}"

# Diretórios
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_DIR="${SCRIPT_DIR}/reports"
CONFIG_DIR="${SCRIPT_DIR}/config"
WORKDIR="/zap/wrk"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# FUNÇÕES AUXILIARES
# =============================================================================

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Validar se variáveis obrigatórias estão definidas
validate_env() {
    local required_vars=("TARGET_URL")
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            error "Variável de ambiente obrigatória não definida: $var"
        fi
    done
    
    log "Validação de ambiente concluída com sucesso"
}

# Criar diretórios necessários
setup_directories() {
    mkdir -p "$REPORTS_DIR"
    mkdir -p "$CONFIG_DIR"
    
    # Definir permissões corretas (ZAP roda como usuário 1000)
    chmod -R 777 "$REPORTS_DIR"
    
    log "Diretórios configurados: $REPORTS_DIR, $CONFIG_DIR"
}

# Verificar se Docker está disponível
check_docker() {
    if ! command -v docker &> /dev/null; then
        error "Docker não encontrado. Instale o Docker antes de continuar."
    fi
    
    if ! docker info &> /dev/null; then
        error "Docker daemon não está rodando ou sem permissões adequadas."
    fi
    
    success "Docker verificado com sucesso"
}

# Pull da imagem ZAP mais recente
pull_zap_image() {
    log "Fazendo pull da imagem OWASP ZAP ${ZAP_VERSION}..."
    
    if ! docker pull "owasp/zap2docker-stable:${ZAP_VERSION}"; then
        warning "Falha no pull da versão específica. Tentando versão latest..."
        docker pull "owasp/zap2docker-stable:latest"
        ZAP_VERSION="latest"
    fi
    
    success "Imagem ZAP ${ZAP_VERSION} obtida com sucesso"
}

# =============================================================================
# FUNÇÕES DE EXECUÇÃO
# =============================================================================

# Executar varredura padrão com arquivo YAML
run_standard_scan() {
    local automation_file="${1:-zap_automation_plan.yaml}"
    
    if [[ ! -f "$automation_file" ]]; then
        error "Arquivo de automação não encontrado: $automation_file"
    fi
    
    log "Iniciando varredura padrão com $automation_file"
    log "Target URL: $TARGET_URL"
    
    # Timestamp para relatórios únicos
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    docker run --rm \
        --name "zap-automation-${timestamp}" \
        -v "$PWD:/zap/wrk/:rw" \
        -v "$automation_file:/zap/wrk/automation.yaml:ro" \
        -e "TARGET_URL=$TARGET_URL" \
        -e "AUTH_USER=${AUTH_USER:-}" \
        -e "AUTH_PASS=${AUTH_PASS:-}" \
        -e "LOGIN_URL=${LOGIN_URL:-}" \
        -e "timestamp=$timestamp" \
        --user root \
        "owasp/zap2docker-stable:${ZAP_VERSION}" \
        zap.sh -cmd -autorun /zap/wrk/automation.yaml
    
    success "Varredura padrão concluída. Relatórios em: $REPORTS_DIR"
}

# Executar varredura para SPAs
run_spa_scan() {
    local spa_config="${1:-zap_spa_automation.yaml}"
    
    if [[ ! -f "$spa_config" ]]; then
        error "Arquivo de configuração SPA não encontrado: $spa_config"
    fi
    
    log "Iniciando varredura para SPA com $spa_config"
    log "SPA Base URL: ${SPA_BASE_URL:-$TARGET_URL}"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    # Para SPAs, pode ser necessário Selenium Grid
    local docker_network=""
    if [[ -n "${SELENIUM_GRID_URL}" ]]; then
        docker_network="--network selenium-grid"
        log "Configuração de rede Selenium detectada: ${SELENIUM_GRID_URL}"
    fi
    
    docker run --rm \
        --name "zap-spa-${timestamp}" \
        $docker_network \
        -v "$PWD:/zap/wrk/:rw" \
        -v "$spa_config:/zap/wrk/automation.yaml:ro" \
        -e "SPA_BASE_URL=${SPA_BASE_URL:-$TARGET_URL}" \
        -e "API_BASE_URL=${API_BASE_URL:-}" \
        -e "AUTH_USER=${AUTH_USER:-}" \
        -e "AUTH_PASS=${AUTH_PASS:-}" \
        -e "SELENIUM_GRID_URL=${SELENIUM_GRID_URL:-}" \
        -e "timestamp=$timestamp" \
        --user root \
        --shm-size=2g \
        "owasp/zap2docker-stable:${ZAP_VERSION}" \
        zap.sh -cmd -autorun /zap/wrk/automation.yaml
    
    success "Varredura SPA concluída. Relatórios em: $REPORTS_DIR"
}

# Executar scan rápido para CI/CD
run_quick_scan() {
    log "Iniciando varredura rápida para CI/CD"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local report_file="quick-scan-${timestamp}"
    
    # Scan básico com timeout reduzido
    docker run --rm \
        --name "zap-quick-${timestamp}" \
        -v "$REPORTS_DIR:/zap/wrk/reports:rw" \
        --user root \
        "owasp/zap2docker-stable:${ZAP_VERSION}" \
        zap-baseline.py \
        -t "$TARGET_URL" \
        -g gen.conf \
        -r "$report_file.html" \
        -J "$report_file.json" \
        -x "$report_file.xml" \
        --hook=/zap/wrk/reports/

    success "Varredura rápida concluída em $REPORTS_DIR/$report_file.*"
}

# Executar scan completo (full scan)
run_full_scan() {
    log "Iniciando varredura completa (pode demorar várias horas)"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local report_file="full-scan-${timestamp}"
    
    docker run --rm \
        --name "zap-full-${timestamp}" \
        -v "$REPORTS_DIR:/zap/wrk/reports:rw" \
        -e "TARGET_URL=$TARGET_URL" \
        --user root \
        "owasp/zap2docker-stable:${ZAP_VERSION}" \
        zap-full-scan.py \
        -t "$TARGET_URL" \
        -g gen.conf \
        -r "$report_file.html" \
        -J "$report_file.json" \
        -x "$report_file.xml"
    
    success "Varredura completa concluída em $REPORTS_DIR/$report_file.*"
}

# =============================================================================
# FUNÇÕES DE UTILITÁRIOS
# =============================================================================

# Configurar Selenium Grid para SPAs (opcional)
setup_selenium_grid() {
    log "Configurando Selenium Grid para testes de SPAs..."
    
    # Criar rede Docker
    docker network create selenium-grid 2>/dev/null || true
    
    # Hub Selenium
    docker run -d \
        --name selenium-hub \
        --network selenium-grid \
        -p 4442-4444:4442-4444 \
        --shm-size=2g \
        selenium/hub:4.15.0-20231129
    
    # Node Chrome
    docker run -d \
        --name selenium-node-chrome \
        --network selenium-grid \
        --shm-size=2g \
        -e HUB_HOST=selenium-hub \
        -e HUB_PORT=4444 \
        selenium/node-chrome:4.15.0-20231129
    
    # Aguardar inicialização
    sleep 10
    
    success "Selenium Grid configurado em http://localhost:4444"
    export SELENIUM_GRID_URL="http://selenium-hub:4444/wd/hub"
}

# Limpar containers e networks do Selenium
cleanup_selenium_grid() {
    log "Limpando Selenium Grid..."
    
    docker stop selenium-node-chrome selenium-hub 2>/dev/null || true
    docker rm selenium-node-chrome selenium-hub 2>/dev/null || true
    docker network rm selenium-grid 2>/dev/null || true
    
    success "Selenium Grid removido"
}

# Processar relatórios para Grafana
process_reports_for_grafana() {
    log "Processando relatórios para integração com Grafana..."
    
    # Encontrar o relatório JSON mais recente
    local latest_json=$(find "$REPORTS_DIR" -name "*.json" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)
    
    if [[ -z "$latest_json" ]]; then
        warning "Nenhum relatório JSON encontrado em $REPORTS_DIR"
        return 1
    fi
    
    # Criar arquivo de métricas simples para Grafana
    local metrics_file="$REPORTS_DIR/zap-metrics-$(date +%Y%m%d_%H%M%S).json"
    
    python3 - <<EOF
import json
import sys
from datetime import datetime

try:
    with open('$latest_json', 'r') as f:
        data = json.load(f)
    
    site = data.get('site', [{}])[0] if data.get('site') else {}
    alerts = data.get('site', [{}])[0].get('alerts', []) if data.get('site') else []
    
    # Contadores por risco
    risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    
    for alert in alerts:
        risk = alert.get('riskdesc', '').split(' ')[0]
        if risk in risk_counts:
            risk_counts[risk] += 1
    
    # Métricas para Grafana
    metrics = {
        'timestamp': datetime.now().isoformat(),
        'target_url': site.get('@name', 'Unknown'),
        'total_alerts': len(alerts),
        'high_risk': risk_counts['High'],
        'medium_risk': risk_counts['Medium'],
        'low_risk': risk_counts['Low'],
        'informational': risk_counts['Informational'],
        'scan_completed': True,
        'scan_duration_seconds': 0  # Pode ser calculado se necessário
    }
    
    with open('$metrics_file', 'w') as f:
        json.dump(metrics, f, indent=2)
        
    print(f"Métricas salvas em: $metrics_file")
    
except Exception as e:
    print(f"Erro ao processar relatório: {e}")
    sys.exit(1)
EOF
    
    success "Métricas processadas para Grafana: $metrics_file"
}

# Mostrar resumo dos resultados
show_results_summary() {
    log "Resumo dos resultados da varredura:"
    
    # Encontrar o relatório JSON mais recente
    local latest_json=$(find "$REPORTS_DIR" -name "*.json" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)
    
    if [[ -n "$latest_json" ]]; then
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📊 RESUMO DA VARREDURA DE SEGURANÇA"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        python3 - <<EOF
import json

try:
    with open('$latest_json', 'r') as f:
        data = json.load(f)
    
    site = data.get('site', [{}])[0] if data.get('site') else {}
    alerts = data.get('site', [{}])[0].get('alerts', []) if data.get('site') else []
    
    print(f"🎯 Target: {site.get('@name', 'N/A')}")
    print(f"📅 Data: $(date +'%Y-%m-%d %H:%M:%S')")
    print(f"📋 Total de Alertas: {len(alerts)}")
    print()
    
    # Contadores por risco
    risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    
    for alert in alerts:
        risk = alert.get('riskdesc', '').split(' ')[0]
        if risk in risk_counts:
            risk_counts[risk] += 1
    
    # Mostrar contadores com cores
    print("📊 Distribuição por Risco:")
    if risk_counts['High'] > 0:
        print(f"   🔴 Alto: {risk_counts['High']}")
    if risk_counts['Medium'] > 0:
        print(f"   🟡 Médio: {risk_counts['Medium']}")
    if risk_counts['Low'] > 0:
        print(f"   🔵 Baixo: {risk_counts['Low']}")
    if risk_counts['Informational'] > 0:
        print(f"   ⚪ Informativo: {risk_counts['Informational']}")
    
    print()
    
    # Top 5 vulnerabilidades mais críticas
    high_medium_alerts = [a for a in alerts if a.get('riskdesc', '').startswith(('High', 'Medium'))]
    
    if high_medium_alerts:
        print("🚨 Top 5 Vulnerabilidades Críticas:")
        for i, alert in enumerate(high_medium_alerts[:5], 1):
            risk = alert.get('riskdesc', '').split(' ')[0]
            name = alert.get('name', 'N/A')
            print(f"   {i}. [{risk}] {name}")
    
except Exception as e:
    print(f"Erro ao processar resumo: {e}")
EOF
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📁 Relatórios salvos em: $REPORTS_DIR"
        echo "🔗 Relatório JSON: $latest_json"
    else
        warning "Nenhum relatório JSON encontrado para resumo"
    fi
}

# =============================================================================
# MENU PRINCIPAL
# =============================================================================

show_usage() {
    cat << EOF
🔒 OWASP ZAP Automation Script

Uso: $0 [COMANDO] [OPÇÕES]

COMANDOS:
    standard                 Executar varredura padrão (requer zap_automation_plan.yaml)
    spa                      Executar varredura para Single Page Applications
    quick                    Varredura rápida para CI/CD (baseline scan)
    full                     Varredura completa (pode demorar horas)
    setup-selenium           Configurar Selenium Grid para SPAs
    cleanup-selenium         Remover Selenium Grid
    process-reports          Processar relatórios para Grafana
    summary                  Mostrar resumo dos últimos resultados

VARIÁVEIS DE AMBIENTE OBRIGATÓRIAS:
    TARGET_URL               URL da aplicação a ser testada

VARIÁVEIS OPCIONAIS:
    ZAP_VERSION              Versão do ZAP (padrão: 2.14.0)
    AUTH_USER                Usuário para autenticação
    AUTH_PASS                Senha para autenticação
    LOGIN_URL                URL de login
    SPA_BASE_URL             URL base do SPA (para scan SPA)
    API_BASE_URL             URL base da API (para scan SPA)
    SELENIUM_GRID_URL        URL do Selenium Grid

EXEMPLOS:
    # Varredura padrão
    TARGET_URL=https://example.com $0 standard
    
    # Varredura SPA com autenticação
    TARGET_URL=https://app.example.com \\
    AUTH_USER=testuser \\
    AUTH_PASS=testpass \\
    $0 spa
    
    # Varredura rápida para CI/CD
    TARGET_URL=https://staging.example.com $0 quick

EOF
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    local command="${1:-help}"
    
    case "$command" in
        "standard")
            validate_env
            setup_directories
            check_docker
            pull_zap_image
            run_standard_scan "${2:-zap_automation_plan.yaml}"
            process_reports_for_grafana
            show_results_summary
            ;;
        "spa")
            validate_env
            setup_directories
            check_docker
            pull_zap_image
            run_spa_scan "${2:-zap_spa_automation.yaml}"
            process_reports_for_grafana
            show_results_summary
            ;;
        "quick")
            validate_env
            setup_directories
            check_docker
            pull_zap_image
            run_quick_scan
            show_results_summary
            ;;
        "full")
            validate_env
            setup_directories
            check_docker
            pull_zap_image
            run_full_scan
            show_results_summary
            ;;
        "setup-selenium")
            check_docker
            setup_selenium_grid
            ;;
        "cleanup-selenium")
            cleanup_selenium_grid
            ;;
        "process-reports")
            setup_directories
            process_reports_for_grafana
            ;;
        "summary")
            show_results_summary
            ;;
        "help"|*)
            show_usage
            ;;
    esac
}

# Executar função principal
main "$@"