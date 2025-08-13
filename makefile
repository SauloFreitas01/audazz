# OWASP ZAP Automation Makefile
# Versão: 1.0
# Descrição: Comandos simplificados para execução do ZAP

# =============================================================================
# CONFIGURAÇÕES PADRÃO
# =============================================================================
.DEFAULT_GOAL := help
.PHONY: help setup clean scan-quick scan-standard scan-spa scan-api report summary

# Variáveis padrão
ZAP_VERSION ?= 2.14.0
TARGET_URL ?= https://example.com
ENVIRONMENT ?= development
REPORTS_DIR ?= ./reports
CONFIG_DIR ?= ./config

# Cores para output
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
NC := \033[0m

# =============================================================================
# ALVOS PRINCIPAIS
# =============================================================================

help: ## Mostrar esta ajuda
	@echo "$(BLUE)🔒 OWASP ZAP Automation Framework$(NC)"
	@echo ""
	@echo "$(YELLOW)Uso: make [ALVO] [VARIÁVEIS]$(NC)"
	@echo ""
	@echo "$(GREEN)ALVOS PRINCIPAIS:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(BLUE)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)VARIÁVEIS:$(NC)"
	@echo "  $(BLUE)TARGET_URL$(NC)     URL da aplicação (obrigatório)"
	@echo "  $(BLUE)ZAP_VERSION$(NC)    Versão do ZAP (padrão: $(ZAP_VERSION))"
	@echo "  $(BLUE)ENVIRONMENT$(NC)    Ambiente (development/staging/production)"
	@echo "  $(BLUE)AUTH_USER$(NC)      Usuário para autenticação"
	@echo "  $(BLUE)AUTH_PASS$(NC)      Senha para autenticação"
	@echo ""
	@echo "$(GREEN)EXEMPLOS:$(NC)"
	@echo "  $(YELLOW)make scan-quick TARGET_URL=https://staging.com$(NC)"
	@echo "  $(YELLOW)make scan-spa TARGET_URL=https://app.com AUTH_USER=test$(NC)"
	@echo "  $(YELLOW)make scan-standard TARGET_URL=https://site.com ENVIRONMENT=production$(NC)"

setup: ## Configurar ambiente e dependências
	@echo "$(BLUE)🛠  Configurando ambiente ZAP...$(NC)"
	@chmod +x run_zap_automation.sh
	@mkdir -p $(REPORTS_DIR) $(CONFIG_DIR)
	@chmod -R 777 $(REPORTS_DIR)
	@docker --version || (echo "$(RED)❌ Docker não encontrado$(NC)" && exit 1)
	@docker-compose --version || (echo "$(RED)❌ Docker Compose não encontrado$(NC)" && exit 1)
	@echo "$(GREEN)✅ Ambiente configurado com sucesso$(NC)"

pull-images: ## Download das imagens Docker necessárias
	@echo "$(BLUE)📥 Baixando imagens Docker...$(NC)"
	@docker pull owasp/zap2docker-stable:$(ZAP_VERSION)
	@docker pull selenium/hub:4.15.0-20231129
	@docker pull selenium/node-chrome:4.15.0-20231129
	@echo "$(GREEN)✅ Imagens baixadas com sucesso$(NC)"

validate-env: ## Validar variáveis de ambiente
	@echo "$(BLUE)🔍 Validando configuração...$(NC)"
	@if [ -z "$(TARGET_URL)" ]; then \
		echo "$(RED)❌ TARGET_URL é obrigatório$(NC)"; \
		echo "$(YELLOW)Exemplo: make scan-quick TARGET_URL=https://example.com$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✅ Configuração válida$(NC)"
	@echo "  Target URL: $(TARGET_URL)"
	@echo "  ZAP Version: $(ZAP_VERSION)"
	@echo "  Environment: $(ENVIRONMENT)"

# =============================================================================
# TIPOS DE VARREDURA
# =============================================================================

scan-quick: validate-env ## Varredura rápida (5-15 min) - ideal para CI/CD
	@echo "$(BLUE)🚀 Iniciando varredura rápida...$(NC)"
	@TARGET_URL=$(TARGET_URL) \
	 ZAP_VERSION=$(ZAP_VERSION) \
	 ENVIRONMENT=$(ENVIRONMENT) \
	 ./run_zap_automation.sh quick
	@$(MAKE) summary

scan-standard: validate-env ## Varredura padrão completa (20-45 min)
	@echo "$(BLUE)🔍 Iniciando varredura padrão...$(NC)"
	@TARGET_URL=$(TARGET_URL) \
	 ZAP_VERSION=$(ZAP_VERSION) \
	 ENVIRONMENT=$(ENVIRONMENT) \
	 AUTH_USER=$(AUTH_USER) \
	 AUTH_PASS=$(AUTH_PASS) \
	 LOGIN_URL=$(LOGIN_URL) \
	 ./run_zap_automation.sh standard
	@$(MAKE) summary

scan-spa: validate-env ## Varredura para Single Page Applications (30-60 min)
	@echo "$(BLUE)⚛️  Iniciando varredura SPA...$(NC)"
	@TARGET_URL=$(TARGET_URL) \
	 SPA_BASE_URL=$(SPA_BASE_URL) \
	 API_BASE_URL=$(API_BASE_URL) \
	 ZAP_VERSION=$(ZAP_VERSION) \
	 ENVIRONMENT=$(ENVIRONMENT) \
	 AUTH_USER=$(AUTH_USER) \
	 AUTH_PASS=$(AUTH_PASS) \
	 JWT_TOKEN=$(JWT_TOKEN) \
	 ./run_zap_automation.sh spa
	@$(MAKE) summary

scan-api: validate-env ## Varredura para APIs REST/GraphQL (15-30 min)
	@echo "$(BLUE)🌐 Iniciando varredura de API...$(NC)"
	@TARGET_URL=$(TARGET_URL) \
	 API_TOKEN=$(API_TOKEN) \
	 SWAGGER_URL=$(SWAGGER_URL) \
	 ZAP_VERSION=$(ZAP_VERSION) \
	 ENVIRONMENT=$(ENVIRONMENT) \
	 ./run_zap_automation.sh standard rest_api_config.yaml
	@$(MAKE) summary

scan-full: validate-env ## Varredura completa e profunda (1-3 horas)
	@echo "$(BLUE)🎯 Iniciando varredura completa...$(NC)"
	@echo "$(YELLOW)⚠️  Esta varredura pode demorar várias horas$(NC)"
	@TARGET_URL=$(TARGET_URL) \
	 ZAP_VERSION=$(ZAP_VERSION) \
	 ENVIRONMENT=$(ENVIRONMENT) \
	 ./run_zap_automation.sh full
	@$(MAKE) summary

# =============================================================================
# DOCKER COMPOSE
# =============================================================================

start-selenium: ## Iniciar Selenium Grid para SPAs
	@echo "$(BLUE)🕷️  Iniciando Selenium Grid...$(NC)"
	@./run_zap_automation.sh setup-selenium
	@echo "$(GREEN)✅ Selenium Grid disponível em http://localhost:4444$(NC)"

stop-selenium: ## Parar Selenium Grid
	@echo "$(BLUE)🛑 Parando Selenium Grid...$(NC)"
	@./run_zap_automation.sh cleanup-selenium
	@echo "$(GREEN)✅ Selenium Grid removido$(NC)"

start-monitoring: ## Iniciar stack de monitoramento (Grafana + InfluxDB)
	@echo "$(BLUE)📊 Iniciando stack de monitoramento...$(NC)"
	@docker-compose --profile monitoring up -d
	@echo "$(GREEN)✅ Monitoramento disponível:$(NC)"
	@echo "  Grafana: http://localhost:3000 (admin/admin123)"
	@echo "  InfluxDB: http://localhost:8086"

stop-monitoring: ## Parar stack de monitoramento
	@echo "$(BLUE)🛑 Parando stack de monitoramento...$(NC)"
	@docker-compose --profile monitoring down
	@echo "$(GREEN)✅ Stack de monitoramento removida$(NC)"

scan-with-selenium: validate-env start-selenium ## Scan SPA com Selenium Grid automatizado
	@echo "$(BLUE)🤖 Scan SPA com Selenium Grid automatizado...$(NC)"
	@TARGET_URL=$(TARGET_URL) \
	 docker-compose --profile zap-with-grid up --abort-on-container-exit
	@$(MAKE) stop-selenium
	@$(MAKE) summary

# =============================================================================
# RELATÓRIOS E MÉTRICAS
# =============================================================================

summary: ## Mostrar resumo dos últimos resultados
	@echo "$(BLUE)📋 Gerando resumo dos resultados...$(NC)"
	@./run_zap_automation.sh summary

report: ## Processar relatórios para Grafana
	@echo "$(BLUE)📊 Processando relatórios para monitoramento...$(NC)"
	@./run_zap_automation.sh process-reports

metrics: ## Gerar métricas completas com Python
	@echo "$(BLUE)📈 Processando métricas avançadas...$(NC)"
	@python3 process_zap_metrics.py --summary --output-grafana --output-junit

send-slack: ## Enviar notificação Slack (requer SLACK_WEBHOOK)
	@if [ -z "$(SLACK_WEBHOOK)" ]; then \
		echo "$(RED)❌ SLACK_WEBHOOK não definido$(NC)"; \
		exit 1; \
	fi
	@python3 process_zap_metrics.py --slack-webhook $(SLACK_WEBHOOK)

check-gates: ## Verificar quality gates de segurança
	@echo "$(BLUE)🚪 Verificando quality gates...$(NC)"
	@MIN_SECURITY_SCORE=$(MIN_SECURITY_SCORE) \
	 MAX_MEDIUM_RISK=$(MAX_MEDIUM_RISK) \
	 MAX_TOTAL_ALERTS=$(MAX_TOTAL_ALERTS) \
	 python3 process_zap_metrics.py --check-gates

# =============================================================================
# UTILITÁRIOS
# =============================================================================

clean: ## Limpar relatórios antigos e containers
	@echo "$(BLUE)🧹 Limpando ambiente...$(NC)"
	@rm -rf $(REPORTS_DIR)/*.json $(REPORTS_DIR)/*.html $(REPORTS_DIR)/*.xml
	@docker container prune -f
	@docker image prune -f
	@echo "$(GREEN)✅ Limpeza concluída$(NC)"

clean-all: clean stop-selenium stop-monitoring ## Limpeza completa (relatórios + containers + redes)
	@docker-compose down --volumes --remove-orphans
	@docker network prune -f
	@echo "$(GREEN)✅ Limpeza completa realizada$(NC)"

logs: ## Mostrar logs dos últimos scans
	@echo "$(BLUE)📜 Logs dos containers ZAP:$(NC)"
	@docker logs owasp-zap-automation 2>/dev/null || echo "$(YELLOW)Nenhum container ZAP ativo$(NC)"
	@docker logs selenium-hub 2>/dev/null || echo "$(YELLOW)Nenhum Selenium Hub ativo$(NC)"

status: ## Verificar status dos serviços
	@echo "$(BLUE)📊 Status dos serviços:$(NC)"
	@echo ""
	@echo "$(GREEN)Docker:$(NC)"
	@docker version --format "  Versão: {{.Server.Version}}" 2>/dev/null || echo "  $(RED)❌ Não disponível$(NC)"
	@echo ""
	@echo "$(GREEN)Containers ZAP:$(NC)"
	@docker ps --filter "name=zap" --format "  {{.Names}} - {{.Status}}" || echo "  $(YELLOW)Nenhum container ZAP rodando$(NC)"
	@echo ""
	@echo "$(GREEN)Selenium Grid:$(NC)"
	@docker ps --filter "name=selenium" --format "  {{.Names}} - {{.Status}}" || echo "  $(YELLOW)Selenium Grid não está rodando$(NC)"
	@echo ""
	@echo "$(GREEN)Relatórios disponíveis:$(NC)"
	@ls -la $(REPORTS_DIR)/*.json 2>/dev/null | head -5 || echo "  $(YELLOW)Nenhum relatório encontrado$(NC)"

# =============================================================================
# ALVOS PARA DIFERENTES TIPOS DE APLICAÇÃO
# =============================================================================

scan-wordpress: validate-env ## Varredura específica para WordPress
	@echo "$(BLUE)📝 Varredura WordPress...$(NC)"
	@TARGET_URL=$(TARGET_URL) \
	 WP_USER=$(WP_USER) \
	 WP_PASS=$(WP_PASS) \
	 ./run_zap_automation.sh standard wordpress_config.yaml

scan-ecommerce: validate-env ## Varredura para e-commerce
	@echo "$(BLUE)🛒 Varredura E-commerce...$(NC)"
	@TARGET_URL=$(TARGET_URL) \
	 CUSTOMER_USER=$(CUSTOMER_USER) \
	 CUSTOMER_PASS=$(CUSTOMER_PASS) \
	 APP_TYPE=ecommerce \
	 ./run_zap_automation.sh standard

scan-microservices: validate-env ## Varredura para arquitetura de microserviços
	@echo "$(BLUE)🏗️  Varredura Microserviços...$(NC)"
	@USER_SERVICE_URL=$(USER_SERVICE_URL) \
	 ORDER_SERVICE_URL=$(ORDER_SERVICE_URL) \
	 PAYMENT_SERVICE_URL=$(PAYMENT_SERVICE_URL) \
	 ./run_zap_automation.sh standard microservices_config.yaml

# =============================================================================
# PIPELINES CI/CD
# =============================================================================

ci-scan: validate-env ## Scan otimizado para CI/CD com quality gates
	@echo "$(BLUE)🔄 Iniciando scan CI/CD...$(NC)"
	@$(MAKE) scan-quick
	@$(MAKE) check-gates
	@$(MAKE) metrics

ci-full-pipeline: validate-env ## Pipeline completo CI/CD com notificações
	@echo "$(BLUE)🚀 Pipeline CI/CD completo...$(NC)"
	@$(MAKE) scan-quick
	@$(MAKE) metrics
	@$(MAKE) check-gates
	@if [ -n "$(SLACK_WEBHOOK)" ]; then $(MAKE) send-slack; fi

# =============================================================================
# AMBIENTES ESPECÍFICOS
# =============================================================================

scan-dev: ## Scan para ambiente de desenvolvimento (mais agressivo)
	@$(MAKE) scan-standard ENVIRONMENT=development

scan-staging: ## Scan para ambiente de staging (balanceado)
	@$(MAKE) scan-standard ENVIRONMENT=staging

scan-prod: ## Scan para ambiente de produção (conservador)
	@$(MAKE) scan-quick ENVIRONMENT=production

# =============================================================================
# MONITORAMENTO E RELATÓRIOS
# =============================================================================

start-full-monitoring: ## Iniciar monitoramento completo (Grafana + Prometheus + InfluxDB)
	@echo "$(BLUE)📊 Iniciando stack completa de monitoramento...$(NC)"
	@docker-compose --profile monitoring --profile web-reports up -d
	@echo "$(GREEN)✅ Stack de monitoramento iniciada:$(NC)"
	@echo "  Grafana: http://localhost:3000"
	@echo "  InfluxDB: http://localhost:8086"
	@echo "  Relatórios Web: http://localhost:8080"

report-html: ## Gerar relatório HTML navegável
	@echo "$(BLUE)📄 Iniciando servidor de relatórios...$(NC)"
	@docker-compose --profile web-reports up -d
	@echo "$(GREEN)✅ Relatórios disponíveis em: http://localhost:8080$(NC)"

export-junit: ## Exportar resultados no formato JUnit XML
	@echo "$(BLUE)📤 Exportando para JUnit XML...$(NC)"
	@python3 process_zap_metrics.py --output-junit zap-junit-results.xml
	@echo "$(GREEN)✅ JUnit XML gerado: $(REPORTS_DIR)/zap-junit-results.xml$(NC)"

# =============================================================================
# DESENVOLVIMENTO E DEBUG
# =============================================================================

debug-scan: validate-env ## Executar scan com debug habilitado
	@echo "$(BLUE)🐛 Scan com debug...$(NC)"
	@DEBUG=true TARGET_URL=$(TARGET_URL) ./run_zap_automation.sh standard

test-selenium: ## Testar conectividade com Selenium Grid
	@echo "$(BLUE)🧪 Testando Selenium Grid...$(NC)"
	@$(MAKE) start-selenium
	@sleep 10
	@curl -f http://localhost:4444/wd/hub/status || echo "$(RED)❌ Selenium Grid não responde$(NC)"
	@$(MAKE) stop-selenium

validate-config: ## Validar arquivos de configuração YAML
	@echo "$(BLUE)✅ Validando configurações YAML...$(NC)"
	@python3 -c "import yaml; yaml.safe_load(open('zap_automation_plan.yaml'))" && echo "$(GREEN)✅ zap_automation_plan.yaml válido$(NC)" || echo "$(RED)❌ zap_automation_plan.yaml inválido$(NC)"
	@python3 -c "import yaml; yaml.safe_load(open('zap_spa_automation.yaml'))" && echo "$(GREEN)✅ zap_spa_automation.yaml válido$(NC)" || echo "$(RED)❌ zap_spa_automation.yaml inválido$(NC)"

# =============================================================================
# EXEMPLOS PRÁTICOS
# =============================================================================

example-react: ## Exemplo: Scan de aplicação React
	@echo "$(YELLOW)🔍 Exemplo: Aplicação React$(NC)"
	@$(MAKE) scan-spa \
		TARGET_URL=https://app.example.com \
		SPA_BASE_URL=https://app.example.com \
		API_BASE_URL=https://api.example.com \
		AUTH_USER=testuser \
		JWT_TOKEN=eyJ0eXAiOiJKV1Q...

example-api: ## Exemplo: Scan de API REST
	@echo "$(YELLOW)🔍 Exemplo: API REST$(NC)"
	@$(MAKE) scan-api \
		TARGET_URL=https://api.example.com \
		API_TOKEN=sk-1234567890 \
		SWAGGER_URL=https://api.example.com/swagger.json

example-ecommerce: ## Exemplo: Scan de e-commerce
	@echo "$(YELLOW)🔍 Exemplo: E-commerce$(NC)"
	@$(MAKE) scan-ecommerce \
		TARGET_URL=https://shop.example.com \
		CUSTOMER_USER=customer@example.com \
		CUSTOMER_PASS=password123

example-wordpress: ## Exemplo: Scan de WordPress
	@echo "$(YELLOW)🔍 Exemplo: WordPress$(NC)"
	@$(MAKE) scan-wordpress \
		TARGET_URL=https://blog.example.com \
		WP_USER=admin \
		WP_PASS=admin123

# =============================================================================
# INTEGRAÇÃO CONTÍNUA
# =============================================================================

ci-setup: setup pull-images validate-config ## Setup completo para CI/CD
	@echo "$(GREEN)✅ Ambiente CI/CD configurado$(NC)"

ci-quick-check: ## Check rápido para pull requests
	@echo "$(BLUE)⚡ Quick check para PR...$(NC)"
	@$(MAKE) scan-quick
	@$(MAKE) check-gates MIN_SECURITY_SCORE=80 MAX_MEDIUM_RISK=3

ci-nightly: ## Scan noturno completo
	@echo "$(BLUE)🌙 Scan noturno completo...$(NC)"
	@$(MAKE) scan-standard
	@$(MAKE) metrics
	@if [ -n "$(SLACK_WEBHOOK)" ]; then $(MAKE) send-slack; fi

ci-release: ## Scan para release (mais rigoroso)
	@echo "$(BLUE)🚀 Scan para release...$(NC)"
	@$(MAKE) scan-standard ENVIRONMENT=production
	@$(MAKE) check-gates MIN_SECURITY_SCORE=90 MAX_MEDIUM_RISK=1 MAX_TOTAL_ALERTS=10

# =============================================================================
# BENCHMARKS E PERFORMANCE
# =============================================================================

benchmark: ## Executar benchmark de performance do ZAP
	@echo "$(BLUE)⏱️  Executando benchmark...$(NC)"
	@echo "$(YELLOW)Scan 1: Aplicação pequena$(NC)"
	@time $(MAKE) scan-quick TARGET_URL=https://httpbin.org
	@echo ""
	@echo "$(YELLOW)Scan 2: Com Selenium$(NC)" 
	@time $(MAKE) scan-with-selenium TARGET_URL=https://httpbin.org
	@echo "$(GREEN)✅ Benchmark concluído$(NC)"

performance-test: ## Teste de performance com múltiplos targets
	@echo "$(BLUE)🏎️  Teste de performance...$(NC)"
	@for url in https://httpbin.org https://jsonplaceholder.typicode.com https://postman-echo.com; do \
		echo "$(YELLOW)Testando: $url$(NC)"; \
		time $(MAKE) scan-quick TARGET_URL=$url; \
		echo ""; \
	done

# =============================================================================
# MANUTENÇÃO
# =============================================================================

update-images: ## Atualizar imagens Docker
	@echo "$(BLUE)🔄 Atualizando imagens...$(NC)"
	@docker pull owasp/zap2docker-stable:latest
	@docker pull selenium/hub:latest
	@docker pull selenium/node-chrome:latest
	@echo "$(GREEN)✅ Imagens atualizadas$(NC)"

backup-reports: ## Backup dos relatórios
	@echo "$(BLUE)💾 Criando backup dos relatórios...$(NC)"
	@timestamp=$(date +%Y%m%d_%H%M%S); \
	tar -czf "zap-reports-backup-$timestamp.tar.gz" $(REPORTS_DIR)/; \
	echo "$(GREEN)✅ Backup criado: zap-reports-backup-$timestamp.tar.gz$(NC)"

health-check: ## Verificar saúde do sistema
	@echo "$(BLUE)🏥 Verificação de saúde do sistema...$(NC)"
	@echo ""
	@echo "$(GREEN)Docker:$(NC)"
	@docker system df
	@echo ""
	@echo "$(GREEN)Espaço em disco:$(NC)"
	@df -h $(REPORTS_DIR)
	@echo ""
	@echo "$(GREEN)Memória disponível:$(NC)"
	@free -h
	@echo ""
	@echo "$(GREEN)Últimos relatórios:$(NC)"
	@ls -lah $(REPORTS_DIR)/ | head -10

# =============================================================================
# RECEITAS COMBINADAS
# =============================================================================

full-spa-pipeline: ## Pipeline completo para SPA (setup + scan + monitoramento)
	@echo "$(BLUE)🎯 Pipeline completo para SPA...$(NC)"
	@$(MAKE) setup
	@$(MAKE) start-selenium
	@$(MAKE) start-monitoring
	@$(MAKE) scan-spa
	@$(MAKE) metrics
	@$(MAKE) report-html
	@echo "$(GREEN)✅ Pipeline SPA concluído$(NC)"
	@echo "  Relatórios: http://localhost:8080"
	@echo "  Monitoramento: http://localhost:3000"

security-audit: validate-env ## Auditoria completa de segurança
	@echo "$(BLUE)🔐 Auditoria completa de segurança...$(NC)"
	@$(MAKE) scan-full
	@$(MAKE) metrics
	@$(MAKE) export-junit
	@$(MAKE) summary
	@echo "$(GREEN)✅ Auditoria de segurança concluída$(NC)"

quick-dev-check: ## Check rápido para desenvolvimento
	@echo "$(BLUE)⚡ Check rápido de desenvolvimento...$(NC)"
	@$(MAKE) scan-quick ENVIRONMENT=development
	@$(MAKE) summary

# =============================================================================
# VARIÁVEIS DE AMBIENTE PARA QUALITY GATES
# =============================================================================

# Definir valores padrão se não estiverem definidos
MIN_SECURITY_SCORE ?= 70
MAX_MEDIUM_RISK ?= 5
MAX_TOTAL_ALERTS ?= 20

# =============================================================================
# TARGETS DE INFORMAÇÃO
# =============================================================================

show-config: ## Mostrar configuração atual
	@echo "$(BLUE)⚙️  Configuração atual:$(NC)"
	@echo "  TARGET_URL: $(TARGET_URL)"
	@echo "  ZAP_VERSION: $(ZAP_VERSION)"
	@echo "  ENVIRONMENT: $(ENVIRONMENT)"
	@echo "  REPORTS_DIR: $(REPORTS_DIR)"
	@echo "  CONFIG_DIR: $(CONFIG_DIR)"
	@echo "  MIN_SECURITY_SCORE: $(MIN_SECURITY_SCORE)"
	@echo "  MAX_MEDIUM_RISK: $(MAX_MEDIUM_RISK)"
	@echo "  MAX_TOTAL_ALERTS: $(MAX_TOTAL_ALERTS)"
	@echo ""
	@echo "$(GREEN)Variáveis opcionais:$(NC)"
	@echo "  AUTH_USER: $(if $(AUTH_USER),$(AUTH_USER),não definido)"
	@echo "  SPA_BASE_URL: $(if $(SPA_BASE_URL),$(SPA_BASE_URL),não definido)"
	@echo "  API_BASE_URL: $(if $(API_BASE_URL),$(API_BASE_URL),não definido)"
	@echo "  SLACK_WEBHOOK: $(if $(SLACK_WEBHOOK),configurado,não definido)"

version: ## Mostrar versões dos componentes
	@echo "$(BLUE)📦 Versões dos componentes:$(NC)"
	@echo "  ZAP Version: $(ZAP_VERSION)"
	@docker --version || echo "  Docker: $(RED)não instalado$(NC)"
	@docker-compose --version || echo "  Docker Compose: $(RED)não instalado$(NC)"
	@python3 --version || echo "  Python: $(RED)não instalado$(NC)"

list-reports: ## Listar relatórios disponíveis
	@echo "$(BLUE)📋 Relatórios disponíveis:$(NC)"
	@find $(REPORTS_DIR) -name "*.json" -o -name "*.html" -o -name "*.xml" | sort -r | head -10

# =============================================================================
# TARGETS DE DESENVOLVIMENTO
# =============================================================================

dev-setup: setup ## Setup completo para desenvolvimento
	@echo "$(BLUE)👨‍💻 Setup para desenvolvimento...$(NC)"
	@$(MAKE) pull-images
	@$(MAKE) validate-config
	@pip3 install pyyaml requests influxdb-client 2>/dev/null || echo "$(YELLOW)⚠️  Algumas dependências Python podem estar faltando$(NC)"
	@echo "$(GREEN)✅ Ambiente de desenvolvimento configurado$(NC)"

test-configs: ## Testar todas as configurações
	@echo "$(BLUE)🧪 Testando configurações...$(NC)"
	@$(MAKE) validate-config
	@$(MAKE) test-selenium
	@echo "$(GREEN)✅ Todos os testes passaram$(NC)"

dry-run: validate-env ## Simulação sem executar scan real
	@echo "$(BLUE)🎭 Simulação de execução (dry-run)...$(NC)"
	@echo "  Comando que seria executado:"
	@echo "  TARGET_URL=$(TARGET_URL) ./run_zap_automation.sh standard"
	@echo ""
	@echo "  Configurações que seriam utilizadas:"
	@$(MAKE) show-config

# =============================================================================
# HELP ADICIONAL
# =============================================================================

help-examples: ## Mostrar exemplos detalhados de uso
	@echo "$(BLUE)📚 Exemplos Detalhados de Uso$(NC)"
	@echo ""
	@echo "$(GREEN)1. Scan básico de aplicação web:$(NC)"
	@echo "   make scan-standard TARGET_URL=https://myapp.com"
	@echo ""
	@echo "$(GREEN)2. Scan SPA React com autenticação:$(NC)"
	@echo "   make scan-spa TARGET_URL=https://app.com \\"
	@echo "                 AUTH_USER=testuser \\"
	@echo "                 AUTH_PASS=testpass \\"
	@echo "                 SPA_BASE_URL=https://app.com \\"
	@echo "                 API_BASE_URL=https://api.com"
	@echo ""
	@echo "$(GREEN)3. Pipeline CI/CD completo:$(NC)"
	@echo "   make ci-full-pipeline TARGET_URL=https://staging.com \\"
	@echo "                         SLACK_WEBHOOK=https://hooks.slack.com/..."
	@echo ""
	@echo "$(GREEN)4. Auditoria de segurança completa:$(NC)"
	@echo "   make security-audit TARGET_URL=https://prod.com \\"
	@echo "                       ENVIRONMENT=production"
	@echo ""
	@echo "$(GREEN)5. Monitoramento contínuo:$(NC)"
	@echo "   make start-full-monitoring"
	@echo "   make scan-standard TARGET_URL=https://app.com"
	@echo "   # Visualizar em http://localhost:3000"

help-ci: ## Ajuda para integração CI/CD
	@echo "$(BLUE)🔄 Integração CI/CD$(NC)"
	@echo ""
	@echo "$(GREEN)Jenkins Pipeline:$(NC)"
	@echo "  stage('Security Scan') {"
	@echo "    steps {"
	@echo "      sh 'make ci-scan TARGET_URL=\$TARGET_URL'"
	@echo "    }"
	@echo "  }"
	@echo ""
	@echo "$(GREEN)GitLab CI:$(NC)"
	@echo "  security_scan:"
	@echo "    script:"
	@echo "      - make ci-scan TARGET_URL=\$CI_ENVIRONMENT_URL"
	@echo "    artifacts:"
	@echo "      reports:"
	@echo "        junit: reports/*.xml"
	@echo ""
	@echo "$(GREEN)GitHub Actions:$(NC)"
	@echo "  - name: Security Scan"
	@echo "    run: make ci-scan TARGET_URL=\${{ secrets.TARGET_URL }}"

help-troubleshooting: ## Ajuda para resolução de problemas
	@echo "$(BLUE)🔧 Resolução de Problemas$(NC)"
	@echo ""
	@echo "$(GREEN)Problemas comuns:$(NC)"
	@echo ""
	@echo "$(YELLOW)1. 'Target URL não acessível':$(NC)"
	@echo "   → Verificar: make validate-env"
	@echo "   → Testar: curl -I \$TARGET_URL"
	@echo ""
	@echo "$(YELLOW)2. 'Selenium Grid não responde':$(NC)"
	@echo "   → Reiniciar: make stop-selenium && make start-selenium"
	@echo "   → Testar: make test-selenium"
	@echo ""
	@echo "$(YELLOW)3. 'Memória insuficiente':$(NC)"
	@echo "   → Verificar: make health-check"
	@echo "   → Limpar: make clean-all"
	@echo ""
	@echo "$(YELLOW)4. 'Falha na autenticação':$(NC)"
	@echo "   → Debug: make debug-scan TARGET_URL=\$TARGET_URL"
	@echo "   → Logs: make logs"

# =============================================================================
# SHORTCUTS
# =============================================================================

s: scan-standard ## Shortcut para scan-standard
q: scan-quick ## Shortcut para scan-quick  
spa: scan-spa ## Shortcut para scan-spa
api: scan-api ## Shortcut para scan-api
r: summary ## Shortcut para summary
c: clean ## Shortcut para clean
h: help ## Shortcut para help