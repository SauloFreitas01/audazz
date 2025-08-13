# 🚀 Guia de Início Rápido - OWASP ZAP Automation

## ⚡ Setup Inicial (5 minutos)

### 1. Pré-requisitos
```bash
# Verificar Docker
docker --version
docker-compose --version

# Se não tiver Docker instalado:
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
```

### 2. Configuração Rápida
```bash
# Clonar/baixar os arquivos
git clone <repository> zap-automation
cd zap-automation

# Setup inicial
make setup
make pull-images
```

### 3. Primeiro Scan (2 minutos)
```bash
# Scan rápido de teste
make scan-quick TARGET_URL=https://httpbin.org

# Visualizar resultados
make summary
```

## 🎯 Casos de Uso Comuns

### Aplicação Web Tradicional
```bash
make scan-standard TARGET_URL=https://mywebapp.com
```

### Single Page Application (React/Angular/Vue)
```bash
make scan-spa \
  TARGET_URL=https://myapp.com \
  SPA_BASE_URL=https://myapp.com \
  API_BASE_URL=https://api.myapp.com
```

### API REST
```bash
make scan-api \
  TARGET_URL=https://api.myservice.com \
  API_TOKEN=your-bearer-token
```

### Com Autenticação
```bash
make scan-standard \
  TARGET_URL=https://myapp.com \
  AUTH_USER=testuser \
  AUTH_PASS=testpass \
  LOGIN_URL=https://myapp.com/login
```

## 🔄 Integração CI/CD

### Jenkins
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'make ci-scan TARGET_URL=${TARGET_URL}'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*'
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'reports',
                reportFiles: '*.html',
                reportName: 'ZAP Security Report'
            ])
        }
    }
}
```

### GitLab CI
```yaml
security_scan:
  stage: test
  script:
    - make ci-scan TARGET_URL=$CI_ENVIRONMENT_URL
  artifacts:
    reports:
      junit: reports/*.xml
    paths:
      - reports/
```

### GitHub Actions
```yaml
- name: Security Scan
  run: make ci-scan TARGET_URL=${{ secrets.TARGET_URL }}
  
- name: Upload Reports
  uses: actions/upload-artifact@v3
  with:
    name: zap-reports
    path: reports/
```

## 📊 Monitoramento

### Setup Grafana + InfluxDB
```bash
# Iniciar stack de monitoramento
make start-full-monitoring

# Executar scan
make scan-standard TARGET_URL=https://myapp.com

# Processar métricas
make metrics

# Acessar dashboards
open http://localhost:3000  # Grafana (admin/admin123)
```

### Notificações Slack
```bash
# Configurar webhook Slack
export SLACK_WEBHOOK=https://hooks.slack.com/services/...

# Scan com notificação
make scan-standard TARGET_URL=https://myapp.com
make send-slack
```

## 🚪 Quality Gates

### Configurar Limites
```bash
# Quality gates rigorosos para produção
make ci-release \
  TARGET_URL=https://prod.myapp.com \
  MIN_SECURITY_SCORE=90 \
  MAX_MEDIUM_RISK=1 \
  MAX_TOTAL_ALERTS=5

# Quality gates flexíveis para desenvolvimento  
make ci-quick-check \
  TARGET_URL=https://dev.myapp.com \
  MIN_SECURITY_SCORE=60 \
  MAX_MEDIUM_RISK=10
```

### Exemplo de Output
```
🚪 Verificando quality gates...
✅ Security Score: 85/100 (mínimo: 80)
✅ Medium Risk: 2 (máximo: 5)
✅ Total Alerts: 8 (máximo: 20)
✅ Todos os quality gates passaram
```

## 🎨 Tipos de Aplicação

### E-commerce
```bash
make scan-ecommerce \
  TARGET_URL=https://shop.example.com \
  CUSTOMER_USER=customer@example.com \
  CUSTOMER_PASS=password123
```

### WordPress
```bash
make scan-wordpress \
  TARGET_URL=https://blog.example.com \
  WP_USER=admin \
  WP_PASS=admin123
```

### Microserviços
```bash
make scan-microservices \
  USER_SERVICE_URL=https://users.api.com \
  ORDER_SERVICE_URL=https://orders.api.com \
  PAYMENT_SERVICE_URL=https://payments.api.com
```

## 🐛 Troubleshooting Rápido

### Problema: Selenium não funciona
```bash
# Diagnóstico
make test-selenium

# Se falhar, reiniciar
make stop-selenium
make start-selenium
```

### Problema: Scan muito lento
```bash
# Usar scan rápido
make scan-quick TARGET_URL=https://myapp.com

# Ou ajustar timeouts
TARGET_URL=https://myapp.com \
MAX_SCAN_TIME=15 \
make scan-standard
```

### Problema: Muitos falsos positivos
```bash
# Editar zap_policy_config.yaml para desabilitar regras problemáticas
# Ou usar ambiente mais restritivo
make scan-standard TARGET_URL=https://myapp.com ENVIRONMENT=production
```

### Problema: Falta de memória
```bash
# Verificar uso
make health-check

# Limpar containers antigos
make clean-all

# Verificar espaço
df -h
```

## 📈 Comandos Essenciais

```bash
# ✅ BÁSICOS
make help                    # Ajuda completa
make setup                   # Configurar ambiente
make scan-quick              # Scan rápido (5-15 min)
make summary                 # Ver resultados

# 🔍 SCANS
make scan-standard           # Scan completo (20-45 min)
make scan-spa               # Para SPAs (30-60 min)
make scan-api               # Para APIs (15-30 min)

# 📊 RELATÓRIOS
make report                 # Processar para Grafana
make export-junit           # Gerar XML para CI/CD
make metrics               # Métricas avançadas

# 🚪 QUALITY GATES
make check-gates           # Verificar limites
make ci-scan              # CI/CD otimizado

# 🧹 MANUTENÇÃO
make clean                # Limpar relatórios
make clean-all            # Limpeza completa
make status               # Status dos serviços
```

## 🎯 Workflows Recomendados

### Para Desenvolvimento
```bash
# Setup inicial (uma vez)
make dev-setup

# Scan diário
make quick-dev-check TARGET_URL=https://dev.myapp.com
```

### Para Staging
```bash
# Scan completo antes do deploy
make scan-standard \
  TARGET_URL=https://staging.myapp.com \
  ENVIRONMENT=staging

# Verificar quality gates
make check-gates MIN_SECURITY_SCORE=75
```

### Para Produção
```bash
# Scan conservador
make scan-prod TARGET_URL=https://myapp.com

# Quality gates rigorosos
make check-gates \
  MIN_SECURITY_SCORE=90 \
  MAX_MEDIUM_RISK=2 \
  MAX_TOTAL_ALERTS=10
```

### Para SPAs Complexas
```bash
# Setup com Selenium
make start-selenium

# Scan SPA completo
make scan-spa \
  TARGET_URL=https://spa.myapp.com \
  AUTH_USER=testuser \
  AUTH_PASS=testpass

# Cleanup
make stop-selenium
```

## ⚙️ Configurações Avançadas

### Customizar Políticas
Edite `zap_policy_config.yaml`:
```yaml
disabledRules:
  - id: "10096"    # Timestamp Disclosure
    reason: "Falsos positivos"

ruleConfigs:
  - id: "40018"    # SQL Injection
    threshold: "HIGH"
    strength: "HIGH"
```

### Variáveis de Ambiente
```bash
# Arquivo .env
TARGET_URL=https://myapp.com
AUTH_USER=testuser
AUTH_PASS=testpass
ZAP_VERSION=2.14.0
ENVIRONMENT=staging
MIN_SECURITY_SCORE=80
SLACK_WEBHOOK=https://hooks.slack.com/...

# Carregar e executar
source .env && make scan-standard
```

### Docker Compose Avançado
```bash
# SPA com Selenium Grid
docker-compose --profile zap-with-grid up

# Com monitoramento completo
docker-compose --profile zap-with-grid --profile monitoring up

# Com servidor de relatórios
docker-compose --profile zap-only --profile web-reports up
```

## 📱 Comandos para Mobile

```bash
# Setup para testes de API mobile
make scan-api \
  TARGET_URL=https://mobile-api.myapp.com \
  API_TOKEN=mobile-app-token

# Headers customizados para mobile
USER_AGENT="MobileApp/1.0 (iOS)" \
make scan-api TARGET_URL=https://mobile-api.com
```

## 🎉 Verificação Final

Após o setup, teste com:
```bash
# Teste básico
make scan-quick TARGET_URL=https://httpbin.org

# Se funcionou, você verá:
# ✅ Varredura rápida concluída
# 📊 Relatórios em: ./reports
# 🎯 Score de segurança: XX/100
```

## 🆘 Ajuda Rápida

```bash
make help                    # Ajuda geral
make help-examples          # Exemplos detalhados  
make help-ci               # Integração CI/CD
make help-troubleshooting  # Resolução de problemas
make show-config           # Ver configuração atual
make status               # Status dos serviços
```

---

**🚀 Pronto para começar!** 

Teste agora: `make scan-quick TARGET_URL=https://httpbin.org`