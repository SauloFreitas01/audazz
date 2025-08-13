# 🔒 AUDAZZ - AUTOMATED DAST

Framework para automação de testes de segurança usando OWASP ZAP via linha de comando e API, sem necessidade de interface gráfica.

## 📋 Índice

- [Características](#características)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Uso Básico](#uso-básico)
- [Tipos de Varredura](#tipos-de-varredura)
- [Configurações Avançadas](#configurações-avançadas)
- [Integração CI/CD](#integração-cicd)
- [Monitoramento e Relatórios](#monitoramento-e-relatórios)
- [Troubleshooting](#troubleshooting)

## ✨ Características

- 🚀 **Automação Completa**: Execução via linha de comando sem interface gráfica
- 🎯 **Múltiplos Tipos**: Suporte para SPAs, APIs REST, GraphQL, aplicações tradicionais
- 🔧 **Configurável**: Políticas customizadas para reduzir falsos positivos
- 📊 **Relatórios**: Múltiplos formatos (JSON, HTML, XML) para integração
- 🐳 **Containerizado**: Execução via Docker com Selenium Grid para SPAs
- 🔄 **CI/CD Ready**: Integração fácil com pipelines de deployment
- 📈 **Métricas**: Processamento para Grafana e sistemas de monitoramento

## 🛠 Pré-requisitos

### Básico
- Docker 20.10+
- Docker Compose 2.0+
- Python 3.8+ (para processamento de relatórios)

### Para SPAs com Selenium
- 4GB+ de RAM disponível
- Rede Docker configurada

### Para integração CI/CD
- Jenkins, GitLab CI, GitHub Actions, ou similar
- Acesso ao registry Docker

## 📦 Instalação

### 1. Clone o repositório
```bash
git clone <repository-url>
cd owasp-zap-automation
```

### 2. Torne o script executável
```bash
chmod +x run_zap_automation.sh
```

### 3. Verificar Docker
```bash
docker --version
docker-compose --version
```

### 4. Pull das imagens necessárias
```bash
docker pull owasp/zap2docker-stable:2.14.0
docker pull selenium/hub:4.15.0-20231129
docker pull selenium/node-chrome:4.15.0-20231129
```

## ⚙️ Configuração

### Estrutura de Arquivos
```
owasp-zap-automation/
├── zap_automation_plan.yaml          # Configuração principal
├── zap_spa_automation.yaml           # Configuração para SPAs
├── zap_policy_config.yaml            # Políticas otimizadas
├── run_zap_automation.sh             # Script principal
├── docker-compose.yaml               # Orquestração Docker
├── examples/
│   └── zap_application_examples.yaml # Exemplos por tipo de app
├── reports/                          # Relatórios gerados
├── config/                           # Configurações extras
└── grafana/                          # Dashboards Grafana
```

### Variáveis de Ambiente

#### Obrigatórias
```bash
export TARGET_URL="https://example.com"
```

#### Opcionais
```bash
export ZAP_VERSION="2.14.0"
export AUTH_USER="testuser"
export AUTH_PASS="testpass"
export LOGIN_URL="https://example.com/login"
export SPA_BASE_URL="https://app.example.com"
export API_BASE_URL="https://api.example.com"
export SELENIUM_GRID_URL="http://selenium-hub:4444/wd/hub"
```

## 🚀 Uso Básico

### Varredura Padrão
```bash
TARGET_URL=https://example.com ./run_zap_automation.sh standard
```

### Varredura SPA (React/Angular/Vue)
```bash
TARGET_URL=https://app.example.com ./run_zap_automation.sh spa
```

### Varredura Rápida (CI/CD)
```bash
TARGET_URL=https://staging.example.com ./run_zap_automation.sh quick
```

### Com Autenticação
```bash
TARGET_URL=https://example.com \
AUTH_USER=testuser \
AUTH_PASS=testpass \
LOGIN_URL=https://example.com/login \
./run_zap_automation.sh standard
```

## 🎯 Tipos de Varredura

### 1. Standard Scan
Varredura completa para aplicações web tradicionais.

**Características:**
- Spider tradicional
- Passive scan
- Active scan com políticas otimizadas
- Relatórios em múltiplos formatos

**Duração:** 20-45 minutos

### 2. SPA Scan
Otimizada para Single Page Applications.

**Características:**
- AJAX Spider com Selenium
- Detecção de DOM XSS
- Configurações específicas para SPAs
- Integração com Selenium Grid

**Duração:** 30-60 minutos

### 3. Quick Scan
Varredura rápida para CI/CD.

**Características:**
- Baseline scan do ZAP
- Foco em vulnerabilidades críticas
- Timeout reduzido
- Relatório simplificado

**Duração:** 5-15 minutos

### 4. API Scan
Específica para APIs REST/GraphQL.

**Características:**
- Import de especificações OpenAPI
- Testes específicos para APIs
- Autenticação via Bearer Token
- Validação de CORS

**Duração:** 15-30 minutos

## 🔧 Configurações Avançadas

### Personalizar Políticas de Varredura

Edite `zap_policy_config.yaml` para:

1. **Desabilitar regras** que geram falsos positivos
2. **Ajustar thresholds** (LOW, MEDIUM, HIGH)
3. **Configurar strength** (LOW, MEDIUM, HIGH)
4. **Definir timeouts** por regra

Exemplo:
```yaml
disabledRules:
  - id: "10096"
    name: "Timestamp Disclosure"
    reason: "Falsos positivos frequentes"

ruleConfigs:
  - id: "40018" # SQL Injection
    threshold: "HIGH"
    strength: "HIGH"
```

### Configurar para Diferentes Ambientes

```bash
# Desenvolvimento - Mais agressivo
ENVIRONMENT=development ./run_zap_automation.sh standard

# Produção - Mais conservador
ENVIRONMENT=production ./run_zap_automation.sh quick
```

### Usar Docker Compose

#### SPA com Selenium Grid
```bash
TARGET_URL=https://app.example.com \
docker-compose --profile zap-with-grid up
```

#### Com Monitoramento
```bash
TARGET_URL=https://example.com \
docker-compose --profile zap-only --profile monitoring up
```

## 🔄 Integração CI/CD

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    
    environment {
        TARGET_URL = "${params.TARGET_URL}"
        ZAP_VERSION = "2.14.0"
    }
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    sh '''
                        chmod +x run_zap_automation.sh
                        ./run_zap_automation.sh quick
                    '''
                }
            }
        }
        
        stage('Process Results') {
            steps {
                script {
                    // Publicar relatórios
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'reports',
                        reportFiles: '*.html',
                        reportName: 'ZAP Security Report'
                    ])
                    
                    // Processar métricas
                    sh './run_zap_automation.sh process-reports'
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*', fingerprint: true
        }
    }
}
```

### GitHub Actions
```yaml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Run ZAP Security Scan
      env:
        TARGET_URL: ${{ secrets.TARGET_URL }}
      run: |
        chmod +x run_zap_automation.sh
        ./run_zap_automation.sh quick
    
    - name: Upload Reports
      uses: actions/upload-artifact@v3
      with:
        name: zap-reports
        path: reports/
```

### GitLab CI
```yaml
variables:
  ZAP_VERSION: "2.14.0"

security_scan:
  stage: test
  image: docker:latest
  services:
    - docker:dind
  script:
    - chmod +x run_zap_automation.sh
    - TARGET_URL=$STAGING_URL ./run_zap_automation.sh quick
  artifacts:
    reports:
      junit: reports/*.xml
    paths:
      - reports/
    expire_in: 1 week
  only:
    - merge_requests
    - main
```

## 📊 Monitoramento e Relatórios

### Integração com Grafana

1. **Iniciar stack de monitoramento:**
```bash
docker-compose --profile monitoring up -d
```

2. **Acessar Grafana:** http://localhost:3000
   - Usuário: admin
   - Senha: admin123

3. **Processar métricas:**
```bash
./run_zap_automation.sh process-reports
```

### Métricas Disponíveis

- Total de vulnerabilidades por criticidade
- Tendências de segurança ao longo do tempo
- Comparação entre ambientes
- Time to remediation
- Cobertura de testes

### Alertas Customizados

Configure alertas no Grafana para:
- Vulnerabilidades críticas detectadas
- Aumento significativo de alertas
- Falhas no processo de scan

## 🐛 Troubleshooting

### Problemas Comuns

#### 1. "Target URL não acessível"
```bash
# Verificar conectividade
curl -I $TARGET_URL

# Verificar DNS
nslookup $(echo $TARGET_URL | sed 's|https\?://||' | cut -d'/' -f1)
```

#### 2. "Selenium Grid não responde"
```bash
# Verificar status do grid
docker logs selenium-hub

# Restart do grid
./run_zap_automation.sh cleanup-selenium
./run_zap_automation.sh setup-selenium
```

#### 3. "Memória insuficiente"
```bash
# Verificar uso de memória
docker stats

# Aumentar limites no docker-compose.yaml
environment:
  - JAVA_OPTS=-Xmx4g
```

#### 4. "Falha na autenticação"
```bash
# Testar autenticação manualmente
curl -X POST $LOGIN_URL \
  -d "username=$AUTH_USER&password=$AUTH_PASS" \
  -v
```

### Debug Mode

Execute com debug habilitado:
```bash
DEBUG=true TARGET_URL=https://example.com ./run_zap_automation.sh standard
```

### Logs Detalhados

Verificar logs do container:
```bash
docker logs owasp-zap-automation
```

### Performance Tuning

Para ambientes com recursos limitados:

1. **Reduzir paralelismo:**
```yaml
parameters:
  threadPerHost: 1
  maxDuration: 15
```

2. **Limitar regras ativas:**
```yaml
disabledRules:
  - "10096"  # Timestamp
  - "10094"  # Base64
  - "10049"  # Content Cacheability
```

3. **Configurar timeouts:**
```yaml
performanceOptimization:
  maxScanTimePerRule: 180
  maxRequestsPerRule: 50
```

## 📝 Exemplos Práticos

### E-commerce
```bash
TARGET_URL=https://shop.example.com \
AUTH_USER=customer@example.com \
AUTH_PASS=password123 \
./run_zap_automation.sh standard
```

### API REST
```bash
TARGET_URL=https://api.example.com \
API_TOKEN=bearer_token_here \
./run_zap_automation.sh standard rest_api_config.yaml
```

### WordPress
```bash
TARGET_URL=https://blog.example.com \
AUTH_USER=wpuser \
AUTH_PASS=wppass \
./run_zap_automation.sh standard wordpress_config.yaml
```

## 🤝 Contribuindo

1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para detalhes.

## 🔗 Links Úteis

- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [OWASP Top 10](https://owasp.org/Top10/)
- [ZAP Docker Images](https://hub.docker.com/r/owasp/zap2docker-stable)
- [Selenium Grid Documentation](https://selenium-python.readthedocs.io/)