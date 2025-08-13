#!/usr/bin/env python3
"""
OWASP ZAP - Processador de Métricas
Arquivo: process_zap_metrics.py
Versão: 1.0
Descrição: Processa relatórios ZAP e envia métricas para sistemas de monitoramento
"""

import json
import os
import sys
import argparse
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ZAPMetricsProcessor:
    """Processador de métricas do OWASP ZAP"""
    
    def __init__(self, reports_dir: str = "./reports"):
        self.reports_dir = Path(reports_dir)
        self.metrics = {}
        
    def find_latest_report(self, format_type: str = "json") -> Optional[Path]:
        """Encontra o relatório mais recente"""
        pattern = f"*.{format_type}"
        reports = list(self.reports_dir.glob(pattern))
        
        if not reports:
            logger.warning(f"Nenhum relatório {format_type} encontrado em {self.reports_dir}")
            return None
            
        # Ordenar por data de modificação
        latest = max(reports, key=lambda p: p.stat().st_mtime)
        logger.info(f"Relatório mais recente: {latest}")
        return latest
    
    def process_json_report(self, report_path: Path) -> Dict:
        """Processa relatório JSON do ZAP"""
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extrair informações do site
            site = data.get('site', [{}])[0] if data.get('site') else {}
            alerts = site.get('alerts', [])
            
            # Métricas básicas
            metrics = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'target_url': site.get('@name', 'unknown'),
                'total_alerts': len(alerts),
                'scan_completed': True,
                'report_path': str(report_path)
            }
            
            # Contadores por risco
            risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
            
            # Vulnerabilidades por categoria OWASP
            owasp_categories = {}
            
            # Detalhes das vulnerabilidades
            vulnerability_details = []
            
            for alert in alerts:
                # Risco
                risk_desc = alert.get('riskdesc', '')
                risk = risk_desc.split(' ')[0] if risk_desc else 'Unknown'
                if risk in risk_counts:
                    risk_counts[risk] += 1
                
                # Categoria OWASP
                alert_name = alert.get('name', '')
                owasp_categories[alert_name] = owasp_categories.get(alert_name, 0) + 1
                
                # Detalhes da vulnerabilidade
                vulnerability_details.append({
                    'name': alert_name,
                    'risk': risk,
                    'confidence': alert.get('confidence', ''),
                    'count': len(alert.get('instances', [])),
                    'description': alert.get('desc', '')[:200],  # Primeiros 200 chars
                    'solution': alert.get('solution', '')[:200]
                })
            
            # Adicionar contadores às métricas
            metrics.update({
                'high_risk': risk_counts['High'],
                'medium_risk': risk_counts['Medium'],
                'low_risk': risk_counts['Low'],
                'informational': risk_counts['Informational'],
                'owasp_categories': owasp_categories,
                'vulnerability_details': vulnerability_details
            })
            
            # Calcular score de segurança (0-100)
            security_score = self.calculate_security_score(risk_counts)
            metrics['security_score'] = security_score
            
            return metrics
            
        except Exception as e:
            logger.error(f"Erro ao processar relatório JSON: {e}")
            return {}
    
    def calculate_security_score(self, risk_counts: Dict) -> int:
        """Calcula score de segurança baseado nas vulnerabilidades"""
        # Score inicial: 100
        score = 100
        
        # Penalidades por risco
        score -= risk_counts.get('High', 0) * 20      # -20 por vulnerabilidade alta
        score -= risk_counts.get('Medium', 0) * 10    # -10 por vulnerabilidade média
        score -= risk_counts.get('Low', 0) * 2        # -2 por vulnerabilidade baixa
        
        # Score mínimo: 0
        return max(0, score)
    
    def export_to_grafana_json(self, metrics: Dict, output_file: str = None) -> str:
        """Exporta métricas no formato para Grafana"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"zap-metrics-{timestamp}.json"
        
        grafana_metrics = {
            "timestamp": metrics.get('timestamp'),
            "target": metrics.get('target_url'),
            "metrics": [
                {
                    "name": "zap_vulnerabilities_total",
                    "value": metrics.get('total_alerts', 0),
                    "labels": {"target_url": metrics.get('target_url', 'unknown')}
                },
                {
                    "name": "zap_high_risk_total",
                    "value": metrics.get('high_risk', 0),
                    "labels": {"risk_level": "High", "target_url": metrics.get('target_url')}
                },
                {
                    "name": "zap_medium_risk_total", 
                    "value": metrics.get('medium_risk', 0),
                    "labels": {"risk_level": "Medium", "target_url": metrics.get('target_url')}
                },
                {
                    "name": "zap_low_risk_total",
                    "value": metrics.get('low_risk', 0),
                    "labels": {"risk_level": "Low", "target_url": metrics.get('target_url')}
                },
                {
                    "name": "zap_security_score",
                    "value": metrics.get('security_score', 0),
                    "labels": {"target_url": metrics.get('target_url')}
                },
                {
                    "name": "zap_scan_status",
                    "value": 1 if metrics.get('scan_completed') else 0,
                    "labels": {"target_url": metrics.get('target_url')}
                }
            ]
        }
        
        output_path = self.reports_dir / output_file
        with open(output_path, 'w') as f:
            json.dump(grafana_metrics, f, indent=2)
        
        logger.info(f"Métricas para Grafana salvas em: {output_path}")
        return str(output_path)
    
    def send_to_prometheus_pushgateway(self, metrics: Dict, gateway_url: str) -> bool:
        """Envia métricas para Prometheus Push Gateway"""
        try:
            # Formato Prometheus
            prometheus_metrics = []
            target_url = metrics.get('target_url', 'unknown').replace('://', '_').replace('.', '_')
            
            prometheus_metrics.extend([
                f'zap_vulnerabilities_total{{target_url="{metrics.get("target_url")}"}} {metrics.get("total_alerts", 0)}',
                f'zap_high_risk_total{{target_url="{metrics.get("target_url")}"}} {metrics.get("high_risk", 0)}',
                f'zap_medium_risk_total{{target_url="{metrics.get("target_url")}"}} {metrics.get("medium_risk", 0)}',
                f'zap_low_risk_total{{target_url="{metrics.get("target_url")}"}} {metrics.get("low_risk", 0)}',
                f'zap_security_score{{target_url="{metrics.get("target_url")}"}} {metrics.get("security_score", 0)}',
                f'zap_scan_status{{target_url="{metrics.get("target_url")}"}} {1 if metrics.get("scan_completed") else 0}'
            ])
            
            # Enviar para Push Gateway
            data = '\n'.join(prometheus_metrics)
            
            response = requests.post(
                f"{gateway_url}/metrics/job/zap-security-scan/instance/{target_url}",
                data=data,
                headers={'Content-Type': 'text/plain'},
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info(f"Métricas enviadas com sucesso para {gateway_url}")
                return True
            else:
                logger.error(f"Falha ao enviar métricas: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao enviar métricas para Prometheus: {e}")
            return False
    
    def send_to_influxdb(self, metrics: Dict, influx_config: Dict) -> bool:
        """Envia métricas para InfluxDB"""
        try:
            from influxdb_client import InfluxDBClient, Point
            from influxdb_client.client.write_api import SYNCHRONOUS
            
            client = InfluxDBClient(
                url=influx_config['url'],
                token=influx_config['token'],
                org=influx_config['org']
            )
            
            write_api = client.write_api(write_option=SYNCHRONOUS)
            
            # Criar pontos de dados
            points = []
            
            # Ponto principal com todas as métricas
            point = Point("zap_security_scan") \
                .tag("target_url", metrics.get('target_url', 'unknown')) \
                .tag("environment", os.environ.get('ENVIRONMENT', 'unknown')) \
                .field("total_alerts", metrics.get('total_alerts', 0)) \
                .field("high_risk", metrics.get('high_risk', 0)) \
                .field("medium_risk", metrics.get('medium_risk', 0)) \
                .field("low_risk", metrics.get('low_risk', 0)) \
                .field("informational", metrics.get('informational', 0)) \
                .field("security_score", metrics.get('security_score', 0)) \
                .field("scan_completed", 1 if metrics.get('scan_completed') else 0) \
                .time(datetime.now(timezone.utc))
            
            points.append(point)
            
            # Pontos individuais por vulnerabilidade
            for vuln in metrics.get('vulnerability_details', []):
                vuln_point = Point("zap_vulnerability") \
                    .tag("target_url", metrics.get('target_url')) \
                    .tag("vulnerability_name", vuln['name']) \
                    .tag("risk_level", vuln['risk']) \
                    .tag("confidence", vuln['confidence']) \
                    .field("count", vuln['count']) \
                    .time(datetime.now(timezone.utc))
                points.append(vuln_point)
            
            # Escrever no InfluxDB
            write_api.write(bucket=influx_config['bucket'], record=points)
            
            logger.info(f"Métricas enviadas com sucesso para InfluxDB")
            return True
            
        except ImportError:
            logger.error("InfluxDB client não instalado: pip install influxdb-client")
            return False
        except Exception as e:
            logger.error(f"Erro ao enviar métricas para InfluxDB: {e}")
            return False
    
    def generate_summary_report(self, metrics: Dict) -> str:
        """Gera relatório resumido em texto"""
        template = f"""
🔒 RELATÓRIO DE SEGURANÇA - OWASP ZAP
═══════════════════════════════════════════════════════════════

📊 RESUMO EXECUTIVO
Target: {metrics.get('target_url', 'N/A')}
Data/Hora: {metrics.get('timestamp', 'N/A')}
Score de Segurança: {metrics.get('security_score', 0)}/100

📈 DISTRIBUIÇÃO DE VULNERABILIDADES
Total de Alertas: {metrics.get('total_alerts', 0)}
├── 🔴 Alto Risco: {metrics.get('high_risk', 0)}
├── 🟡 Médio Risco: {metrics.get('medium_risk', 0)}
├── 🔵 Baixo Risco: {metrics.get('low_risk', 0)}
└── ⚪ Informativo: {metrics.get('informational', 0)}

🚨 AÇÃO REQUERIDA
"""
        
        # Adicionar recomendações baseadas no score
        score = metrics.get('security_score', 0)
        high_risk = metrics.get('high_risk', 0)
        
        if high_risk > 0:
            template += f"❌ CRÍTICO: {high_risk} vulnerabilidades de ALTO RISCO detectadas!\n"
            template += "   → Correção IMEDIATA necessária antes do deploy\n\n"
        elif score < 70:
            template += "⚠️  ATENÇÃO: Score de segurança abaixo do recomendado (70+)\n"
            template += "   → Revisar e corrigir vulnerabilidades médias\n\n"
        elif score < 90:
            template += "✅ BOM: Score de segurança aceitável\n"
            template += "   → Considerar corrigir vulnerabilidades restantes\n\n"
        else:
            template += "🎉 EXCELENTE: Score de segurança muito bom!\n\n"
        
        # Top vulnerabilidades
        if metrics.get('vulnerability_details'):
            template += "🎯 TOP VULNERABILIDADES:\n"
            top_vulns = sorted(
                metrics['vulnerability_details'], 
                key=lambda x: (x['risk'] == 'High', x['risk'] == 'Medium', x['count']), 
                reverse=True
            )[:5]
            
            for i, vuln in enumerate(top_vulns, 1):
                risk_emoji = {'High': '🔴', 'Medium': '🟡', 'Low': '🔵'}.get(vuln['risk'], '⚪')
                template += f"   {i}. {risk_emoji} [{vuln['risk']}] {vuln['name']} ({vuln['count']} instâncias)\n"
        
        template += f"\n📁 Relatório completo: {metrics.get('report_path', 'N/A')}"
        template += "\n═══════════════════════════════════════════════════════════════"
        
        return template
    
    def send_slack_notification(self, metrics: Dict, webhook_url: str) -> bool:
        """Envia notificação para Slack"""
        try:
            score = metrics.get('security_score', 0)
            high_risk = metrics.get('high_risk', 0)
            
            # Determinar cor baseada no score
            if high_risk > 0:
                color = "danger"
                status = "🔴 CRÍTICO"
            elif score < 70:
                color = "warning" 
                status = "🟡 ATENÇÃO"
            else:
                color = "good"
                status = "✅ OK"
            
            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"ZAP Security Scan - {status}",
                        "title_link": metrics.get('target_url'),
                        "fields": [
                            {
                                "title": "Target",
                                "value": metrics.get('target_url'),
                                "short": True
                            },
                            {
                                "title": "Security Score",
                                "value": f"{score}/100",
                                "short": True
                            },
                            {
                                "title": "Alto Risco",
                                "value": str(high_risk),
                                "short": True
                            },
                            {
                                "title": "Médio Risco", 
                                "value": str(metrics.get('medium_risk', 0)),
                                "short": True
                            },
                            {
                                "title": "Total de Alertas",
                                "value": str(metrics.get('total_alerts', 0)),
                                "short": True
                            },
                            {
                                "title": "Timestamp",
                                "value": metrics.get('timestamp', 'N/A'),
                                "short": True
                            }
                        ],
                        "footer": "OWASP ZAP Security Scanner",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=30)
            
            if response.status_code == 200:
                logger.info("Notificação Slack enviada com sucesso")
                return True
            else:
                logger.error(f"Falha ao enviar notificação Slack: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao enviar notificação Slack: {e}")
            return False
    
    def send_teams_notification(self, metrics: Dict, webhook_url: str) -> bool:
        """Envia notificação para Microsoft Teams"""
        try:
            score = metrics.get('security_score', 0)
            high_risk = metrics.get('high_risk', 0)
            
            # Determinar cor e status
            if high_risk > 0:
                theme_color = "FF0000"  # Vermelho
                status = "🔴 CRÍTICO"
            elif score < 70:
                theme_color = "FFA500"  # Laranja
                status = "🟡 ATENÇÃO"
            else:
                theme_color = "00FF00"  # Verde
                status = "✅ OK"
            
            payload = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": f"ZAP Security Scan - {metrics.get('target_url')}",
                "themeColor": theme_color,
                "title": f"ZAP Security Scan Results - {status}",
                "sections": [
                    {
                        "activityTitle": "Security Assessment Completed",
                        "activitySubtitle": f"Target: {metrics.get('target_url')}",
                        "facts": [
                            {
                                "name": "Security Score",
                                "value": f"{score}/100"
                            },
                            {
                                "name": "High Risk",
                                "value": str(high_risk)
                            },
                            {
                                "name": "Medium Risk",
                                "value": str(metrics.get('medium_risk', 0))
                            },
                            {
                                "name": "Low Risk", 
                                "value": str(metrics.get('low_risk', 0))
                            },
                            {
                                "name": "Total Alerts",
                                "value": str(metrics.get('total_alerts', 0))
                            },
                            {
                                "name": "Timestamp",
                                "value": metrics.get('timestamp', 'N/A')
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=30)
            
            if response.status_code == 200:
                logger.info("Notificação Teams enviada com sucesso")
                return True
            else:
                logger.error(f"Falha ao enviar notificação Teams: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao enviar notificação Teams: {e}")
            return False
    
    def export_junit_xml(self, metrics: Dict, output_file: str = None) -> str:
        """Exporta resultados no formato JUnit XML para CI/CD"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"zap-junit-{timestamp}.xml"
        
        # Criar estrutura XML JUnit
        testsuites = ET.Element("testsuites")
        testsuites.set("name", "ZAP Security Tests")
        testsuites.set("tests", str(metrics.get('total_alerts', 0)))
        testsuites.set("failures", str(metrics.get('high_risk', 0) + metrics.get('medium_risk', 0)))
        testsuites.set("errors", "0")
        testsuites.set("time", "0")
        
        # Test suite para cada nível de risco
        for risk_level in ['High', 'Medium', 'Low']:
            testsuite = ET.SubElement(testsuites, "testsuite")
            testsuite.set("name", f"Security Tests - {risk_level} Risk")
            
            risk_count = metrics.get(f'{risk_level.lower()}_risk', 0)
            testsuite.set("tests", str(risk_count))
            testsuite.set("failures", str(risk_count) if risk_level in ['High', 'Medium'] else "0")
            testsuite.set("errors", "0")
            testsuite.set("time", "0")
            
            # Casos de teste individuais
            for vuln in metrics.get('vulnerability_details', []):
                if vuln['risk'] == risk_level:
                    testcase = ET.SubElement(testsuite, "testcase")
                    testcase.set("classname", f"ZAP.{risk_level}Risk")
                    testcase.set("name", vuln['name'])
                    testcase.set("time", "0")
                    
                    # Falha para High e Medium risk
                    if risk_level in ['High', 'Medium']:
                        failure = ET.SubElement(testcase, "failure")
                        failure.set("message", f"{vuln['name']} - {vuln['risk']} Risk")
                        failure.text = vuln['description']
        
        # Salvar arquivo
        output_path = self.reports_dir / output_file
        tree = ET.ElementTree(testsuites)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
        
        logger.info(f"Relatório JUnit XML salvo em: {output_path}")
        return str(output_path)
    
    def check_security_gates(self, metrics: Dict) -> Tuple[bool, List[str]]:
        """Verifica quality gates de segurança"""
        passed = True
        violations = []
        
        # Gate 1: Nenhuma vulnerabilidade de alto risco
        high_risk = metrics.get('high_risk', 0)
        if high_risk > 0:
            passed = False
            violations.append(f"❌ {high_risk} vulnerabilidades de ALTO RISCO detectadas")
        
        # Gate 2: Score de segurança mínimo
        min_score = int(os.environ.get('MIN_SECURITY_SCORE', '70'))
        score = metrics.get('security_score', 0)
        if score < min_score:
            passed = False
            violations.append(f"❌ Score de segurança {score} abaixo do mínimo {min_score}")
        
        # Gate 3: Limite de vulnerabilidades médias
        max_medium = int(os.environ.get('MAX_MEDIUM_RISK', '5'))
        medium_risk = metrics.get('medium_risk', 0)
        if medium_risk > max_medium:
            passed = False
            violations.append(f"❌ {medium_risk} vulnerabilidades médias excedem limite de {max_medium}")
        
        # Gate 4: Limit total de vulnerabilidades
        max_total = int(os.environ.get('MAX_TOTAL_ALERTS', '20'))
        total_alerts = metrics.get('total_alerts', 0)
        if total_alerts > max_total:
            passed = False
            violations.append(f"❌ {total_alerts} alertas excedem limite de {max_total}")
        
        if passed:
            logger.info("✅ Todos os quality gates de segurança passaram")
        else:
            logger.warning("❌ Alguns quality gates de segurança falharam:")
            for violation in violations:
                logger.warning(f"  {violation}")
        
        return passed, violations


def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description="Processador de Métricas OWASP ZAP")
    parser.add_argument("--reports-dir", default="./reports", help="Diretório dos relatórios")
    parser.add_argument("--format", choices=["json", "xml"], default="json", help="Formato do relatório")
    parser.add_argument("--output-grafana", help="Arquivo de saída para Grafana")
    parser.add_argument("--output-junit", help="Arquivo de saída JUnit XML")
    parser.add_argument("--prometheus-gateway", help="URL do Prometheus Push Gateway")
    parser.add_argument("--influxdb-url", help="URL do InfluxDB")
    parser.add_argument("--influxdb-token", help="Token do InfluxDB")
    parser.add_argument("--influxdb-org", help="Organização do InfluxDB")
    parser.add_argument("--influxdb-bucket", help="Bucket do InfluxDB")
    parser.add_argument("--slack-webhook", help="URL do webhook Slack")
    parser.add_argument("--teams-webhook", help="URL do webhook Teams")
    parser.add_argument("--check-gates", action="store_true", help="Verificar quality gates")
    parser.add_argument("--summary", action="store_true", help="Gerar relatório resumido")
    
    args = parser.parse_args()
    
    # Inicializar processador
    processor = ZAPMetricsProcessor(args.reports_dir)
    
    # Encontrar relatório mais recente
    latest_report = processor.find_latest_report(args.format)
    if not latest_report:
        logger.error("Nenhum relatório encontrado")
        sys.exit(1)
    
    # Processar relatório
    if args.format == "json":
        metrics = processor.process_json_report(latest_report)
    else:
        logger.error("Formato XML ainda não implementado")
        sys.exit(1)
    
    if not metrics:
        logger.error("Falha ao processar relatório")
        sys.exit(1)
    
    # Gerar saídas conforme solicitado
    try:
        # Grafana JSON
        if args.output_grafana:
            processor.export_to_grafana_json(metrics, args.output_grafana)
        
        # JUnit XML
        if args.output_junit:
            processor.export_junit_xml(metrics, args.output_junit)
        
        # Prometheus Push Gateway
        if args.prometheus_gateway:
            processor.send_to_prometheus_pushgateway(metrics, args.prometheus_gateway)
        
        # InfluxDB
        if all([args.influxdb_url, args.influxdb_token, args.influxdb_org, args.influxdb_bucket]):
            influx_config = {
                'url': args.influxdb_url,
                'token': args.influxdb_token,
                'org': args.influxdb_org,
                'bucket': args.influxdb_bucket
            }
            processor.send_to_influxdb(metrics, influx_config)
        
        # Notificações
        if args.slack_webhook:
            processor.send_slack_notification(metrics, args.slack_webhook)
        
        if args.teams_webhook:
            processor.send_teams_notification(metrics, args.teams_webhook)
        
        # Relatório resumido
        if args.summary:
            summary = processor.generate_summary_report(metrics)
            print(summary)
            
            # Salvar resumo em arquivo
            summary_file = processor.reports_dir / f"security-summary-{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(summary_file, 'w') as f:
                f.write(summary)
            logger.info(f"Resumo salvo em: {summary_file}")
        
        # Verificar quality gates
        if args.check_gates:
            gates_passed, violations = processor.check_security_gates(metrics)
            
            if not gates_passed:
                logger.error("Quality gates de segurança falharam:")
                for violation in violations:
                    logger.error(f"  {violation}")
                sys.exit(1)
            else:
                logger.info("✅ Todos os quality gates passaram")
        
        # Sempre exportar métricas básicas
        if not any([args.output_grafana, args.output_junit, args.prometheus_gateway]):
            # Export padrão para Grafana
            default_output = processor.export_to_grafana_json(metrics)
            logger.info(f"Métricas exportadas por padrão: {default_output}")
        
        logger.info("Processamento de métricas concluído com sucesso")
        
    except Exception as e:
        logger.error(f"Erro durante processamento: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


# =============================================================================
# EXEMPLOS DE USO
# =============================================================================
"""
# Uso básico - processar último relatório e gerar métricas para Grafana
python3 process_zap_metrics.py --summary

# Enviar para Prometheus Push Gateway
python3 process_zap_metrics.py \
    --prometheus-gateway http://prometheus-pushgateway:9091

# Enviar para InfluxDB
python3 process_zap_metrics.py \
    --influxdb-url http://influxdb:8086 \
    --influxdb-token your-token-here \
    --influxdb-org your-org \
    --influxdb-bucket zap-metrics

# Notificações Slack
python3 process_zap_metrics.py \
    --slack-webhook https://hooks.slack.com/services/... \
    --summary

# Verificar quality gates (para CI/CD)
MIN_SECURITY_SCORE=80 \
MAX_MEDIUM_RISK=3 \
MAX_TOTAL_ALERTS=15 \
python3 process_zap_metrics.py --check-gates

# Gerar JUnit XML para Jenkins/GitLab
python3 process_zap_metrics.py \
    --output-junit zap-results.xml \
    --check-gates

# Uso completo
python3 process_zap_metrics.py \
    --reports-dir ./reports \
    --output-grafana zap-grafana-metrics.json \
    --output-junit zap-junit-results.xml \
    --prometheus-gateway http://prometheus:9091 \
    --slack-webhook https://hooks.slack.com/... \
    --check-gates \
    --summary
"""