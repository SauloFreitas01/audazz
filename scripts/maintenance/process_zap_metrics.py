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
        """Encontra o relatório mais recente considerando a nova estrutura de diretórios"""
        # Buscar recursivamente por arquivos do formato especificado
        if format_type == "json":
            # Buscar em diretórios json/ e arquivos .json (mas não .sarif.json)
            pattern_paths = [
                f"**/{format_type}/*.{format_type}",  # Arquivos .json em diretórios json/
                f"**/*.{format_type}"  # Arquivos .json em qualquer lugar (fallback)
            ]
        else:
            pattern_paths = [f"**/*.{format_type}"]
        
        reports = []
        for pattern in pattern_paths:
            found_reports = list(self.reports_dir.glob(pattern))
            # Filtrar arquivos .sarif.json se estivermos procurando por .json
            if format_type == "json":
                found_reports = [r for r in found_reports if not r.name.endswith('.sarif.json')]
            reports.extend(found_reports)
        
        if not reports:
            logger.warning(f"Nenhum relatório {format_type} encontrado em {self.reports_dir}")
            return None
            
        # Remover duplicatas e ordenar por data de modificação
        reports = list(set(reports))
        latest = max(reports, key=lambda p: p.stat().st_mtime)
        logger.info(f"Relatório mais recente: {latest}")
        return latest
    
    def find_reports_by_domain(self, domain: str, format_type: str = "json") -> List[Path]:
        """Encontra todos os relatórios para um domínio específico"""
        domain_pattern = f"**/{domain}/**/*.{format_type}"
        reports = list(self.reports_dir.glob(domain_pattern))
        
        # Filtrar arquivos .sarif.json se estivermos procurando por .json
        if format_type == "json":
            reports = [r for r in reports if not r.name.endswith('.sarif.json')]
            
        # Ordenar por data de modificação (mais recente primeiro)
        reports.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        
        logger.info(f"Encontrados {len(reports)} relatórios para domínio {domain}")
        return reports
    
    def get_available_domains(self) -> List[str]:
        """Lista todos os domínios disponíveis nos relatórios"""
        domains = []
        for item in self.reports_dir.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                domains.append(item.name)
        
        logger.info(f"Domínios disponíveis: {domains}")
        return domains
    
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
    
    def export_to_metrics_json(self, metrics: Dict, output_file: str = None) -> str:
        """Exporta métricas no formato JSON simples"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"zap-metrics-{timestamp}.json"

        metrics_export = {
            "timestamp": metrics.get('timestamp'),
            "target": metrics.get('target_url'),
            "scan_summary": {
                "total_vulnerabilities": metrics.get('total_alerts', 0),
                "high_risk": metrics.get('high_risk', 0),
                "medium_risk": metrics.get('medium_risk', 0),
                "low_risk": metrics.get('low_risk', 0),
                "informational": metrics.get('informational', 0),
                "security_score": metrics.get('security_score', 0),
                "scan_completed": metrics.get('scan_completed', False)
            },
            "vulnerability_details": metrics.get('vulnerability_details', []),
            "owasp_categories": metrics.get('owasp_categories', {}),
            "report_path": metrics.get('report_path', '')
        }

        output_path = self.reports_dir / output_file
        with open(output_path, 'w') as f:
            json.dump(metrics_export, f, indent=2)

        logger.info(f"Métricas exportadas para: {output_path}")
        return str(output_path)
    
# Prometheus integration removed in bare version
    
# InfluxDB integration removed in bare version
    
    def generate_summary_report(self, metrics: Dict) -> str:
        """Gera relatório resumido em texto"""
        template = f"""
RELATORIO DE SEGURANCA - OWASP ZAP
===================================================================

RESUMO EXECUTIVO
Target: {metrics.get('target_url', 'N/A')}
Data/Hora: {metrics.get('timestamp', 'N/A')}
Score de Seguranca: {metrics.get('security_score', 0)}/100

DISTRIBUICAO DE VULNERABILIDADES
Total de Alertas: {metrics.get('total_alerts', 0)}
+-- Alto Risco: {metrics.get('high_risk', 0)}
+-- Medio Risco: {metrics.get('medium_risk', 0)}
+-- Baixo Risco: {metrics.get('low_risk', 0)}
+-- Informativo: {metrics.get('informational', 0)}

ACAO REQUERIDA
"""
        
        # Adicionar recomendações baseadas no score
        score = metrics.get('security_score', 0)
        high_risk = metrics.get('high_risk', 0)
        
        if high_risk > 0:
            template += f"CRITICO: {high_risk} vulnerabilidades de ALTO RISCO detectadas!\n"
            template += "   -> Correcao IMEDIATA necessaria antes do deploy\n\n"
        elif score < 70:
            template += "ATENCAO: Score de seguranca abaixo do recomendado (70+)\n"
            template += "   -> Revisar e corrigir vulnerabilidades medias\n\n"
        elif score < 90:
            template += "BOM: Score de seguranca aceitavel\n"
            template += "   -> Considerar corrigir vulnerabilidades restantes\n\n"
        else:
            template += "EXCELENTE: Score de seguranca muito bom!\n\n"
        
        # Top vulnerabilidades
        if metrics.get('vulnerability_details'):
            template += "TOP VULNERABILIDADES:\n"
            top_vulns = sorted(
                metrics['vulnerability_details'], 
                key=lambda x: (x['risk'] == 'High', x['risk'] == 'Medium', x['count']), 
                reverse=True
            )[:5]
            
            for i, vuln in enumerate(top_vulns, 1):
                risk_level = vuln['risk']
                template += f"   {i}. [{risk_level}] {vuln['name']} ({vuln['count']} instancias)\n"
        
        template += f"\nRelatorio completo: {metrics.get('report_path', 'N/A')}"
        template += "\n==================================================================="
        
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
    
    def send_google_workspace_notification(self, metrics: Dict, webhook_url: str, 
                                         message_style: str = "card") -> bool:
        """Envia notificação para Google Workspace (Google Chat)"""
        try:
            score = metrics.get('security_score', 0)
            high_risk = metrics.get('high_risk', 0)
            medium_risk = metrics.get('medium_risk', 0)
            low_risk = metrics.get('low_risk', 0)
            total_alerts = metrics.get('total_alerts', 0)
            target_url = metrics.get('target_url', 'N/A')
            
            # Determinar status e cor
            if high_risk > 0:
                status_text = "CRITICO"
                status_color = "#FF0000"
                status_icon = "🔴"
            elif score < 70:
                status_text = "ATENCAO"
                status_color = "#FFA500"
                status_icon = "🟡"
            elif score < 90:
                status_text = "BOM"
                status_color = "#00AA00"
                status_icon = "✅"
            else:
                status_text = "EXCELENTE"
                status_color = "#00FF00"
                status_icon = "🎉"
            
            if message_style == "simple":
                # Mensagem simples
                text = (f"{status_icon} *DAST Security Scan - {status_text}*\n\n"
                       f"Target: {target_url}\n"
                       f"Security Score: {score}/100\n"
                       f"High Risk: {high_risk} | Medium: {medium_risk} | Low: {low_risk}\n"
                       f"Total Alerts: {total_alerts}")
                
                payload = {"text": text}
                
            else:
                # Mensagem com card (formato mais rico)
                # Top vulnerabilidades para incluir no card
                top_vulns = []
                if metrics.get('vulnerability_details'):
                    sorted_vulns = sorted(
                        metrics['vulnerability_details'], 
                        key=lambda x: (x['risk'] == 'High', x['risk'] == 'Medium', x['count']), 
                        reverse=True
                    )[:3]  # Top 3
                    
                    for vuln in sorted_vulns:
                        top_vulns.append(f"• [{vuln['risk']}] {vuln['name']} ({vuln['count']} instancias)")
                
                # Recomendações baseadas no score
                if high_risk > 0:
                    recommendation = "Correcao IMEDIATA necessaria antes do deploy"
                elif score < 70:
                    recommendation = "Revisar e corrigir vulnerabilidades medias"
                elif score < 90:
                    recommendation = "Considerar corrigir vulnerabilidades restantes"
                else:
                    recommendation = "Continuar monitoramento regular"
                
                payload = {
                    "cards": [
                        {
                            "header": {
                                "title": f"DAST Security Scan - {status_text}",
                                "subtitle": f"Target: {target_url}",
                                "imageUrl": "https://www.zaproxy.org/img/zap256x256.png"
                            },
                            "sections": [
                                {
                                    "widgets": [
                                        {
                                            "keyValue": {
                                                "topLabel": "Security Score",
                                                "content": f"{score}/100",
                                                "contentMultiline": False,
                                                "icon": "STAR"
                                            }
                                        },
                                        {
                                            "keyValue": {
                                                "topLabel": "Vulnerabilities by Risk",
                                                "content": f"High: {high_risk} | Medium: {medium_risk} | Low: {low_risk}",
                                                "contentMultiline": False,
                                                "icon": "BOOKMARK"
                                            }
                                        },
                                        {
                                            "keyValue": {
                                                "topLabel": "Total Alerts",
                                                "content": str(total_alerts),
                                                "contentMultiline": False,
                                                "icon": "DESCRIPTION"
                                            }
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
                
                # Adicionar seção com top vulnerabilidades se existirem
                if top_vulns:
                    payload["cards"][0]["sections"].append({
                        "widgets": [
                            {
                                "textParagraph": {
                                    "text": f"<b>Top Vulnerabilidades:</b><br>{'<br>'.join(top_vulns)}"
                                }
                            }
                        ]
                    })
                
                # Adicionar seção com recomendação
                payload["cards"][0]["sections"].append({
                    "widgets": [
                        {
                            "textParagraph": {
                                "text": f"<b>Recomendacao:</b><br>{recommendation}"
                            }
                        }
                    ]
                })
                
                # Adicionar botões de ação se relevante
                if high_risk > 0 or score < 70:
                    payload["cards"][0]["sections"].append({
                        "widgets": [
                            {
                                "buttons": [
                                    {
                                        "textButton": {
                                            "text": "Ver Relatorio Completo",
                                            "onClick": {
                                                "openLink": {
                                                    "url": f"file://{metrics.get('report_path', '')}"
                                                }
                                            }
                                        }
                                    }
                                ]
                            }
                        ]
                    })
            
            response = requests.post(webhook_url, json=payload, timeout=30)
            
            if response.status_code == 200:
                logger.info("Notificação Google Workspace enviada com sucesso")
                return True
            else:
                logger.error(f"Falha ao enviar notificação Google Workspace: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao enviar notificação Google Workspace: {e}")
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
    parser.add_argument("--domain", help="Domínio específico para processar (ex: brokencrystals.com)")
    parser.add_argument("--list-domains", action="store_true", help="Listar domínios disponíveis")
    parser.add_argument("--all-domains", action="store_true", help="Processar todos os domínios disponíveis")
    parser.add_argument("--output-metrics", help="Arquivo de saída para métricas JSON")
    parser.add_argument("--output-junit", help="Arquivo de saída JUnit XML")
# Prometheus and InfluxDB arguments removed in bare version
    parser.add_argument("--slack-webhook", help="URL do webhook Slack")
    parser.add_argument("--teams-webhook", help="URL do webhook Teams")
    parser.add_argument("--google-workspace-webhook", help="URL do webhook Google Workspace")
    parser.add_argument("--google-workspace-style", choices=["simple", "card"], default="card", help="Estilo da mensagem Google Workspace")
    parser.add_argument("--check-gates", action="store_true", help="Verificar quality gates")
    parser.add_argument("--summary", action="store_true", help="Gerar relatório resumido")
    
    args = parser.parse_args()
    
    # Inicializar processador
    processor = ZAPMetricsProcessor(args.reports_dir)
    
    # Listar domínios se solicitado
    if args.list_domains:
        domains = processor.get_available_domains()
        if domains:
            print("Domínios disponíveis:")
            for domain in domains:
                reports = processor.find_reports_by_domain(domain, args.format)
                print(f"  - {domain} ({len(reports)} relatórios)")
        else:
            print("Nenhum domínio encontrado")
        sys.exit(0)
    
    # Determinar quais relatórios processar
    reports_to_process = []
    
    if args.all_domains:
        # Processar todos os domínios
        domains = processor.get_available_domains()
        for domain in domains:
            domain_reports = processor.find_reports_by_domain(domain, args.format)
            if domain_reports:
                reports_to_process.extend(domain_reports)
    elif args.domain:
        # Processar domínio específico
        domain_reports = processor.find_reports_by_domain(args.domain, args.format)
        if not domain_reports:
            logger.error(f"Nenhum relatório encontrado para o domínio {args.domain}")
            sys.exit(1)
        reports_to_process = domain_reports
    else:
        # Comportamento padrão: encontrar relatório mais recente
        latest_report = processor.find_latest_report(args.format)
        if not latest_report:
            logger.error("Nenhum relatório encontrado")
            sys.exit(1)
        reports_to_process = [latest_report]
    
    # Processar cada relatório
    all_metrics = []
    for report_path in reports_to_process:
        logger.info(f"Processando relatório: {report_path}")
        
        if args.format == "json":
            metrics = processor.process_json_report(report_path)
        else:
            logger.error("Formato XML ainda não implementado")
            sys.exit(1)
        
        if not metrics:
            logger.warning(f"Falha ao processar relatório: {report_path}")
            continue
            
        all_metrics.append(metrics)
    
    if not all_metrics:
        logger.error("Nenhum relatório foi processado com sucesso")
        sys.exit(1)
    
    # Se processando múltiplos relatórios, use o mais recente para as saídas principais
    # mas processe todos para métricas agregadas
    primary_metrics = all_metrics[0] if len(all_metrics) == 1 else max(all_metrics, key=lambda m: m.get('timestamp', ''))
    
    logger.info(f"Processados {len(all_metrics)} relatórios. Usando como principal: {primary_metrics.get('target_url', 'unknown')}")
    
    # Gerar saídas conforme solicitado
    try:
        # Multiple reports processing (simplified for bare version)
        if len(all_metrics) > 1:
            logger.info(f"Processando múltiplos relatórios: {len(all_metrics)} encontrados")
        
        # Usar métricas principais para saídas de arquivo únicas
        # Metrics JSON
        if args.output_metrics:
            processor.export_to_metrics_json(primary_metrics, args.output_metrics)
        
        # JUnit XML
        if args.output_junit:
            processor.export_junit_xml(primary_metrics, args.output_junit)
        
        # External monitoring systems removed in bare version
        
        # Notificações (usando métricas principais)
        if args.slack_webhook:
            processor.send_slack_notification(primary_metrics, args.slack_webhook)
        
        if args.teams_webhook:
            processor.send_teams_notification(primary_metrics, args.teams_webhook)
        
        if args.google_workspace_webhook:
            processor.send_google_workspace_notification(
                primary_metrics, 
                args.google_workspace_webhook, 
                args.google_workspace_style
            )
        
        # Relatório resumido
        if args.summary:
            if len(all_metrics) > 1:
                print(f"\nRESUMO CONSOLIDADO - {len(all_metrics)} relatorios processados")
                print("=" * 60)
                
                for i, metrics in enumerate(all_metrics, 1):
                    print(f"\nRelatorio {i}: {metrics.get('target_url', 'unknown')}")
                    summary = processor.generate_summary_report(metrics)
                    print(summary)
                    print("-" * 40)
            else:
                summary = processor.generate_summary_report(primary_metrics)
                print(summary)
            
            # Salvar resumo em arquivo
            summary_file = processor.reports_dir / f"security-summary-{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(summary_file, 'w', encoding='utf-8') as f:
                if len(all_metrics) > 1:
                    f.write(f"RESUMO CONSOLIDADO - {len(all_metrics)} relatórios processados\n")
                    f.write("=" * 60 + "\n\n")
                    for i, metrics in enumerate(all_metrics, 1):
                        f.write(f"Relatório {i}: {metrics.get('target_url', 'unknown')}\n")
                        f.write(processor.generate_summary_report(metrics))
                        f.write("\n" + "-" * 40 + "\n\n")
                else:
                    f.write(processor.generate_summary_report(primary_metrics))
            logger.info(f"Resumo salvo em: {summary_file}")
        
        # Verificar quality gates (usando métricas principais)
        if args.check_gates:
            gates_passed, violations = processor.check_security_gates(primary_metrics)
            
            if not gates_passed:
                logger.error("Quality gates de segurança falharam:")
                for violation in violations:
                    logger.error(f"  {violation}")
                sys.exit(1)
            else:
                logger.info("✅ Todos os quality gates passaram")
        
        # Sempre exportar métricas básicas
        if not any([args.output_metrics, args.output_junit]):
            # Export padrão para métricas JSON
            default_output = processor.export_to_metrics_json(primary_metrics)
            logger.info(f"Métricas exportadas por padrão: {default_output}")
        
        logger.info("Processamento de métricas concluído com sucesso")
        
    except Exception as e:
        logger.error(f"Erro durante processamento: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


# =============================================================================
# EXEMPLOS DE USO - VERSÃO BARE (SEM GRAFANA/PROMETHEUS/REDIS/DATABASE)
# =============================================================================
"""
# Listar domínios disponíveis
python3 process_zap_metrics.py --list-domains

# Uso básico - processar último relatório e gerar métricas JSON
python3 process_zap_metrics.py --summary

# Processar relatórios de um domínio específico
python3 process_zap_metrics.py --domain brokencrystals.com --summary

# Processar todos os domínios disponíveis
python3 process_zap_metrics.py --all-domains --summary

# Exportar métricas para arquivo JSON (domínio específico)
python3 process_zap_metrics.py \
    --domain brokencrystals.com \
    --output-metrics zap-metrics.json

# Notificações Slack para domínio específico
python3 process_zap_metrics.py \
    --domain example.com \
    --slack-webhook https://hooks.slack.com/services/... \
    --summary

# Notificações Google Workspace (formato card)
python3 process_zap_metrics.py \
    --domain brokencrystals.com \
    --google-workspace-webhook https://chat.googleapis.com/v1/spaces/.../messages?key=... \
    --google-workspace-style card \
    --summary

# Notificações Google Workspace (formato simples)
python3 process_zap_metrics.py \
    --google-workspace-webhook https://chat.googleapis.com/v1/spaces/.../messages?key=... \
    --google-workspace-style simple \
    --summary

# Verificar quality gates (para CI/CD) - último relatório
MIN_SECURITY_SCORE=80 \
MAX_MEDIUM_RISK=3 \
MAX_TOTAL_ALERTS=15 \
python3 process_zap_metrics.py --check-gates

# Verificar quality gates para domínio específico
MIN_SECURITY_SCORE=80 \
python3 process_zap_metrics.py \
    --domain brokencrystals.com \
    --check-gates

# Gerar JUnit XML para Jenkins/GitLab (domínio específico)
python3 process_zap_metrics.py \
    --domain brokencrystals.com \
    --output-junit zap-results.xml \
    --check-gates

# Uso completo - processar domínio específico (versão bare)
python3 process_zap_metrics.py \
    --reports-dir ./reports \
    --domain brokencrystals.com \
    --output-metrics zap-metrics.json \
    --output-junit zap-junit-results.xml \
    --google-workspace-webhook https://chat.googleapis.com/... \
    --check-gates \
    --summary

# Processar todos os domínios (versão bare)
python3 process_zap_metrics.py \
    --all-domains \
    --output-metrics zap-metrics.json \
    --google-workspace-webhook https://chat.googleapis.com/... \
    --summary
"""