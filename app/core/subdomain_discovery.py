#!/usr/bin/env python3
"""
Advanced Subdomain Discovery Module
Integrates multiple tools and techniques for comprehensive subdomain enumeration
"""

import asyncio
import json
import logging
import subprocess
import time
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path
import requests
import yaml

@dataclass
class SubdomainResult:
    subdomain: str
    source: str
    timestamp: float
    verified: bool = False
    ip_address: Optional[str] = None
    status_code: Optional[int] = None
    technologies: List[str] = None
    cname: Optional[str] = None

class SubdomainDiscovery:
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.timeout = config.get('timeout', 300)
        self.max_subdomains = config.get('max_subdomains_per_domain', 50)
        
        # Initialize DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10
        
        # Thread pool for concurrent operations
        self.executor = ThreadPoolExecutor(max_workers=10)

    async def discover_subdomains(self, domain: str) -> List[SubdomainResult]:
        """Main method to discover subdomains using multiple techniques"""
        self.logger.info(f"Starting subdomain discovery for {domain}")
        
        all_subdomains = set()
        results = []
        
        # Run discovery tools concurrently
        discovery_tasks = []
        
        tools = self.config.get('tools', ['subfinder', 'assetfinder'])
        
        if 'subfinder' in tools:
            discovery_tasks.append(self._run_subfinder(domain))
        if 'assetfinder' in tools:
            discovery_tasks.append(self._run_assetfinder(domain))
        if 'amass' in tools:
            discovery_tasks.append(self._run_amass(domain))
        if 'findomain' in tools:
            discovery_tasks.append(self._run_findomain(domain))
        
        # Add passive discovery methods
        discovery_tasks.append(self._certificate_transparency_search(domain))
        discovery_tasks.append(self._dns_bruteforce(domain))
        discovery_tasks.append(self._search_engine_discovery(domain))
        
        # Execute all discovery methods
        discovery_results = await asyncio.gather(*discovery_tasks, return_exceptions=True)
        
        # Collect results
        for result in discovery_results:
            if isinstance(result, Exception):
                self.logger.error(f"Discovery method failed: {result}")
                continue
            
            if isinstance(result, list):
                for subdomain_result in result:
                    if subdomain_result.subdomain not in all_subdomains:
                        all_subdomains.add(subdomain_result.subdomain)
                        results.append(subdomain_result)
        
        # Limit results if configured
        if self.max_subdomains and len(results) > self.max_subdomains:
            # Sort by source priority and verification status
            results.sort(key=lambda x: (not x.verified, self._get_source_priority(x.source)))
            results = results[:self.max_subdomains]
        
        # Verify subdomains
        verified_results = await self._verify_subdomains(results)
        
        self.logger.info(f"Discovered {len(verified_results)} subdomains for {domain}")
        return verified_results

    async def _run_subfinder(self, domain: str) -> List[SubdomainResult]:
        """Run subfinder tool"""
        try:
            cmd = ['subfinder', '-d', domain, '-silent', '-json']
            
            # Add config file if specified
            config_file = self.config.get('subfinder', {}).get('config_file')
            if config_file and Path(config_file).exists():
                cmd.extend(['-config', config_file])
            
            # Add sources filter
            sources = self.config.get('subfinder', {}).get('sources', 'all')
            if sources != 'all':
                cmd.extend(['-sources', sources])
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=self.timeout)
            
            if result.returncode == 0:
                subdomains = []
                for line in stdout.decode().strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            subdomain = data.get('host', '').strip()
                            if subdomain and domain in subdomain:
                                subdomains.append(SubdomainResult(
                                    subdomain=subdomain,
                                    source='subfinder',
                                    timestamp=time.time()
                                ))
                        except json.JSONDecodeError:
                            # Fallback for non-JSON output
                            subdomain = line.strip()
                            if subdomain and domain in subdomain:
                                subdomains.append(SubdomainResult(
                                    subdomain=subdomain,
                                    source='subfinder',
                                    timestamp=time.time()
                                ))
                
                self.logger.debug(f"Subfinder found {len(subdomains)} subdomains for {domain}")
                return subdomains
            
        except Exception as e:
            self.logger.warning(f"Subfinder failed for {domain}: {e}")
        
        return []

    async def _run_assetfinder(self, domain: str) -> List[SubdomainResult]:
        """Run assetfinder tool"""
        try:
            result = await asyncio.create_subprocess_exec(
                'assetfinder', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=self.timeout)
            
            if result.returncode == 0:
                subdomains = []
                for line in stdout.decode().strip().split('\n'):
                    subdomain = line.strip()
                    if subdomain and domain in subdomain:
                        subdomains.append(SubdomainResult(
                            subdomain=subdomain,
                            source='assetfinder',
                            timestamp=time.time()
                        ))
                
                self.logger.debug(f"Assetfinder found {len(subdomains)} subdomains for {domain}")
                return subdomains
            
        except Exception as e:
            self.logger.warning(f"Assetfinder failed for {domain}: {e}")
        
        return []

    async def _run_amass(self, domain: str) -> List[SubdomainResult]:
        """Run amass tool"""
        try:
            cmd = ['amass', 'enum', '-d', domain, '-json']
            
            # Add config file if specified
            config_file = self.config.get('amass', {}).get('config_file')
            if config_file and Path(config_file).exists():
                cmd.extend(['-config', config_file])
            
            # Add wordlist if specified
            wordlist = self.config.get('amass', {}).get('wordlist')
            if wordlist and Path(wordlist).exists():
                cmd.extend(['-w', wordlist])
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=self.timeout)
            
            if result.returncode == 0:
                subdomains = []
                for line in stdout.decode().strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            subdomain = data.get('name', '').strip()
                            if subdomain and domain in subdomain:
                                subdomains.append(SubdomainResult(
                                    subdomain=subdomain,
                                    source='amass',
                                    timestamp=time.time()
                                ))
                        except json.JSONDecodeError:
                            continue
                
                self.logger.debug(f"Amass found {len(subdomains)} subdomains for {domain}")
                return subdomains
            
        except Exception as e:
            self.logger.warning(f"Amass failed for {domain}: {e}")
        
        return []

    async def _run_findomain(self, domain: str) -> List[SubdomainResult]:
        """Run findomain tool"""
        try:
            result = await asyncio.create_subprocess_exec(
                'findomain', '-t', domain, '-q',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=self.timeout)
            
            if result.returncode == 0:
                subdomains = []
                for line in stdout.decode().strip().split('\n'):
                    subdomain = line.strip()
                    if subdomain and domain in subdomain:
                        subdomains.append(SubdomainResult(
                            subdomain=subdomain,
                            source='findomain',
                            timestamp=time.time()
                        ))
                
                self.logger.debug(f"Findomain found {len(subdomains)} subdomains for {domain}")
                return subdomains
            
        except Exception as e:
            self.logger.warning(f"Findomain failed for {domain}: {e}")
        
        return []

    async def _certificate_transparency_search(self, domain: str) -> List[SubdomainResult]:
        """Search certificate transparency logs"""
        subdomains = []
        
        try:
            # crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                self.executor, 
                lambda: requests.get(url, timeout=30)
            )
            
            if response.status_code == 200:
                data = response.json()
                found_subdomains = set()
                
                for cert in data:
                    name_value = cert.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain and domain in subdomain and '*' not in subdomain:
                            if subdomain not in found_subdomains:
                                found_subdomains.add(subdomain)
                                subdomains.append(SubdomainResult(
                                    subdomain=subdomain,
                                    source='certificate_transparency',
                                    timestamp=time.time()
                                ))
            
        except Exception as e:
            self.logger.warning(f"Certificate transparency search failed for {domain}: {e}")
        
        self.logger.debug(f"Certificate transparency found {len(subdomains)} subdomains for {domain}")
        return subdomains

    async def _dns_bruteforce(self, domain: str) -> List[SubdomainResult]:
        """Perform DNS bruteforce with common subdomains"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns4',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
            'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns5', 'upload',
            'mx1', 'mx2', 'www3', 'monitor', 'owa', 'mail3', 'db', 'search', 'staging'
        ]
        
        subdomains = []
        
        # Limit concurrent DNS queries
        semaphore = asyncio.Semaphore(20)
        
        async def check_subdomain(prefix):
            async with semaphore:
                subdomain = f"{prefix}.{domain}"
                try:
                    # Use thread executor for DNS resolution
                    loop = asyncio.get_event_loop()
                    answers = await loop.run_in_executor(
                        self.executor,
                        lambda: self.resolver.resolve(subdomain, 'A')
                    )
                    
                    if answers:
                        ip = str(answers[0])
                        return SubdomainResult(
                            subdomain=subdomain,
                            source='dns_bruteforce',
                            timestamp=time.time(),
                            verified=True,
                            ip_address=ip
                        )
                
                except Exception:
                    pass
                
                return None
        
        # Execute DNS queries concurrently
        tasks = [check_subdomain(prefix) for prefix in common_subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, SubdomainResult):
                subdomains.append(result)
        
        self.logger.debug(f"DNS bruteforce found {len(subdomains)} subdomains for {domain}")
        return subdomains

    async def _search_engine_discovery(self, domain: str) -> List[SubdomainResult]:
        """Use search engines to discover subdomains"""
        subdomains = []
        
        try:
            # Google dorking (be careful with rate limits)
            query = f"site:{domain} -www.{domain}"
            # This would require implementing Google search API or scraping
            # For now, we'll skip this to avoid rate limiting issues
            pass
            
        except Exception as e:
            self.logger.warning(f"Search engine discovery failed for {domain}: {e}")
        
        return subdomains

    async def _verify_subdomains(self, subdomains: List[SubdomainResult]) -> List[SubdomainResult]:
        """Verify discovered subdomains"""
        verified_subdomains = []
        
        # Create semaphore to limit concurrent verifications
        semaphore = asyncio.Semaphore(10)
        
        async def verify_subdomain(subdomain_result):
            async with semaphore:
                return await self._verify_single_subdomain(subdomain_result)
        
        # Verify subdomains concurrently
        verification_tasks = [verify_subdomain(sub) for sub in subdomains]
        results = await asyncio.gather(*verification_tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, SubdomainResult) and result.verified:
                verified_subdomains.append(result)
        
        return verified_subdomains

    async def _verify_single_subdomain(self, subdomain_result: SubdomainResult) -> SubdomainResult:
        """Verify a single subdomain"""
        try:
            # DNS resolution
            if not subdomain_result.ip_address:
                loop = asyncio.get_event_loop()
                try:
                    answers = await loop.run_in_executor(
                        self.executor,
                        lambda: self.resolver.resolve(subdomain_result.subdomain, 'A')
                    )
                    if answers:
                        subdomain_result.ip_address = str(answers[0])
                    else:
                        return subdomain_result  # DNS resolution failed
                except Exception:
                    return subdomain_result  # DNS resolution failed
            
            # HTTP verification
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain_result.subdomain}"
                    
                    response = await loop.run_in_executor(
                        self.executor,
                        lambda: requests.head(url, timeout=10, allow_redirects=True)
                    )
                    
                    subdomain_result.status_code = response.status_code
                    subdomain_result.verified = True
                    
                    # Try to detect technologies
                    subdomain_result.technologies = self._detect_technologies(response)
                    break
                    
                except Exception:
                    continue
            
            # Get CNAME if available
            try:
                cname_answers = await loop.run_in_executor(
                    self.executor,
                    lambda: self.resolver.resolve(subdomain_result.subdomain, 'CNAME')
                )
                if cname_answers:
                    subdomain_result.cname = str(cname_answers[0])
            except Exception:
                pass
            
        except Exception as e:
            self.logger.debug(f"Verification failed for {subdomain_result.subdomain}: {e}")
        
        return subdomain_result

    def _detect_technologies(self, response) -> List[str]:
        """Detect technologies from HTTP response headers"""
        technologies = []
        
        headers = response.headers
        
        # Server header
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            technologies.append('Nginx')
        elif 'apache' in server:
            technologies.append('Apache')
        elif 'iis' in server:
            technologies.append('IIS')
        elif 'cloudflare' in server:
            technologies.append('Cloudflare')
        
        # X-Powered-By header
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        elif 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        elif 'express' in powered_by:
            technologies.append('Express.js')
        
        # Other indicators
        if headers.get('X-Drupal-Cache'):
            technologies.append('Drupal')
        if headers.get('X-Generator') and 'wordpress' in headers.get('X-Generator', '').lower():
            technologies.append('WordPress')
        
        return technologies

    def _get_source_priority(self, source: str) -> int:
        """Get priority score for source (lower = higher priority)"""
        priorities = {
            'dns_bruteforce': 1,
            'certificate_transparency': 2,
            'subfinder': 3,
            'amass': 4,
            'assetfinder': 5,
            'findomain': 6
        }
        return priorities.get(source, 10)

    def export_results(self, results: List[SubdomainResult], format: str = 'json') -> str:
        """Export results in specified format"""
        if format == 'json':
            data = []
            for result in results:
                data.append({
                    'subdomain': result.subdomain,
                    'source': result.source,
                    'timestamp': result.timestamp,
                    'verified': result.verified,
                    'ip_address': result.ip_address,
                    'status_code': result.status_code,
                    'technologies': result.technologies,
                    'cname': result.cname
                })
            return json.dumps(data, indent=2)
        
        elif format == 'csv':
            lines = ['subdomain,source,verified,ip_address,status_code,technologies,cname']
            for result in results:
                tech_str = ';'.join(result.technologies) if result.technologies else ''
                lines.append(f"{result.subdomain},{result.source},{result.verified},"
                           f"{result.ip_address or ''},{result.status_code or ''},"
                           f"{tech_str},{result.cname or ''}")
            return '\n'.join(lines)
        
        elif format == 'txt':
            return '\n'.join([result.subdomain for result in results if result.verified])
        
        else:
            raise ValueError(f"Unsupported format: {format}")

async def main():
    """Test the subdomain discovery"""
    config = {
        'tools': ['subfinder', 'assetfinder'],
        'timeout': 300,
        'max_subdomains_per_domain': 20
    }
    
    discovery = SubdomainDiscovery(config)
    results = await discovery.discover_subdomains('example.com')
    
    print(f"Found {len(results)} subdomains:")
    for result in results:
        status = "✓" if result.verified else "?"
        print(f"{status} {result.subdomain} ({result.source})")

if __name__ == '__main__':
    asyncio.run(main())