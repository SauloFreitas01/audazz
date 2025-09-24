import yaml
import os
from typing import Dict, List, Any, Optional
from pydantic import BaseModel


class ZapConfig(BaseModel):
    host: str = "localhost"
    port: int = 8080
    api_key: str = ""


class ZapDockerConfig(BaseModel):
    enabled: bool = False
    image: str = "zaproxy/zap-stable"
    container_name: str = "autodast-zap"
    port: int = 8080
    host_port: int = 8080
    api_key: str = ""
    command: Optional[List[str]] = None
    memory_limit: str = "2g"
    auto_remove: bool = True
    reports_volume: str = "./reports"
    session_volume: str = "./zap-session"


class SchedulerConfig(BaseModel):
    interval_hours: int = 24


class GoogleChatConfig(BaseModel):
    webhook_url: str = ""


class ReportsConfig(BaseModel):
    output_dir: str = "reports"
    formats: List[str] = ["html", "json"]


class Target(BaseModel):
    name: str
    url: str
    scan_policy: str = "default"


class ScanPolicy(BaseModel):
    spider_max_children: int = 5
    spider_max_depth: int = 5
    spider_max_duration: int = 10
    ascan_delay_in_ms: int = 0
    ascan_threads_per_host: int = 2
    ascan_policy: str = "Default Policy"


class TargetConfig(BaseModel):
    source_type: str = "file_based"  # Options: "file_based", "config_based"
    domains_file: str = "targets/domains.txt"
    subdomains_dir: str = "targets/subdomains"
    default_policies: Dict[str, str] = {
        "main_domain": "default",
        "subdomain": "quick",
        "new_subdomain": "quick"
    }
    discovery: Dict[str, Any] = {
        "enabled": True,
        "auto_scan_new": True,
        "max_targets_per_batch": 50
    }
    legacy_targets: List[Target] = []

class Config(BaseModel):
    zap: ZapConfig
    zap_docker: Optional[ZapDockerConfig] = None
    scheduler: SchedulerConfig
    google_chat: GoogleChatConfig
    reports: ReportsConfig
    targets: TargetConfig
    scan_policies: Dict[str, ScanPolicy]


def load_config(config_path: str = "config.yaml") -> Config:
    """Load configuration from YAML file."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, 'r') as file:
        config_data = yaml.safe_load(file)

    return Config(**config_data)


def save_config(config: Config, config_path: str = "config.yaml"):
    """Save configuration to YAML file."""
    with open(config_path, 'w') as file:
        yaml.dump(config.dict(), file, default_flow_style=False, indent=2)