import docker
import time
import logging
import subprocess
import os
import platform
from typing import Dict, Any, Optional, List
from .config import ZapDockerConfig

logger = logging.getLogger(__name__)


class DockerManager:
    def __init__(self, config: ZapDockerConfig):
        self.config = config
        self.client = None
        self.container = None
        self._initialize_docker_client()

    def _initialize_docker_client(self):
        """Initialize Docker client with error handling."""
        try:
            self.client = docker.from_env()
            # Test connection
            self.client.ping()
            logger.info("Docker client initialized successfully")
        except docker.errors.DockerException as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            raise RuntimeError(f"Docker is not available or not running: {e}")
        except Exception as e:
            logger.error(f"Unexpected error initializing Docker: {e}")
            raise

    def _ensure_docker_running(self) -> bool:
        """Ensure Docker daemon is running."""
        try:
            # Check if Docker daemon is accessible
            self.client.ping()
            return True
        except Exception as e:
            logger.error(f"Docker daemon not accessible: {e}")
            return False

    def _pull_zap_image(self) -> bool:
        """Pull the ZAP Docker image if not already present."""
        try:
            logger.info(f"Checking for ZAP image: {self.config.image}")

            # Check if image exists locally
            try:
                self.client.images.get(self.config.image)
                logger.info(f"ZAP image {self.config.image} already exists locally")
                return True
            except docker.errors.ImageNotFound:
                logger.info(f"ZAP image not found locally, pulling: {self.config.image}")

            # Pull the image
            self.client.images.pull(self.config.image)
            logger.info(f"Successfully pulled ZAP image: {self.config.image}")
            return True

        except Exception as e:
            logger.error(f"Failed to pull ZAP image: {e}")
            return False

    def _get_container_ports(self) -> Dict[str, int]:
        """Get port configuration for the container."""
        return {
            f'{self.config.port}/tcp': self.config.host_port
        }

    def _get_container_environment(self) -> Dict[str, str]:
        """Get environment variables for the container."""
        env = {}
        if self.config.api_key:
            env['ZAP_API_KEY'] = self.config.api_key
        return env

    def _get_container_volumes(self) -> Dict[str, Dict[str, str]]:
        """Get volume mounts for the container."""
        volumes = {}

        # Mount reports directory if specified
        if self.config.reports_volume:
            reports_path = os.path.abspath(self.config.reports_volume)
            os.makedirs(reports_path, exist_ok=True)
            volumes[reports_path] = {'bind': '/zap/reports', 'mode': 'rw'}

        # Mount session directory if specified
        if self.config.session_volume:
            session_path = os.path.abspath(self.config.session_volume)
            os.makedirs(session_path, exist_ok=True)
            volumes[session_path] = {'bind': '/zap/session', 'mode': 'rw'}

        return volumes

    def start_zap_container(self) -> bool:
        """Start ZAP Docker container."""
        try:
            if not self._ensure_docker_running():
                return False

            if not self._pull_zap_image():
                return False

            # Stop existing container if running
            self.stop_zap_container()

            logger.info("Starting ZAP Docker container...")

            # Container configuration
            container_config = {
                'image': self.config.image,
                'name': self.config.container_name,
                'ports': self._get_container_ports(),
                'environment': self._get_container_environment(),
                'volumes': self._get_container_volumes(),
                'detach': True,
                'remove': self.config.auto_remove,
                'command': self.config.command or ['zap.sh', '-daemon', '-host', '0.0.0.0', '-port', str(self.config.port), '-config', 'api.addrs.addr.name=.*', '-config', 'api.addrs.addr.regex=true', '-config', 'api.disablekey=true']
            }

            # Add memory limit if specified
            if self.config.memory_limit:
                container_config['mem_limit'] = self.config.memory_limit

            # Start container
            self.container = self.client.containers.run(**container_config)

            # Wait for ZAP to be ready
            if self._wait_for_zap_ready():
                logger.info(f"ZAP container started successfully: {self.container.id[:12]}")
                return True
            else:
                logger.error("ZAP container started but failed to become ready")
                self.stop_zap_container()
                return False

        except Exception as e:
            logger.error(f"Failed to start ZAP container: {e}")
            return False

    def stop_zap_container(self) -> bool:
        """Stop ZAP Docker container."""
        try:
            # Find container by name
            containers = self.client.containers.list(
                filters={'name': self.config.container_name}
            )

            for container in containers:
                logger.info(f"Stopping ZAP container: {container.id[:12]}")
                container.stop(timeout=30)
                if not self.config.auto_remove:
                    container.remove()
                logger.info("ZAP container stopped successfully")

            self.container = None
            return True

        except Exception as e:
            logger.error(f"Failed to stop ZAP container: {e}")
            return False

    def _wait_for_zap_ready(self, timeout: int = 120) -> bool:
        """Wait for ZAP to be ready to accept connections."""
        import requests

        zap_url = f"http://localhost:{self.config.host_port}"
        api_url = f"{zap_url}/JSON/core/view/version/"

        logger.info(f"Waiting for ZAP to be ready at {zap_url}...")

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(api_url, timeout=5)
                if response.status_code == 200:
                    logger.info("ZAP is ready and responding")
                    return True
            except Exception:
                pass

            time.sleep(2)

        logger.error(f"ZAP failed to become ready within {timeout} seconds")
        return False

    def is_container_running(self) -> bool:
        """Check if ZAP container is running."""
        try:
            containers = self.client.containers.list(
                filters={'name': self.config.container_name}
            )
            return len(containers) > 0
        except Exception as e:
            logger.error(f"Error checking container status: {e}")
            return False

    def get_container_status(self) -> Dict[str, Any]:
        """Get detailed container status information."""
        try:
            containers = self.client.containers.list(
                all=True,
                filters={'name': self.config.container_name}
            )

            if not containers:
                return {'status': 'not_found', 'running': False}

            container = containers[0]
            return {
                'status': container.status,
                'running': container.status == 'running',
                'id': container.id[:12],
                'name': container.name,
                'image': container.image.tags[0] if container.image.tags else 'unknown',
                'ports': container.ports,
                'created': container.attrs['Created'],
                'started': container.attrs.get('State', {}).get('StartedAt', 'unknown')
            }

        except Exception as e:
            logger.error(f"Error getting container status: {e}")
            return {'status': 'error', 'running': False, 'error': str(e)}

    def get_container_logs(self, tail: int = 100) -> str:
        """Get container logs."""
        try:
            containers = self.client.containers.list(
                all=True,
                filters={'name': self.config.container_name}
            )

            if not containers:
                return "Container not found"

            container = containers[0]
            logs = container.logs(tail=tail, timestamps=True)
            return logs.decode('utf-8')

        except Exception as e:
            logger.error(f"Error getting container logs: {e}")
            return f"Error retrieving logs: {e}"

    def cleanup_containers(self) -> bool:
        """Clean up stopped ZAP containers."""
        try:
            containers = self.client.containers.list(
                all=True,
                filters={'name': self.config.container_name}
            )

            for container in containers:
                if container.status != 'running':
                    logger.info(f"Removing stopped container: {container.id[:12]}")
                    container.remove()

            return True

        except Exception as e:
            logger.error(f"Error cleaning up containers: {e}")
            return False

    def get_zap_url(self) -> str:
        """Get the ZAP API URL."""
        return f"http://localhost:{self.config.host_port}"

    def restart_container(self) -> bool:
        """Restart the ZAP container."""
        logger.info("Restarting ZAP container...")
        if self.stop_zap_container():
            return self.start_zap_container()
        return False