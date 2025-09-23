#!/usr/bin/env python3
"""
Target Manager for AutoDast Security Scanner
Manages domains and subdomains from discovery tools integration
"""

import os
import glob
import json
import logging
from typing import List, Dict, Set
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class TargetManager:
    """Manages scan targets from subdomain discovery integration."""

    def __init__(self, targets_dir: str = "targets"):
        self.targets_dir = Path(targets_dir)
        self.domains_file = self.targets_dir / "domains.txt"
        self.subdomains_dir = self.targets_dir / "subdomains"
        self.ensure_directories()

    def ensure_directories(self):
        """Create necessary directories if they don't exist."""
        self.targets_dir.mkdir(exist_ok=True)
        self.subdomains_dir.mkdir(exist_ok=True)

        if not self.domains_file.exists():
            self.domains_file.write_text("# Add your main domains here, one per line\n")

    def get_main_domains(self) -> List[str]:
        """Read main domains from domains.txt file."""
        domains = []

        if not self.domains_file.exists():
            logger.warning(f"Domains file not found: {self.domains_file}")
            return domains

        try:
            with open(self.domains_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith('#'):
                        domains.append(line)

            logger.info(f"Loaded {len(domains)} main domains")
            return domains

        except Exception as e:
            logger.error(f"Error reading domains file: {e}")
            return []

    def get_subdomains_for_domain(self, domain: str) -> List[str]:
        """Get subdomains for a specific domain from subdomains directory."""
        subdomains = []

        # Look for subdomain files with various naming patterns
        possible_files = [
            self.subdomains_dir / f"{domain}.txt",
            self.subdomains_dir / f"{domain}_subdomains.txt",
            self.subdomains_dir / f"subdomains_{domain}.txt",
            self.subdomains_dir / domain / "subdomains.txt",
            self.subdomains_dir / domain / f"{domain}.txt"
        ]

        for subdomain_file in possible_files:
            if subdomain_file.exists():
                try:
                    with open(subdomain_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            # Skip comments and empty lines
                            if line and not line.startswith('#'):
                                # Ensure subdomain is properly formatted
                                if line.endswith(f".{domain}") or line == domain:
                                    subdomains.append(line)
                                elif '.' not in line:
                                    # Add domain suffix if missing
                                    subdomains.append(f"{line}.{domain}")
                                else:
                                    subdomains.append(line)

                    logger.info(f"Loaded {len(subdomains)} subdomains for {domain} from {subdomain_file}")
                    break  # Use the first file found

                except Exception as e:
                    logger.error(f"Error reading subdomain file {subdomain_file}: {e}")
                    continue

        # Remove duplicates and sort
        return sorted(list(set(subdomains)))

    def get_all_targets(self) -> Dict[str, List[str]]:
        """Get all targets organized by main domain."""
        all_targets = {}

        # Get main domains
        main_domains = self.get_main_domains()

        for domain in main_domains:
            targets = [domain]  # Include the main domain

            # Add subdomains
            subdomains = self.get_subdomains_for_domain(domain)
            targets.extend(subdomains)

            all_targets[domain] = targets

        return all_targets

    def get_flat_target_list(self) -> List[str]:
        """Get a flat list of all targets for scanning."""
        all_targets = self.get_all_targets()
        flat_list = []

        for domain, targets in all_targets.items():
            flat_list.extend(targets)

        # Remove duplicates and sort
        return sorted(list(set(flat_list)))

    def detect_new_subdomains(self, previous_targets_file: str = None) -> Dict[str, List[str]]:
        """Detect newly added subdomains since last scan."""
        current_targets = self.get_all_targets()

        if not previous_targets_file or not os.path.exists(previous_targets_file):
            logger.info("No previous targets file found, treating all as new")
            return current_targets

        try:
            with open(previous_targets_file, 'r') as f:
                previous_targets = json.load(f)
        except Exception as e:
            logger.error(f"Error reading previous targets: {e}")
            return current_targets

        new_subdomains = {}

        for domain, current_list in current_targets.items():
            previous_list = previous_targets.get(domain, [])
            new_items = list(set(current_list) - set(previous_list))

            if new_items:
                new_subdomains[domain] = new_items
                logger.info(f"Found {len(new_items)} new targets for {domain}: {new_items}")

        return new_subdomains

    def save_current_targets(self, output_file: str):
        """Save current targets to a file for comparison."""
        targets = self.get_all_targets()

        try:
            with open(output_file, 'w') as f:
                json.dump(targets, f, indent=2)
            logger.info(f"Saved current targets to {output_file}")
        except Exception as e:
            logger.error(f"Error saving targets: {e}")

    def get_changed_files(self, git_diff_output: str) -> List[str]:
        """Parse git diff output to find changed domain/subdomain files."""
        changed_files = []

        for line in git_diff_output.split('\n'):
            line = line.strip()

            # Check for changes in domains.txt or subdomain files
            if (line.startswith('targets/domains.txt') or
                line.startswith('targets/subdomains/') or
                'domains.txt' in line or
                'subdomains' in line):
                changed_files.append(line)

        return changed_files

    def format_targets_for_matrix(self, max_targets_per_job: int = 50) -> List[List[str]]:
        """Format targets for GitHub Actions matrix strategy."""
        all_targets = self.get_flat_target_list()

        if not all_targets:
            logger.warning("No targets found for scanning")
            return []

        # Split targets into chunks for parallel processing
        chunks = []
        for i in range(0, len(all_targets), max_targets_per_job):
            chunk = all_targets[i:i + max_targets_per_job]
            chunks.append(chunk)

        logger.info(f"Split {len(all_targets)} targets into {len(chunks)} chunks")
        return chunks

    def get_targets_summary(self) -> Dict[str, any]:
        """Get a summary of all targets for reporting."""
        all_targets = self.get_all_targets()
        flat_targets = self.get_flat_target_list()

        summary = {
            "total_targets": len(flat_targets),
            "main_domains": len(all_targets),
            "domains": {},
            "last_updated": datetime.now().isoformat()
        }

        for domain, targets in all_targets.items():
            subdomains = [t for t in targets if t != domain]
            summary["domains"][domain] = {
                "total_targets": len(targets),
                "subdomains_count": len(subdomains),
                "targets": targets
            }

        return summary

def main():
    """CLI interface for target management."""
    import argparse

    parser = argparse.ArgumentParser(description="Manage AutoDast scan targets")
    parser.add_argument("--targets-dir", default="targets", help="Targets directory path")
    parser.add_argument("--action", choices=["list", "summary", "matrix", "detect-new"],
                       default="list", help="Action to perform")
    parser.add_argument("--previous-targets", help="Previous targets file for comparison")
    parser.add_argument("--save-current", help="Save current targets to file")
    parser.add_argument("--max-per-job", type=int, default=50,
                       help="Maximum targets per matrix job")

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    manager = TargetManager(args.targets_dir)

    if args.action == "list":
        targets = manager.get_flat_target_list()
        print(f"Found {len(targets)} total targets:")
        for target in targets:
            print(f"  - {target}")

    elif args.action == "summary":
        summary = manager.get_targets_summary()
        print(json.dumps(summary, indent=2))

    elif args.action == "matrix":
        chunks = manager.format_targets_for_matrix(args.max_per_job)
        matrix = {"include": []}

        for i, chunk in enumerate(chunks):
            matrix["include"].append({
                "job_name": f"scan-batch-{i+1}",
                "targets": ",".join(chunk)
            })

        print(json.dumps(matrix, indent=2))

    elif args.action == "detect-new":
        new_targets = manager.detect_new_subdomains(args.previous_targets)
        if new_targets:
            print("New targets detected:")
            print(json.dumps(new_targets, indent=2))
        else:
            print("No new targets detected")

    if args.save_current:
        manager.save_current_targets(args.save_current)

if __name__ == "__main__":
    main()