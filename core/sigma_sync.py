"""
ThreatScope — SigmaHQ Auto-Sync Module
Author: 0xSABRY

Automatically syncs Sigma detection rules from the official SigmaHQ
GitHub repository. Supports cloning, pulling updates, and deduplication.
"""

import os
import json
import shutil
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict

logger = logging.getLogger("threatscope.sigma_sync")


class SigmaSync:
    """
    Synchronizes Sigma rules from the official SigmaHQ GitHub repository.
    
    Clones the repo on first run, then pulls updates on subsequent runs.
    Rules are extracted from the repo's rules directory and copied
    to ThreatScope's local sigma_rules directory.
    """

    SIGMAHQ_URL = "https://github.com/SigmaHQ/sigma.git"
    RULES_SUBDIR = "rules"

    def __init__(self, sigma_rules_dir: Optional[str] = None, cache_dir: Optional[str] = None):
        """
        Initialize the SigmaHQ sync system.

        Args:
            sigma_rules_dir: Target directory for copied rules.
            cache_dir: Directory to store the cloned SigmaHQ repo.
        """
        from config import SIGMA_RULES_DIR, DATA_DIR

        self.sigma_rules_dir = Path(sigma_rules_dir) if sigma_rules_dir else SIGMA_RULES_DIR
        self.cache_dir = Path(cache_dir) if cache_dir else DATA_DIR / "sigmahq_repo"
        self.sync_state_file = Path(DATA_DIR) / "sigma_sync_state.json"

        # Ensure directories exist
        self.sigma_rules_dir.mkdir(parents=True, exist_ok=True)

    def sync(self, force: bool = False) -> Dict:
        """
        Synchronize Sigma rules from SigmaHQ.

        Clones the repository if not present, or pulls updates.
        Then copies all rules to the local sigma_rules directory.

        Args:
            force: If True, re-clone even if repo exists.

        Returns:
            Dictionary with sync results (rules_added, rules_updated, etc.).
        """
        result = {
            "status": "success",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rules_added": 0,
            "rules_updated": 0,
            "rules_total": 0,
            "errors": [],
        }

        try:
            # Step 1: Clone or pull the SigmaHQ repository
            if force or not (self.cache_dir / ".git").exists():
                self._clone_repo()
                result["action"] = "clone"
            else:
                self._pull_updates()
                result["action"] = "pull"

            # Step 2: Copy rules to sigma_rules directory
            rules_source = self.cache_dir / self.RULES_SUBDIR
            if not rules_source.exists():
                # Try 'rules-*' directories (newer SigmaHQ structure)
                rules_dirs = list(self.cache_dir.glob("rules*"))
                if rules_dirs:
                    rules_source = rules_dirs[0]
                else:
                    result["status"] = "error"
                    result["errors"].append("No rules directory found in SigmaHQ repo")
                    return result

            # Step 3: Copy and deduplicate
            sync_counts = self._copy_rules(rules_source)
            result.update(sync_counts)

            # Step 4: Save sync state
            self._save_sync_state(result)

            logger.info(
                f"Sigma sync complete: {result['rules_total']} rules "
                f"({result['rules_added']} new, {result['rules_updated']} updated)"
            )

        except FileNotFoundError:
            result["status"] = "error"
            result["errors"].append("git is not installed or not in PATH. Please install git.")
            logger.error("git not found — cannot sync SigmaHQ rules")
        except subprocess.CalledProcessError as e:
            result["status"] = "error"
            result["errors"].append(f"Git command failed: {e}")
            logger.error(f"Git error during sync: {e}")
        except Exception as e:
            result["status"] = "error"
            result["errors"].append(str(e))
            logger.error(f"Sigma sync failed: {e}")

        return result

    def _clone_repo(self):
        """Clone the SigmaHQ repository."""
        logger.info(f"Cloning SigmaHQ repository to {self.cache_dir}...")
        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir)

        subprocess.run(
            ["git", "clone", "--depth", "1", self.SIGMAHQ_URL, str(self.cache_dir)],
            check=True,
            capture_output=True,
            timeout=300,
        )
        logger.info("SigmaHQ repository cloned successfully.")

    def _pull_updates(self):
        """Pull latest updates from SigmaHQ."""
        logger.info("Pulling latest SigmaHQ updates...")
        subprocess.run(
            ["git", "-C", str(self.cache_dir), "pull", "--rebase"],
            check=True,
            capture_output=True,
            timeout=120,
        )
        logger.info("SigmaHQ updates pulled successfully.")

    def _copy_rules(self, source_dir: Path) -> Dict:
        """
        Copy Sigma rules from the cloned repo to the local directory.

        Preserves directory structure and handles deduplication.

        Args:
            source_dir: Source directory containing Sigma rules.

        Returns:
            Counts of added, updated, and total rules.
        """
        added = 0
        updated = 0
        total = 0

        for yml_file in source_dir.rglob("*.yml"):
            total += 1
            # Preserve subdirectory structure
            relative = yml_file.relative_to(source_dir)
            target = self.sigma_rules_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)

            if target.exists():
                # Compare content — only update if changed
                source_content = yml_file.read_bytes()
                target_content = target.read_bytes()
                if source_content != target_content:
                    target.write_bytes(source_content)
                    updated += 1
            else:
                shutil.copy2(yml_file, target)
                added += 1

        # Also check .yaml extension
        for yaml_file in source_dir.rglob("*.yaml"):
            total += 1
            relative = yaml_file.relative_to(source_dir)
            target = self.sigma_rules_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)

            if target.exists():
                source_content = yaml_file.read_bytes()
                target_content = target.read_bytes()
                if source_content != target_content:
                    target.write_bytes(source_content)
                    updated += 1
            else:
                shutil.copy2(yaml_file, target)
                added += 1

        return {"rules_added": added, "rules_updated": updated, "rules_total": total}

    def _save_sync_state(self, result: dict):
        """Save sync state for tracking."""
        state = {
            "last_sync": result.get("timestamp"),
            "last_action": result.get("action"),
            "rules_total": result.get("rules_total"),
            "status": result.get("status"),
        }
        with open(self.sync_state_file, "w") as f:
            json.dump(state, f, indent=2)

    def get_last_sync(self) -> Optional[dict]:
        """
        Get information about the last sync operation.

        Returns:
            Dictionary with last sync details, or None.
        """
        if self.sync_state_file.exists():
            try:
                with open(self.sync_state_file) as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def needs_sync(self, interval_days: int = 7) -> bool:
        """
        Check if a sync is needed based on the interval.

        Args:
            interval_days: Number of days between syncs.

        Returns:
            True if sync is needed.
        """
        state = self.get_last_sync()
        if not state or not state.get("last_sync"):
            return True

        try:
            last_sync = datetime.fromisoformat(state["last_sync"])
            now = datetime.now(timezone.utc)
            return (now - last_sync).days >= interval_days
        except Exception:
            return True

    def get_rule_categories(self) -> Dict[str, int]:
        """
        Count rules by directory category.

        Returns:
            Dictionary mapping category paths to rule counts.
        """
        categories = {}
        for yml_file in self.sigma_rules_dir.rglob("*.yml"):
            rel = yml_file.relative_to(self.sigma_rules_dir)
            parts = rel.parts
            if len(parts) > 1:
                category = parts[0]
            else:
                category = "root"
            categories[category] = categories.get(category, 0) + 1
        return categories
