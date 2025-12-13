"""
Thread-safe storage module for managing EQL rules.

Provides read/write helpers for persisting rules to a JSON file with schema:
{
    "id": string,
    "name": string,
    "description": string,
    "severity": string,
    "query": string,
    "created_at": ISO8601 datetime,
    "updated_at": ISO8601 datetime
}
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class RulesStorage:
    """Thread-safe storage for EQL rules."""

    def __init__(self, storage_path: str | Path = "eql_engine/rules.json"):
        """Initialize the rules storage.

        Args:
            storage_path: Path to the rules JSON file
        """
        self.storage_path = Path(storage_path)
        self._lock = threading.RLock()
        self._ensure_file_exists()

    def _ensure_file_exists(self) -> None:
        """Ensure the storage file exists."""
        with self._lock:
            if not self.storage_path.exists():
                self.storage_path.parent.mkdir(parents=True, exist_ok=True)
                self._write_file([])

    def _read_file(self) -> List[Dict[str, Any]]:
        """Read the rules file.

        Returns:
            List of rule dictionaries
        """
        try:
            with open(self.storage_path, 'r') as f:
                content = f.read().strip()
                if not content:
                    return []
                return json.loads(content)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _write_file(self, rules: List[Dict[str, Any]]) -> None:
        """Write rules to the file.

        Args:
            rules: List of rule dictionaries
        """
        with open(self.storage_path, 'w') as f:
            json.dump(rules, f, indent=2)

    def get_all(self) -> List[Dict[str, Any]]:
        """Get all rules.

        Returns:
            List of all rules
        """
        with self._lock:
            return self._read_file()

    def get_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get a rule by ID.

        Args:
            rule_id: The rule ID

        Returns:
            The rule dictionary or None if not found
        """
        with self._lock:
            rules = self._read_file()
            for rule in rules:
                if rule.get("id") == rule_id:
                    return rule
            return None

    def create(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new rule.

        Args:
            rule: Rule dictionary with id, name, description, severity, query

        Returns:
            The created rule with timestamps added
        """
        with self._lock:
            rules = self._read_file()

            # Add timestamps
            now = datetime.now(timezone.utc).isoformat()
            rule["created_at"] = now
            rule["updated_at"] = now

            rules.append(rule)
            self._write_file(rules)
            return rule

    def update(self, rule_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update an existing rule.

        Args:
            rule_id: The rule ID
            updates: Dictionary with fields to update

        Returns:
            The updated rule or None if not found
        """
        with self._lock:
            rules = self._read_file()

            for rule in rules:
                if rule.get("id") == rule_id:
                    # Update fields
                    for key, value in updates.items():
                        if key not in ("created_at",):  # Don't update created_at
                            rule[key] = value

                    # Update the updated_at timestamp
                    rule["updated_at"] = datetime.now(timezone.utc).isoformat()

                    self._write_file(rules)
                    return rule

            return None

    def delete(self, rule_id: str) -> bool:
        """Delete a rule by ID.

        Args:
            rule_id: The rule ID

        Returns:
            True if rule was deleted, False if not found
        """
        with self._lock:
            rules = self._read_file()
            original_len = len(rules)
            rules = [r for r in rules if r.get("id") != rule_id]

            if len(rules) < original_len:
                self._write_file(rules)
                return True

            return False

    def export(self) -> str:
        """Export all rules as JSON string.

        Returns:
            JSON string of all rules
        """
        with self._lock:
            rules = self._read_file()
            return json.dumps(rules, indent=2)
