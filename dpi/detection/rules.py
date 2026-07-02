import yaml
from pathlib import Path
from typing import Dict, List, Any


class RuleEngine:
    """Custom detection rules loaded from YAML configuration."""

    def __init__(self, rules_file: str = None):
        self.rules: List[Dict[str, Any]] = []
        if rules_file:
            self.load_rules(rules_file)
        else:
            default_rules = Path(__file__).parent / "custom_rules.yaml"
            if default_rules.exists():
                self.load_rules(str(default_rules))

    def load_rules(self, rules_file: str):
        """Load rules from a YAML file."""
        with open(rules_file, 'r') as f:
            config = yaml.safe_load(f)
            self.rules = config.get('rules', [])
        return len(self.rules)

    def evaluate(self, packet_info: Dict[str, Any]) -> List[Dict[str, str]]:
        """Evaluate packet against all rules."""
        alerts = []

        for rule in self.rules:
            if self._check_rule(rule, packet_info):
                alerts.append({
                    "rule": rule.get("name", "Unknown"),
                    "severity": rule.get("severity", "INFO"),
                    "action": rule.get("action", "log"),
                    "message": rule.get("message", "Rule matched")
                })

        return alerts

    def _check_rule(self, rule: Dict, packet: Dict) -> bool:
        """Check if a single rule matches the packet."""
        conditions = rule.get("conditions", {})
        if not conditions:
            return False

        logic = rule.get("logic", "AND")

        results = []
        for field, pattern in conditions.items():
            actual_value = str(packet.get(field, ""))
            results.append(pattern.lower() in actual_value.lower())

        if logic == "AND":
            return all(results)
        elif logic == "OR":
            return any(results)

        return False

    def to_dict(self) -> Dict:
        """Export current rules as dictionary."""
        return {"rules": self.rules}