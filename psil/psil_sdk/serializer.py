"""PSIL Serializer - JSON and YAML support"""
import json
from typing import Union
from .models import Engagement


class PSILSerializer:
    @staticmethod
    def to_json(engagement: Engagement, indent: int = 2) -> str:
        return json.dumps(engagement.to_dict(), indent=indent, default=str)

    @staticmethod
    def from_json(data: Union[str, bytes]) -> Engagement:
        return Engagement.from_dict(json.loads(data))

    @staticmethod
    def to_yaml(engagement: Engagement) -> str:
        try:
            import yaml
            return yaml.dump(engagement.to_dict(), default_flow_style=False, allow_unicode=True)
        except ImportError:
            raise RuntimeError("PyYAML not installed. Run: pip install pyyaml")

    @staticmethod
    def from_yaml(data: str) -> Engagement:
        try:
            import yaml
            return Engagement.from_dict(yaml.safe_load(data))
        except ImportError:
            raise RuntimeError("PyYAML not installed. Run: pip install pyyaml")
