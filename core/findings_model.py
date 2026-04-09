from dataclasses import dataclass, asdict
from typing import Dict, Any


@dataclass
class Finding:
    service: str
    resource_name: str
    issue: str
    severity: str
    recommendation: str
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)