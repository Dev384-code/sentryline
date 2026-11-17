from datetime import datetime, timezone
from uuid import uuid4


def build_alerts(findings: list[dict]) -> list[dict]:
    alerts = []
    for index, finding in enumerate(findings, 1):
        alerts.append({
            "id": f"ALT-{uuid4().hex[:16]}",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "open",
            **finding,
        })
    return alerts
