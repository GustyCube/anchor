from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


@dataclass(frozen=True)
class AnchorProtocolHttpClient:
    base_url: str
    session: requests.Session

    def __post_init__(self) -> None:
        if not self.base_url or not self.base_url.strip():
            raise ValueError("base_url is required")
        if self.session is None:
            raise ValueError("session is required")

    def post_json(self, path: str, payload: Any, expected_status: int) -> Any:
        response = self.session.post(
            f"{self.base_url.rstrip('/')}{path}",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if response.status_code != expected_status:
            raise RuntimeError(
                f"Unexpected status ({response.status_code}): {response.text}"
            )
        return response.json()
