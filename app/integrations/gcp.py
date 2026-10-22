"""Read-only Google Cloud adapter. A service-account key is exchanged for a short-lived read-only token.

Hosts are fixed (no URL from the key or the client is ever followed), every call has a timeout, and
nothing here can change a resource: only GET requests are made.
"""
import base64
import json
import re
import time

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/cloud-platform.read-only"
TIMEOUT = 15.0
MAX_ITEMS = 200
_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


class GcpError(Exception):
    pass


def valid_project(project_id: str) -> bool:
    return bool(_PROJECT_RE.match(project_id))


def parse_key(raw: str) -> dict:
    """Validate a service-account key file. Returns the parsed key or raises GcpError('invalid_key')."""
    try:
        key = json.loads(raw)
        if key.get("type") != "service_account":
            raise ValueError
        for f in ("client_email", "private_key", "project_id"):
            if not isinstance(key.get(f), str) or not key[f]:
                raise ValueError
        serialization.load_pem_private_key(key["private_key"].encode(), password=None)
    except (ValueError, TypeError, AttributeError) as exc:  # includes JSON and PEM errors
        raise GcpError("invalid_key") from exc
    return key


def _b64(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _assertion(key: dict) -> str:
    now = int(time.time())
    head = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = _b64(json.dumps({"iss": key["client_email"], "scope": SCOPE, "aud": TOKEN_URL,
                              "iat": now, "exp": now + 3000}).encode())
    signing_input = head + b"." + claims
    pk = serialization.load_pem_private_key(key["private_key"].encode(), password=None)
    sig = pk.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]
    return (signing_input + b"." + _b64(sig)).decode()


class GcpClient:
    def __init__(self, key: dict, project_id: str, transport: httpx.BaseTransport | None = None):
        self._key, self.project_id = key, project_id
        self._http = httpx.Client(timeout=TIMEOUT, transport=transport)
        self._token: str | None = None

    def _auth(self) -> dict:
        if self._token is None:
            try:
                r = self._http.post(TOKEN_URL, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                                     "assertion": _assertion(self._key)})
            except httpx.HTTPError as exc:
                raise GcpError("unreachable") from exc
            if r.status_code != 200:
                raise GcpError("unauthorized")
            self._token = r.json().get("access_token")
        return {"Authorization": f"Bearer {self._token}"}

    def _get(self, url: str) -> dict:
        try:
            r = self._http.get(url, headers=self._auth())
        except httpx.HTTPError as exc:
            raise GcpError("unreachable") from exc
        if r.status_code in (401, 403):
            raise GcpError("forbidden")
        if r.status_code == 404:
            raise GcpError("not_found")
        if r.status_code != 200:
            raise GcpError("error")
        return r.json()

    def project(self) -> dict:
        d = self._get(f"https://cloudresourcemanager.googleapis.com/v1/projects/{self.project_id}")
        return {"projectId": d.get("projectId"), "name": d.get("name"), "state": d.get("lifecycleState")}

    def compute(self) -> list[dict]:
        d = self._get(f"https://compute.googleapis.com/compute/v1/projects/{self.project_id}/aggregated/instances"
                      f"?maxResults={MAX_ITEMS}")
        out = []
        for scoped in (d.get("items") or {}).values():
            for i in scoped.get("instances", []):
                out.append({"name": i.get("name"), "zone": (i.get("zone") or "").rsplit("/", 1)[-1],
                            "machineType": (i.get("machineType") or "").rsplit("/", 1)[-1], "status": i.get("status")})
        return out[:MAX_ITEMS]

    def cloud_run(self) -> list[dict]:
        d = self._get(f"https://run.googleapis.com/v2/projects/{self.project_id}/locations/-/services")
        out = []
        for s in d.get("services", []):
            parts = (s.get("name") or "").split("/")  # projects/P/locations/REGION/services/NAME
            ready = any(c.get("type") == "Ready" and c.get("state") == "CONDITION_SUCCEEDED" for c in s.get("conditions", []))
            out.append({"name": parts[-1], "region": parts[3] if len(parts) > 3 else "", "uri": s.get("uri"),
                        "status": "ready" if ready else "not_ready"})
        return out[:MAX_ITEMS]

    def gke(self) -> list[dict]:
        d = self._get(f"https://container.googleapis.com/v1/projects/{self.project_id}/locations/-/clusters")
        return [{"name": c.get("name"), "location": c.get("location"), "status": c.get("status"),
                 "nodeCount": c.get("currentNodeCount")} for c in d.get("clusters", [])][:MAX_ITEMS]
