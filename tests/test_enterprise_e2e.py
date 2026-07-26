"""Real HTTP end-to-end coverage for the enterprise reference control plane."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from wsgiref.simple_server import WSGIServer, make_server

from agentic_security import (
    EnterpriseFleetApplication,
    EnterpriseFleetStore,
    FleetIdentity,
    StaticFleetAuthenticator,
)


@contextmanager
def running_server(app: Any) -> Iterator[str]:
    """Serve the actual WSGI boundary on an ephemeral local TCP port."""
    server: WSGIServer = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def request_json(
    base_url: str, token: str, method: str, path: str, body: dict[str, Any] | None = None
) -> tuple[int, dict[str, Any]]:
    """Send one authenticated HTTP request through the reference server."""
    payload = json.dumps(body).encode() if body is not None else None
    request = Request(  # noqa: S310 - URL is constructed from the test-owned localhost server.
        f"{base_url}{path}",
        data=payload,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urlopen(request, timeout=3) as response:  # noqa: S310 - localhost URL is test-owned.
        return response.status, json.loads(response.read())


def test_enterprise_reference_server_end_to_end(tmp_path: Path) -> None:
    """HTTP clients can register, govern, roll out, and evidence one deployment."""
    token = "enterprise-e2e-token-1234"  # noqa: S105 - synthetic test credential.
    identity = FleetIdentity("e2e-admin", "org-e2e", frozenset({"admin"}))
    store = EnterpriseFleetStore(tmp_path / "fleet.sqlite")
    store.create_organization("org-e2e", "E2E Enterprise")
    store.create_project("org-e2e", "project-e2e", "E2E Project")
    app = EnterpriseFleetApplication(
        store,
        authenticator=StaticFleetAuthenticator({token: identity}),
        allowed_origin="http://localhost:5175",
    )

    with running_server(app) as base_url:
        status, deployment = request_json(
            base_url,
            token,
            "POST",
            "/api/enterprise/deployments",
            {
                "organizationId": "org-e2e",
                "projectId": "project-e2e",
                "deploymentId": "deployment-e2e",
                "name": "E2E Claude",
                "environment": "staging",
                "region": "eu-west-2",
                "team": "platform",
            },
        )
        assert status == 201 and deployment["id"] == "deployment-e2e"
        status, _ = request_json(
            base_url,
            token,
            "POST",
            "/api/enterprise/deployments",
            {
                "organizationId": "org-e2e",
                "projectId": "project-e2e",
                "deploymentId": "deployment-e2e-2",
                "name": "E2E Claude 2",
                "environment": "staging",
                "region": "us-east-1",
            },
        )
        assert status == 201
        status, first_page = request_json(
            base_url, token, "GET", "/api/enterprise/deployments?limit=1"
        )
        assert status == 200 and len(first_page["items"]) == 1
        assert first_page["nextCursor"] == "1"
        status, second_page = request_json(
            base_url,
            token,
            "GET",
            f"/api/enterprise/deployments?limit=1&cursor={first_page['nextCursor']}",
        )
        assert status == 200 and len(second_page["items"]) == 1
        status, template = request_json(
            base_url,
            token,
            "POST",
            "/api/enterprise/templates",
            {
                "templateId": "template-e2e",
                "name": "E2E safe default",
                "configuration": {
                    "policy": {"denyByDefault": True},
                    "budgets": {"maxActions": 10},
                    "isolation": {"requiredForHighRisk": True},
                },
            },
        )
        assert status == 201 and template["id"] == "template-e2e"
        status, assigned = request_json(
            base_url,
            token,
            "POST",
            "/api/enterprise/deployment-config",
            {"deploymentId": "deployment-e2e", "templateId": "template-e2e"},
        )
        assert status == 200 and assigned["rolloutState"] == "staged"
        status, rolled_out = request_json(
            base_url,
            token,
            "POST",
            "/api/enterprise/deployment-config/rollout",
            {"deploymentId": "deployment-e2e", "state": "canary", "percentage": 10},
        )
        assert status == 200 and rolled_out["rolloutState"] == "canary"
        status, evidence = request_json(
            base_url, token, "GET", "/api/enterprise/compliance/evidence"
        )
        assert status == 200
        assert evidence["deploymentCount"] == 2
        assert evidence["deployments"][0]["configuration"]["desiredHash"]
        assert evidence["redaction"]["credentialMaterialIncluded"] is False
        status, capabilities = request_json(base_url, token, "GET", "/api/enterprise/capabilities")
        assert status == 200
        assert capabilities["adapter"] == "sqlite-reference"
        assert capabilities["highAvailability"] is False
