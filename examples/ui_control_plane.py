"""Run the local reference control plane used by ``aai-sec-ui``.

This example is intentionally bound to localhost and requires an explicit
bearer token.  It persists only validated configuration and synthetic
dashboard state; production deployments must replace the token mechanism and
wire the saved configuration to an application-owned ``GuardedRuntime``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast
from wsgiref.simple_server import make_server

from agentic_security import (
    AgentPresenceStore,
    ControlPlaneApplication,
    ControlPlaneStore,
    EnterpriseFleetApplication,
    EnterpriseFleetStore,
    FleetIdentity,
    InMemoryAuditSink,
    InMemoryControlPlaneAuthority,
    OperatorIdentity,
    StaticBearerAuthenticator,
    StaticFleetAuthenticator,
)


class CombinedControlPlaneApplication:
    """Route local runtime and enterprise fleet APIs through one HTTP server."""

    def __init__(self, runtime: Any, enterprise: Any) -> None:
        """Bind the two explicitly scoped reference applications."""
        self.runtime = runtime
        self.enterprise = enterprise

    def __call__(self, environ: dict[str, Any], start_response: Any) -> list[bytes]:
        """Dispatch enterprise paths without changing the existing runtime API."""
        if str(environ.get("PATH_INFO", "")).startswith("/api/enterprise/"):
            return cast(list[bytes], self.enterprise(environ, start_response))
        return cast(list[bytes], self.runtime(environ, start_response))


def main() -> None:
    """Start the local UI control plane with explicit development settings."""
    token = os.environ.get("AAI_SEC_UI_TOKEN")
    if not token:
        raise SystemExit("Set AAI_SEC_UI_TOKEN to a development token of at least 16 characters.")
    path = Path(os.environ.get("AAI_SEC_UI_CONFIG", ".aai-sec-ui/config.json"))
    host = os.environ.get("AAI_SEC_UI_HOST", "127.0.0.1")
    port = int(os.environ.get("AAI_SEC_UI_PORT", "8000"))
    agent_token = os.environ.get("AAI_SEC_AGENT_TOKEN", "synthetic-agent-token-1234")
    audit = InMemoryAuditSink()
    presence = AgentPresenceStore(audit=audit)
    application: Any = ControlPlaneApplication(
        ControlPlaneStore(
            path,
            authority=InMemoryControlPlaneAuthority(),
            audit=audit,
            presence=presence,
        ),
        authenticator=StaticBearerAuthenticator(
            {
                token: OperatorIdentity("local-operator", frozenset({"admin"})),
                agent_token: OperatorIdentity("claude-code-local", frozenset({"agent"})),
            }
        ),
        allowed_origin=os.environ.get("AAI_SEC_UI_ORIGIN", "http://localhost:5173"),
    )
    fleet = EnterpriseFleetStore(path.with_name("fleet.sqlite"), audit=audit)
    fleet_identity = FleetIdentity("local-operator", "org-example", frozenset({"admin"}))
    try:
        fleet.create_organization("org-example", "Example enterprise")
        fleet.create_project("org-example", "project-platform", "Platform")
        fleet.create_deployment(
            "org-example",
            "project-platform",
            "deployment-local",
            "Local development",
            environment="development",
            region="local",
            sdk_version="1.1.0",
            team="platform",
        )
    except ValueError:
        # The seed is idempotent for the local reference database.
        pass
    try:
        fleet.create_template(
            fleet_identity,
            template_id="template-safe-default",
            name="Safe default",
            configuration={
                "runtime": {
                    "allowedTools": ["read_repository"],
                    "maxActions": 25,
                    "maxConcurrent": 2,
                    "maxFanOut": 2,
                    "maxCostUnits": 25,
                    "maxDelegationDepth": 1,
                    "credentialsEnabled": False,
                    "isolationRequiredForHighRisk": True,
                    "redactSensitiveData": True,
                    "captureToolContent": False,
                },
                "rollout": {"requireApproval": True},
            },
        )
    except ValueError:
        pass
    try:
        fleet.assign_template(fleet_identity, "deployment-local", "template-safe-default")
    except ValueError:
        # Re-applying the same local seed is intentionally harmless.
        pass
    enterprise_application = EnterpriseFleetApplication(
        fleet,
        authenticator=StaticFleetAuthenticator(
            {
                token: fleet_identity,
                agent_token: FleetIdentity(
                    "claude-code-local", "org-example", frozenset({"agent"})
                ),
            }
        ),
        allowed_origin=os.environ.get("AAI_SEC_UI_ORIGIN", "http://localhost:5173"),
    )
    application = CombinedControlPlaneApplication(application, enterprise_application)
    print(f"AAI Security UI control plane listening on http://{host}:{port}")
    print(f"Validated configuration will be stored at {path}")
    print("Agent presence token is configured for the local Claude MCP example.")
    with make_server(host, port, application) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
