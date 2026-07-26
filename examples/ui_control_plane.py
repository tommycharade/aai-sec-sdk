"""Run the local reference control plane used by ``aai-sec-ui``.

This example is intentionally bound to localhost and requires an explicit
bearer token.  It persists only validated configuration and synthetic
dashboard state; production deployments must replace the token mechanism and
wire the saved configuration to an application-owned ``GuardedRuntime``.
"""

from __future__ import annotations

import os
from pathlib import Path
from wsgiref.simple_server import make_server

from agentic_security import (
    AgentPresenceStore,
    ControlPlaneApplication,
    ControlPlaneStore,
    InMemoryAuditSink,
    InMemoryControlPlaneAuthority,
    OperatorIdentity,
    StaticBearerAuthenticator,
)


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
    application = ControlPlaneApplication(
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
    print(f"AAI Security UI control plane listening on http://{host}:{port}")
    print(f"Validated configuration will be stored at {path}")
    print("Agent presence token is configured for the local Claude MCP example.")
    with make_server(host, port, application) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
