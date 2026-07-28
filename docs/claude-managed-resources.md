# Managed Claude resources

Skills and MCP servers are enterprise resources, not arbitrary policy JSON.
The control plane owns a tenant-scoped registry; policies reference registered
resource IDs; and an enrolled deployment reconciles the effective policy into
the project configuration.

## Trust boundary

The browser never writes to a developer's filesystem. It can register a
resource and select it in a policy, but a deployment agent must authenticate,
fetch the effective policy, validate the resource manifest, and apply it to
the target project. The deployment agent reports the applied manifest hash and
drift status back to the control plane.

Skills are stored as reviewed, versioned content with a digest. They are
installed as project-scoped `.claude/skills/<name>/SKILL.md` files. Skill
content is prompt input and may influence the model; it is not a security
authority and cannot alter immutable SDK safeguards.

MCP registrations contain transport, executable or URL, arguments, and
non-secret environment references. Secret values are deployment-owned and are
never stored in the policy or resource registry. Project-scoped MCP entries
are written to `.mcp.json`; the SDK gateway remains mandatory for SDK-owned
tools. External MCP servers are only made available when explicitly selected
by the policy and allowed by the deployment's host controls.

## Application lifecycle

1. A security operator registers and reviews a Skill or MCP server.
2. The operator selects resource IDs in a typed policy editor.
3. Applying the policy creates a new immutable policy version and audits the
   resource set.
4. The enrolled deployment agent fetches the effective policy, resolves the
   selected registry entries, validates signatures/digests and writes only the
   project-scoped managed files.
5. Claude Code is restarted or refreshed, and the agent reports the applied
   manifest hash. Missing, invalid, revoked, or unavailable resources fail
   closed and are not installed.

Removing a resource from a policy removes it from the managed set on the next
reconciliation. Files outside the managed manifest are preserved and are
reported as unmanaged configuration rather than silently deleted.

## What this does not provide

This mechanism does not sandbox Claude Code, make arbitrary Skills trusted, or
make an external MCP server secure. High-risk MCP actions still need to route
through the SDK gateway or an independently reviewed, authenticated adapter.
Host-level permissions, secrets, network egress and process isolation remain
deployment-owned controls.
