terraform {
  required_providers {
    aaisec = {
      source = "tommycharade/aaisec"
    }
  }
}

provider "aaisec" {
  timeout_seconds = 30
}

data "aaisec_tenant" "current" {}

variable "active_policy_id" {
  type        = string
  description = "An independently approved and activated policy ID for the group."
}

resource "aaisec_skill" "secure_review" {
  id              = "secure-review"
  organization_id = "org-platform"
  name            = "Secure review"
  description     = "Synthetic repository review guidance."
  version         = "1.0.0"
  content         = "# Secure review\nDeny unsafe changes and redact synthetic secrets.\n"
  enabled         = true
}

resource "aaisec_mcp_server" "github" {
  id                     = "github-readonly"
  organization_id        = "org-platform"
  name                   = "GitHub read-only"
  description            = "Synthetic approved GitHub MCP registration."
  version                = "1.0.0"
  transport              = "http"
  url                    = "https://mcp.example.invalid/github"
  environment_references = ["GITHUB_MCP_TOKEN"]
  enabled                = true
}

resource "aaisec_policy_draft" "claude_safe" {
  id              = "claude-safe"
  organization_id = "org-platform"
  name            = "Claude safe default"
  configuration_json = jsonencode({
    allowed_tools = ["repository.read"]
    denied_tools  = ["shell.execute"]
  })
}

# This references a separately approved active policy. Terraform intentionally
# cannot turn the draft above into runtime authority during the same apply.
resource "aaisec_group" "platform" {
  id        = "group-platform"
  name      = "Platform engineering"
  policy_id = var.active_policy_id
}
