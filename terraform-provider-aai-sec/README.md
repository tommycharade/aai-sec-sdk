# Agentic Security Terraform provider

This provider manages policy drafts, groups, Skills and MCP registrations
through the scoped `/machine/v1` API. It cannot approve or activate policy.

## Local verification

```bash
go test ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go build ./...
```

For a local Terraform smoke test, build the provider and configure a Terraform
CLI `dev_overrides` entry for `registry.terraform.io/tommycharade/aaisec` pointing
to the directory containing the binary. Export `AAI_SEC_ENDPOINT` and the
one-time `AAI_SEC_SERVICE_TOKEN`; do not commit either value.

See [the full design and usage guide](../docs/terraform-provider-design.md) and
the [synthetic example](examples/basic/main.tf).
