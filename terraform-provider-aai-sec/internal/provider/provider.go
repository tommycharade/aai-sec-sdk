// Package provider exposes declarative Agentic Security management resources.
package provider

import (
	"context"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	providerschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tommycharade/terraform-provider-aai-sec/internal/client"
)

// aaiProvider binds Terraform only to the separately authenticated machine API.
type aaiProvider struct{ version string }

type providerModel struct {
	Endpoint       types.String `tfsdk:"endpoint"`
	Token          types.String `tfsdk:"token"`
	TimeoutSeconds types.Int64  `tfsdk:"timeout_seconds"`
}

// New returns a provider factory for the Terraform protocol server.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &aaiProvider{version: version} }
}

func (p *aaiProvider) Metadata(_ context.Context, _ provider.MetadataRequest, response *provider.MetadataResponse) {
	response.TypeName = "aaisec"
	response.Version = p.version
}

func (p *aaiProvider) Schema(_ context.Context, _ provider.SchemaRequest, response *provider.SchemaResponse) {
	response.Schema = providerschema.Schema{
		Description: "Manages draft and fleet configuration through the scoped Agentic Security machine API. It cannot approve or activate policy.",
		Attributes: map[string]providerschema.Attribute{
			"endpoint":        providerschema.StringAttribute{Optional: true, Description: "Control-plane origin. May also be set with AAI_SEC_ENDPOINT."},
			"token":           providerschema.StringAttribute{Optional: true, Sensitive: true, Description: "Short-lived service identity token. May also be set with AAI_SEC_SERVICE_TOKEN."},
			"timeout_seconds": providerschema.Int64Attribute{Optional: true, Description: "Per-request timeout from 1 to 120 seconds; defaults to 30.", Validators: []validator.Int64{boundedInt64{minimum: 1, maximum: 120}}},
		},
	}
}

func (p *aaiProvider) Configure(ctx context.Context, request provider.ConfigureRequest, response *provider.ConfigureResponse) {
	var configuration providerModel
	response.Diagnostics.Append(request.Config.Get(ctx, &configuration)...)
	if response.Diagnostics.HasError() {
		return
	}
	endpoint := configuration.Endpoint.ValueString()
	if endpoint == "" {
		endpoint = os.Getenv("AAI_SEC_ENDPOINT")
	}
	token := configuration.Token.ValueString()
	if token == "" {
		token = os.Getenv("AAI_SEC_SERVICE_TOKEN")
	}
	timeout := int64(30)
	if !configuration.TimeoutSeconds.IsNull() && !configuration.TimeoutSeconds.IsUnknown() {
		timeout = configuration.TimeoutSeconds.ValueInt64()
	}
	api, err := client.New(endpoint, token, time.Duration(timeout)*time.Second)
	if err != nil {
		response.Diagnostics.AddError("Invalid Agentic Security provider configuration", err.Error())
		return
	}
	response.DataSourceData = api
	response.ResourceData = api
}

func (p *aaiProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newSkillResource,
		newMCPServerResource,
		newGroupResource,
		newPolicyDraftResource,
	}
}

func (p *aaiProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newTenantDataSource}
}

// boundedInt64 keeps timeout validation local and deterministic.
type boundedInt64 struct{ minimum, maximum int64 }

func (v boundedInt64) Description(context.Context) string {
	return "value must be within the documented bounds"
}
func (v boundedInt64) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (v boundedInt64) ValidateInt64(_ context.Context, request validator.Int64Request, response *validator.Int64Response) {
	if request.ConfigValue.IsNull() || request.ConfigValue.IsUnknown() {
		return
	}
	value := request.ConfigValue.ValueInt64()
	if value < v.minimum || value > v.maximum {
		response.Diagnostics.AddAttributeError(request.Path, "Value outside safe bounds", "The value is outside the documented minimum and maximum.")
	}
}

func configuredClient(data any, diagnostics *diag.Diagnostics) *client.Client {
	api, ok := data.(*client.Client)
	if !ok || api == nil {
		diagnostics.AddError("Provider is not configured", "Configure the aai_sec provider before using this object.")
		return nil
	}
	return api
}

func stringList(ctx context.Context, value types.List, diagnostics *diag.Diagnostics) []string {
	if value.IsNull() || value.IsUnknown() {
		return []string{}
	}
	var result []string
	diagnostics.Append(value.ElementsAs(ctx, &result, false)...)
	return result
}

func listValue(values []string, diagnostics *diag.Diagnostics) types.List {
	items := make([]attr.Value, 0, len(values))
	for _, value := range values {
		items = append(items, types.StringValue(value))
	}
	result, itemDiagnostics := types.ListValue(types.StringType, items)
	diagnostics.Append(itemDiagnostics...)
	return result
}
