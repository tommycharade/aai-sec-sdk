package provider

import (
	"context"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tommycharade/terraform-provider-aai-sec/internal/client"
)

type tenantDataSource struct{ client *client.Client }
type tenantModel struct {
	ID             types.String `tfsdk:"id"`
	Status         types.String `tfsdk:"status"`
	Trial          types.Bool   `tfsdk:"trial"`
	TrialExpiresAt types.Int64  `tfsdk:"trial_expires_at"`
	CreatedAt      types.Int64  `tfsdk:"created_at"`
}

func newTenantDataSource() datasource.DataSource { return &tenantDataSource{} }
func (d *tenantDataSource) Metadata(_ context.Context, request datasource.MetadataRequest, response *datasource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_tenant"
}
func (d *tenantDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, response *datasource.SchemaResponse) {
	response.Schema = datasourceschema.Schema{Description: "Reads the exact tenant bound to the service identity. Tenant provisioning remains deployment-owned.", Attributes: map[string]datasourceschema.Attribute{"id": datasourceschema.StringAttribute{Computed: true}, "status": datasourceschema.StringAttribute{Computed: true}, "trial": datasourceschema.BoolAttribute{Computed: true}, "trial_expires_at": datasourceschema.Int64Attribute{Computed: true}, "created_at": datasourceschema.Int64Attribute{Computed: true}}}
}
func (d *tenantDataSource) Configure(_ context.Context, request datasource.ConfigureRequest, response *datasource.ConfigureResponse) {
	if request.ProviderData != nil {
		d.client = configuredClient(request.ProviderData, &response.Diagnostics)
	}
}
func (d *tenantDataSource) Read(ctx context.Context, _ datasource.ReadRequest, response *datasource.ReadResponse) {
	var item map[string]any
	if err := d.client.Do(ctx, http.MethodGet, "/tenant", nil, &item); err != nil {
		response.Diagnostics.AddError("Could not read tenant", err.Error())
		return
	}
	state := tenantModel{ID: types.StringValue(textField(item, "id")), Status: types.StringValue(textField(item, "status")), Trial: types.BoolValue(boolField(item, "trial")), TrialExpiresAt: nullableInt(item, "trialExpiresAt"), CreatedAt: nullableInt(item, "createdAt")}
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}
func nullableInt(item map[string]any, key string) types.Int64 {
	if item[key] == nil {
		return types.Int64Null()
	}
	return types.Int64Value(intField(item, key))
}
func itoa(value int64) string { return strconv.FormatInt(value, 10) }
