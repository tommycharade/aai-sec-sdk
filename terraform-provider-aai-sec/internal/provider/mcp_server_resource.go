package provider

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tommycharade/terraform-provider-aai-sec/internal/client"
)

type mcpServerResource struct{ client *client.Client }

type mcpServerModel struct {
	ID                    types.String `tfsdk:"id"`
	OrganizationID        types.String `tfsdk:"organization_id"`
	Name                  types.String `tfsdk:"name"`
	Description           types.String `tfsdk:"description"`
	Version               types.String `tfsdk:"version"`
	Transport             types.String `tfsdk:"transport"`
	Command               types.String `tfsdk:"command"`
	Arguments             types.List   `tfsdk:"arguments"`
	URL                   types.String `tfsdk:"url"`
	EnvironmentReferences types.List   `tfsdk:"environment_references"`
	Enabled               types.Bool   `tfsdk:"enabled"`
	Revision              types.Int64  `tfsdk:"revision"`
	Status                types.String `tfsdk:"status"`
}

func newMCPServerResource() resource.Resource { return &mcpServerResource{} }

func (r *mcpServerResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_mcp_server"
}

func (r *mcpServerResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = resourceschema.Schema{
		Description: "Registers an approved MCP server definition. Credentials are references, never values. Destroy retires the registration.",
		Attributes: map[string]resourceschema.Attribute{
			"id":                     resourceschema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"organization_id":        resourceschema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"name":                   resourceschema.StringAttribute{Required: true},
			"description":            resourceschema.StringAttribute{Required: true},
			"version":                resourceschema.StringAttribute{Required: true},
			"transport":              resourceschema.StringAttribute{Required: true, Description: "Either stdio or http; the server validates the exact value."},
			"command":                resourceschema.StringAttribute{Optional: true, Computed: true, Description: "Executable name for stdio transport."},
			"arguments":              resourceschema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType},
			"url":                    resourceschema.StringAttribute{Optional: true, Computed: true, Description: "HTTPS endpoint for HTTP transport."},
			"environment_references": resourceschema.ListAttribute{Required: true, ElementType: types.StringType, Description: "Environment variable names only; never secret values."},
			"enabled":                resourceschema.BoolAttribute{Required: true},
			"revision":               resourceschema.Int64Attribute{Computed: true},
			"status":                 resourceschema.StringAttribute{Computed: true},
		},
	}
}

func (r *mcpServerResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	if request.ProviderData != nil {
		r.client = configuredClient(request.ProviderData, &response.Diagnostics)
	}
}

func mcpPayloadWithDiagnostics(ctx context.Context, model mcpServerModel, diagnostics *diag.Diagnostics) map[string]any {
	return map[string]any{
		"serverId": model.ID.ValueString(), "organizationId": model.OrganizationID.ValueString(),
		"name": model.Name.ValueString(), "description": model.Description.ValueString(),
		"version": model.Version.ValueString(), "transport": model.Transport.ValueString(),
		"command": model.Command.ValueString(), "args": stringList(ctx, model.Arguments, diagnostics),
		"url": model.URL.ValueString(), "environmentReferences": stringList(ctx, model.EnvironmentReferences, diagnostics),
		"enabled": model.Enabled.ValueBool(),
	}
}

func mcpState(item map[string]any, state *mcpServerModel, diagnostics *diag.Diagnostics) {
	state.ID = types.StringValue(textField(item, "id"))
	state.OrganizationID = types.StringValue(textField(item, "organizationId"))
	state.Name = types.StringValue(textField(item, "name"))
	state.Description = types.StringValue(textField(item, "description"))
	state.Version = types.StringValue(textField(item, "version"))
	state.Transport = types.StringValue(textField(item, "transport"))
	state.Command = nullableString(item, "command")
	state.URL = nullableString(item, "url")
	state.Arguments = listValue(stringSliceField(item, "args"), diagnostics)
	state.EnvironmentReferences = listValue(stringSliceField(item, "environmentReferences"), diagnostics)
	state.Enabled = types.BoolValue(boolField(item, "enabled"))
	state.Revision = types.Int64Value(intField(item, "revision"))
	state.Status = types.StringValue(textField(item, "status"))
}

func nullableString(item map[string]any, key string) types.String {
	if item[key] == nil || textField(item, key) == "" {
		return types.StringNull()
	}
	return types.StringValue(textField(item, key))
}

func (r *mcpServerResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan mcpServerModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	payload := mcpPayloadWithDiagnostics(ctx, plan, &response.Diagnostics)
	if response.Diagnostics.HasError() {
		return
	}
	var item map[string]any
	if err := r.client.Do(ctx, http.MethodPost, "/mcp-servers", payload, &item); err != nil {
		response.Diagnostics.AddError("Could not create MCP server", err.Error())
		return
	}
	mcpState(item, &plan, &response.Diagnostics)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *mcpServerResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state mcpServerModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, found, err := r.client.Find(ctx, "/mcp-servers", state.ID.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Could not read MCP server", err.Error())
		return
	}
	if !found || textField(item, "status") == "retired" {
		response.State.RemoveResource(ctx)
		return
	}
	mcpState(item, &state, &response.Diagnostics)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *mcpServerResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan, state mcpServerModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	payload := mcpPayloadWithDiagnostics(ctx, plan, &response.Diagnostics)
	payload["expectedRevision"] = state.Revision.ValueInt64()
	if response.Diagnostics.HasError() {
		return
	}
	var item map[string]any
	if err := r.client.Do(ctx, http.MethodPut, "/mcp-servers/"+plan.ID.ValueString(), payload, &item); err != nil {
		response.Diagnostics.AddError("Could not update MCP server", err.Error())
		return
	}
	mcpState(item, &plan, &response.Diagnostics)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *mcpServerResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state mcpServerModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	if err := r.client.Do(ctx, http.MethodDelete, "/mcp-servers/"+state.ID.ValueString(), map[string]any{"expectedRevision": state.Revision.ValueInt64()}, nil); err != nil {
		response.Diagnostics.AddError("Could not retire MCP server", err.Error())
	}
}

func (r *mcpServerResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}
