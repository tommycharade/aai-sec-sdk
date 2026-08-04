package provider

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tommycharade/terraform-provider-aai-sec/internal/client"
)

type policyDraftResource struct{ client *client.Client }
type policyDraftModel struct {
	ID                types.String `tfsdk:"id"`
	OrganizationID    types.String `tfsdk:"organization_id"`
	Name              types.String `tfsdk:"name"`
	ConfigurationJSON types.String `tfsdk:"configuration_json"`
	Version           types.Int64  `tfsdk:"version"`
	State             types.String `tfsdk:"state"`
	ContentHash       types.String `tfsdk:"content_hash"`
}

func newPolicyDraftResource() resource.Resource { return &policyDraftResource{} }
func (r *policyDraftResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_policy_draft"
}
func (r *policyDraftResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = resourceschema.Schema{Description: "Creates governed policy drafts. Changes append a new draft only after the previous version has completed governance. Approval, staging and activation remain human-only. Destroy removes Terraform tracking but retains the immutable server ledger.", Attributes: map[string]resourceschema.Attribute{
		"id": resourceschema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}, "organization_id": resourceschema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}, "name": resourceschema.StringAttribute{Required: true},
		"configuration_json": resourceschema.StringAttribute{Required: true, Description: "Schema-validated local policy configuration encoded as JSON."}, "version": resourceschema.Int64Attribute{Computed: true}, "state": resourceschema.StringAttribute{Computed: true}, "content_hash": resourceschema.StringAttribute{Computed: true},
	}}
}
func (r *policyDraftResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	if request.ProviderData != nil {
		r.client = configuredClient(request.ProviderData, &response.Diagnostics)
	}
}
func policyPayload(model policyDraftModel, includeID bool) (map[string]any, error) {
	var configuration map[string]any
	if err := json.Unmarshal([]byte(model.ConfigurationJSON.ValueString()), &configuration); err != nil {
		return nil, err
	}
	payload := map[string]any{"organizationId": model.OrganizationID.ValueString(), "name": model.Name.ValueString(), "configuration": configuration}
	if includeID {
		payload["policyId"] = model.ID.ValueString()
	}
	return payload, nil
}
func canonicalJSON(value any) string { encoded, _ := json.Marshal(value); return string(encoded) }
func policyVersionState(item map[string]any, state *policyDraftModel) {
	state.Name = types.StringValue(textField(item, "name"))
	state.Version = types.Int64Value(intField(item, "version"))
	state.State = types.StringValue(textField(item, "state"))
	state.ContentHash = types.StringValue(textField(item, "contentHash"))
	if organization := textField(item, "organizationId"); organization != "" {
		state.OrganizationID = types.StringValue(organization)
	}
	if configuration, ok := item["localConfiguration"].(map[string]any); ok {
		state.ConfigurationJSON = types.StringValue(canonicalJSON(configuration))
	} else if configuration, ok := item["configuration"].(map[string]any); ok {
		state.ConfigurationJSON = types.StringValue(canonicalJSON(configuration))
	}
}
func (r *policyDraftResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan policyDraftModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	payload, err := policyPayload(plan, true)
	if err != nil {
		response.Diagnostics.AddAttributeError(path.Root("configuration_json"), "Invalid policy JSON", err.Error())
		return
	}
	var summary map[string]any
	if err := r.client.Do(ctx, http.MethodPost, "/policies", payload, &summary); err != nil {
		response.Diagnostics.AddError("Could not create policy draft", err.Error())
		return
	}
	version := intField(summary, "pendingVersion")
	var item map[string]any
	if err := r.client.Do(ctx, http.MethodGet, "/policies/"+plan.ID.ValueString()+"/versions/"+itoa(version), nil, &item); err != nil {
		response.Diagnostics.AddError("Could not read created policy draft", err.Error())
		return
	}
	policyVersionState(item, &plan)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *policyDraftResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state policyDraftModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	summary, found, err := r.client.Find(ctx, "/policies", state.ID.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Could not read policy", err.Error())
		return
	}
	if !found {
		response.State.RemoveResource(ctx)
		return
	}
	version := intField(summary, "pendingVersion")
	if version == 0 {
		version = intField(summary, "activeVersion")
	}
	if version == 0 {
		version = intField(summary, "latestVersion")
	}
	var item map[string]any
	if err := r.client.Do(ctx, http.MethodGet, "/policies/"+state.ID.ValueString()+"/versions/"+itoa(version), nil, &item); err != nil {
		response.Diagnostics.AddError("Could not read policy version", err.Error())
		return
	}
	policyVersionState(item, &state)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}
func (r *policyDraftResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan policyDraftModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	payload, err := policyPayload(plan, false)
	if err != nil {
		response.Diagnostics.AddAttributeError(path.Root("configuration_json"), "Invalid policy JSON", err.Error())
		return
	}
	var item map[string]any
	if err := r.client.Do(ctx, http.MethodPost, "/policies/"+plan.ID.ValueString()+"/versions", payload, &item); err != nil {
		response.Diagnostics.AddError("Could not append policy draft", err.Error())
		return
	}
	policyVersionState(item, &plan)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *policyDraftResource) Delete(_ context.Context, _ resource.DeleteRequest, response *resource.DeleteResponse) {
	response.Diagnostics.AddWarning("Policy retained", "Terraform removed its tracking state, but the immutable governed policy ledger remains in Agentic Security.")
}
func (r *policyDraftResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}
