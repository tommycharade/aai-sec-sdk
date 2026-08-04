package provider

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tommycharade/terraform-provider-aai-sec/internal/client"
)

type groupResource struct{ client *client.Client }

type groupModel struct {
	ID                    types.String `tfsdk:"id"`
	Name                  types.String `tfsdk:"name"`
	PolicyID              types.String `tfsdk:"policy_id"`
	OrganizationID        types.String `tfsdk:"organization_id"`
	ConfigurationRevision types.Int64  `tfsdk:"configuration_revision"`
	MembershipRevision    types.Int64  `tfsdk:"membership_revision"`
	MemberCount           types.Int64  `tfsdk:"member_count"`
}

func newGroupResource() resource.Resource { return &groupResource{} }
func (r *groupResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_group"
}
func (r *groupResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = resourceschema.Schema{Description: "Manages an agent group bound to an already-active governed policy. Membership is managed separately and an occupied group cannot be destroyed.", Attributes: map[string]resourceschema.Attribute{
		"id":                     resourceschema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"name":                   resourceschema.StringAttribute{Required: true},
		"policy_id":              resourceschema.StringAttribute{Required: true, Description: "An active policy ID; Terraform cannot activate a draft."},
		"organization_id":        resourceschema.StringAttribute{Computed: true},
		"configuration_revision": resourceschema.Int64Attribute{Computed: true},
		"membership_revision":    resourceschema.Int64Attribute{Computed: true},
		"member_count":           resourceschema.Int64Attribute{Computed: true},
	}}
}
func (r *groupResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	if request.ProviderData != nil {
		r.client = configuredClient(request.ProviderData, &response.Diagnostics)
	}
}

func groupState(item map[string]any, state *groupModel) {
	state.ID = types.StringValue(textField(item, "id"))
	state.Name = types.StringValue(textField(item, "name"))
	state.PolicyID = types.StringValue(textField(item, "policyId"))
	state.OrganizationID = types.StringValue(textField(item, "organizationId"))
	state.ConfigurationRevision = types.Int64Value(intField(item, "configurationRevision"))
	state.MembershipRevision = types.Int64Value(intField(item, "membershipRevision"))
	if agents, ok := item["agents"].([]any); ok {
		state.MemberCount = types.Int64Value(int64(len(agents)))
	} else {
		state.MemberCount = types.Int64Value(intField(item, "memberCount"))
	}
}
func (r *groupResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan groupModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	var item map[string]any
	payload := map[string]any{"groupId": plan.ID.ValueString(), "name": plan.Name.ValueString(), "policyId": plan.PolicyID.ValueString()}
	if err := r.client.Do(ctx, http.MethodPost, "/groups", payload, &item); err != nil {
		response.Diagnostics.AddError("Could not create group", err.Error())
		return
	}
	groupState(item, &plan)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *groupResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state groupModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, found, err := r.client.Find(ctx, "/groups", state.ID.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Could not read group", err.Error())
		return
	}
	if !found {
		response.State.RemoveResource(ctx)
		return
	}
	groupState(item, &state)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}
func (r *groupResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan, state groupModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	payload := map[string]any{"name": plan.Name.ValueString(), "policyId": plan.PolicyID.ValueString(), "expectedConfigurationRevision": state.ConfigurationRevision.ValueInt64()}
	var item map[string]any
	if err := r.client.Do(ctx, http.MethodPut, "/groups/"+plan.ID.ValueString(), payload, &item); err != nil {
		response.Diagnostics.AddError("Could not update group", err.Error())
		return
	}
	groupState(item, &plan)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *groupResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state groupModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	if err := r.client.Do(ctx, http.MethodDelete, "/groups/"+state.ID.ValueString(), map[string]any{"expectedConfigurationRevision": state.ConfigurationRevision.ValueInt64()}, nil); err != nil {
		response.Diagnostics.AddError("Could not delete group", err.Error())
	}
}
func (r *groupResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}
