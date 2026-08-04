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

type skillResource struct{ client *client.Client }

type skillModel struct {
	ID             types.String `tfsdk:"id"`
	OrganizationID types.String `tfsdk:"organization_id"`
	Name           types.String `tfsdk:"name"`
	Description    types.String `tfsdk:"description"`
	Version        types.String `tfsdk:"version"`
	Content        types.String `tfsdk:"content"`
	Enabled        types.Bool   `tfsdk:"enabled"`
	Digest         types.String `tfsdk:"digest"`
	Revision       types.Int64  `tfsdk:"revision"`
	Status         types.String `tfsdk:"status"`
}

func newSkillResource() resource.Resource { return &skillResource{} }

func (r *skillResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_skill"
}

func (r *skillResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = resourceschema.Schema{
		Description: "Registers a project-scoped Claude Code Skill. Destroy retires it and retains server evidence.",
		Attributes: map[string]resourceschema.Attribute{
			"id":              resourceschema.StringAttribute{Required: true, Description: "Stable tenant-scoped Skill identifier.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"organization_id": resourceschema.StringAttribute{Required: true, Description: "Immutable organization owner.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"name":            resourceschema.StringAttribute{Required: true},
			"description":     resourceschema.StringAttribute{Required: true},
			"version":         resourceschema.StringAttribute{Required: true},
			"content":         resourceschema.StringAttribute{Required: true, Description: "Bounded SKILL.md content installed only when selected by governed policy."},
			"enabled":         resourceschema.BoolAttribute{Required: true},
			"digest":          resourceschema.StringAttribute{Computed: true},
			"revision":        resourceschema.Int64Attribute{Computed: true},
			"status":          resourceschema.StringAttribute{Computed: true},
		},
	}
}

func (r *skillResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	if request.ProviderData != nil {
		r.client = configuredClient(request.ProviderData, &response.Diagnostics)
	}
}

func skillPayload(model skillModel) map[string]any {
	return map[string]any{
		"skillId": model.ID.ValueString(), "organizationId": model.OrganizationID.ValueString(),
		"name": model.Name.ValueString(), "description": model.Description.ValueString(),
		"version": model.Version.ValueString(), "content": model.Content.ValueString(),
		"enabled": model.Enabled.ValueBool(),
	}
}

func skillState(item map[string]any, state *skillModel) {
	state.ID = types.StringValue(textField(item, "id"))
	state.OrganizationID = types.StringValue(textField(item, "organizationId"))
	state.Name = types.StringValue(textField(item, "name"))
	state.Description = types.StringValue(textField(item, "description"))
	state.Version = types.StringValue(textField(item, "version"))
	state.Content = types.StringValue(textField(item, "content"))
	state.Enabled = types.BoolValue(boolField(item, "enabled"))
	state.Digest = types.StringValue(textField(item, "digest"))
	state.Revision = types.Int64Value(intField(item, "revision"))
	state.Status = types.StringValue(textField(item, "status"))
}

func (r *skillResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan skillModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	var item map[string]any
	if err := r.client.Do(ctx, http.MethodPost, "/skills", skillPayload(plan), &item); err != nil {
		response.Diagnostics.AddError("Could not create Skill", err.Error())
		return
	}
	skillState(item, &plan)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *skillResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state skillModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, found, err := r.client.Find(ctx, "/skills", state.ID.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Could not read Skill", err.Error())
		return
	}
	if !found || textField(item, "status") == "retired" {
		response.State.RemoveResource(ctx)
		return
	}
	skillState(item, &state)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *skillResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan, state skillModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	payload := skillPayload(plan)
	payload["expectedRevision"] = state.Revision.ValueInt64()
	var item map[string]any
	if err := r.client.Do(ctx, http.MethodPut, "/skills/"+plan.ID.ValueString(), payload, &item); err != nil {
		response.Diagnostics.AddError("Could not update Skill", err.Error())
		return
	}
	skillState(item, &plan)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *skillResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state skillModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	if err := r.client.Do(ctx, http.MethodDelete, "/skills/"+state.ID.ValueString(), map[string]any{"expectedRevision": state.Revision.ValueInt64()}, nil); err != nil {
		response.Diagnostics.AddError("Could not retire Skill", err.Error())
	}
}

func (r *skillResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}
