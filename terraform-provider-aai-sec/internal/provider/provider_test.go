package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	providerschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestProviderSchemaAndObjectInventory(t *testing.T) {
	t.Parallel()
	instance := New("test")()
	var schema provider.SchemaResponse
	instance.Schema(context.Background(), provider.SchemaRequest{}, &schema)
	if schema.Diagnostics.HasError() {
		t.Fatalf("provider schema diagnostics: %v", schema.Diagnostics)
	}
	attribute, ok := schema.Schema.Attributes["token"].(providerschema.StringAttribute)
	if !ok || !attribute.Sensitive {
		t.Error("service token must be a sensitive provider attribute")
	}
	if got := len(instance.Resources(context.Background())); got != 4 {
		t.Fatalf("expected four declarative resources, got %d", got)
	}
	if got := len(instance.DataSources(context.Background())); got != 1 {
		t.Fatalf("expected tenant data source, got %d", got)
	}
}

func TestPolicyPayloadRejectsNonObjectJSON(t *testing.T) {
	t.Parallel()
	model := policyDraftModel{ConfigurationJSON: types.StringValue("[]")}
	if _, err := policyPayload(model, true); err == nil {
		t.Error("policy configuration array was accepted")
	}
}
