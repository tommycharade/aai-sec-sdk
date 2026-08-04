// Command terraform-provider-aai-sec serves the Agentic Security Terraform provider.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/tommycharade/terraform-provider-aai-sec/internal/provider"
)

var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run the provider with debugger support")
	flag.Parse()
	err := providerserver.Serve(
		context.Background(),
		provider.New(version),
		providerserver.ServeOpts{
			Address: "registry.terraform.io/tommycharade/aaisec",
			Debug:   *debug,
		},
	)
	if err != nil {
		log.Fatal(err)
	}
}
