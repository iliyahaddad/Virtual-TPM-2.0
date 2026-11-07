module github.com/vtpm2/service

go 1.23

require (
	github.com/deploymenttheory/go-sdk-vtpm2 v0.0.0
	golang.org/x/sys v0.23.0
)

replace github.com/deploymenttheory/go-sdk-vtpm2 => ../engine
