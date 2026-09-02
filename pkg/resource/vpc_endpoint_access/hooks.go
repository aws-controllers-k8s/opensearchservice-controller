// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package vpc_endpoint_access

import (
	"context"
	"errors"
	"regexp"

	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackerr "github.com/aws-controllers-k8s/runtime/pkg/errors"
	ackrtlog "github.com/aws-controllers-k8s/runtime/pkg/runtime/log"
	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdk "github.com/aws/aws-sdk-go-v2/service/opensearch"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"

	svcapitypes "github.com/aws-controllers-k8s/opensearchservice-controller/apis/v1alpha1"
)

// awsAccountIDRegexp matches a bare 12-digit AWS account ID.
var awsAccountIDRegexp = regexp.MustCompile(`^\d{12}$`)

// vpcEndpointAccessPrincipal returns the principal as an account or a service.
func vpcEndpointAccessPrincipal(
	principal string,
) (account *string, service svcsdktypes.AWSServicePrincipal) {
	if awsAccountIDRegexp.MatchString(principal) {
		return aws.String(principal), ""
	}
	return nil, svcsdktypes.AWSServicePrincipal(principal)
}

func customPreCompare(delta *ackcompare.Delta, a *resource, b *resource) {
	// Regions are late-initialized from the domain's own region when the spec
	// leaves them out, and late initialization runs after the update path.
	if !supportedRegionsDeclared(a.ko.Spec.ServiceOptions) {
		return
	}
	added, removed := supportedRegionsDiff(a.ko.Spec.ServiceOptions, b.ko.Spec.ServiceOptions)
	if len(added) > 0 || len(removed) > 0 {
		delta.Add("Spec.ServiceOptions.SupportedRegions", a.ko.Spec.ServiceOptions, b.ko.Spec.ServiceOptions)
	}
}

// supportedRegionsDeclared reports whether the spec states which regions the
// authorization covers.
func supportedRegionsDeclared(options *svcapitypes.ServiceOptions) bool {
	return options != nil && options.SupportedRegions != nil
}

// supportedRegionsDiff returns the regions to authorize and to revoke, compared
// as sets because ListVpcEndpointAccess does not guarantee ordering.
func supportedRegionsDiff(desired, latest *svcapitypes.ServiceOptions) (added, removed []string) {
	desiredRegions := supportedRegionSet(desired)
	latestRegions := supportedRegionSet(latest)
	for region := range desiredRegions {
		if !latestRegions[region] {
			added = append(added, region)
		}
	}
	for region := range latestRegions {
		if !desiredRegions[region] {
			removed = append(removed, region)
		}
	}
	return added, removed
}

func supportedRegionSet(options *svcapitypes.ServiceOptions) map[string]bool {
	regions := map[string]bool{}
	if options == nil {
		return regions
	}
	for _, r := range options.SupportedRegions {
		if region := aws.ToString(r); region != "" {
			regions[region] = true
		}
	}
	return regions
}

// customUpdate reconciles the authorized regions. AuthorizeVpcEndpointAccess
// merges the regions it is given rather than replacing them, so widening is an
// authorize and narrowing is a revoke of just the dropped regions.
func (rm *resourceManager) customUpdate(
	ctx context.Context,
	desired *resource,
	latest *resource,
	delta *ackcompare.Delta,
) (updated *resource, err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.customUpdate")
	defer func() { exit(err) }()

	if !supportedRegionsDeclared(desired.ko.Spec.ServiceOptions) {
		return desired, nil
	}

	// An authorization always covers at least one region, so revoking them all
	// would delete it out from under this resource.
	if len(supportedRegionSet(desired.ko.Spec.ServiceOptions)) == 0 {
		err = ackerr.NewTerminalError(
			errors.New("an authorization must cover at least one region; delete this resource instead"),
		)
		return nil, err
	}

	added, removed := supportedRegionsDiff(desired.ko.Spec.ServiceOptions, latest.ko.Spec.ServiceOptions)

	if len(added) > 0 {
		if err = rm.setSupportedRegions(ctx, desired, added, true); err != nil {
			return nil, err
		}
	}
	if len(removed) > 0 {
		if err = rm.setSupportedRegions(ctx, desired, removed, false); err != nil {
			return nil, err
		}
	}

	ko := desired.ko.DeepCopy()
	rm.setStatusDefaults(ko)
	return &resource{ko}, nil
}

// setSupportedRegions authorizes or revokes the supplied regions for the
// resource's principal.
func (rm *resourceManager) setSupportedRegions(
	ctx context.Context,
	r *resource,
	regions []string,
	authorize bool,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.setSupportedRegions")
	defer func() { exit(err) }()

	account, service := vpcEndpointAccessPrincipal(aws.ToString(r.ko.Spec.Principal))
	options := &svcsdktypes.ServiceOptions{SupportedRegions: regions}

	if authorize {
		_, err = rm.sdkapi.AuthorizeVpcEndpointAccess(ctx, &svcsdk.AuthorizeVpcEndpointAccessInput{
			DomainName:     r.ko.Spec.DomainName,
			Account:        account,
			Service:        service,
			ServiceOptions: options,
		})
		rm.metrics.RecordAPICall("UPDATE", "AuthorizeVpcEndpointAccess", err)
		return err
	}

	_, err = rm.sdkapi.RevokeVpcEndpointAccess(ctx, &svcsdk.RevokeVpcEndpointAccessInput{
		DomainName:     r.ko.Spec.DomainName,
		Account:        account,
		Service:        service,
		ServiceOptions: options,
	})
	rm.metrics.RecordAPICall("UPDATE", "RevokeVpcEndpointAccess", err)
	return err
}
