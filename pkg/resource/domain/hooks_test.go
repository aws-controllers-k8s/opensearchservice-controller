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

package domain

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"

	svcapitypes "github.com/aws-controllers-k8s/opensearchservice-controller/apis/v1alpha1"
)

func TestVPCEndpointAccessPrincipal(t *testing.T) {
	tests := []struct {
		name        string
		principal   string
		wantAccount *string
		wantService svcsdktypes.AWSServicePrincipal
	}{
		{
			name:        "twelve digits is an account",
			principal:   "123456789012",
			wantAccount: aws.String("123456789012"),
		},
		{
			name:        "service name is a service principal",
			principal:   "application.opensearchservice.amazonaws.com",
			wantService: "application.opensearchservice.amazonaws.com",
		},
		{
			name:        "eleven digits is not an account",
			principal:   "12345678901",
			wantService: "12345678901",
		},
		{
			name:        "thirteen digits is not an account",
			principal:   "1234567890123",
			wantService: "1234567890123",
		},
		{
			name:        "account ARN is not an account",
			principal:   "arn:aws:iam::123456789012:root",
			wantService: "arn:aws:iam::123456789012:root",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account, service := vpcEndpointAccessPrincipal(test.principal)
			if aws.ToString(account) != aws.ToString(test.wantAccount) {
				t.Errorf("account = %q, want %q", aws.ToString(account), aws.ToString(test.wantAccount))
			}
			if service != test.wantService {
				t.Errorf("service = %q, want %q", service, test.wantService)
			}
		})
	}
}

func TestAuthorizedPrincipalsDiff(t *testing.T) {
	principal := func(name string, regions ...string) *svcapitypes.AuthorizedPrincipal {
		p := &svcapitypes.AuthorizedPrincipal{Principal: aws.String(name)}
		if len(regions) > 0 {
			p.ServiceOptions = &svcapitypes.ServiceOptions{
				SupportedRegions: aws.StringSlice(regions),
			}
		}
		return p
	}

	tests := []struct {
		name        string
		desired     []*svcapitypes.AuthorizedPrincipal
		latest      []*svcapitypes.AuthorizedPrincipal
		wantAdded   []string
		wantRemoved []string
	}{
		{
			name: "both empty",
		},
		{
			name:      "authorize a new principal",
			desired:   []*svcapitypes.AuthorizedPrincipal{principal("123456789012")},
			wantAdded: []string{"123456789012"},
		},
		{
			name:        "revoke an undesired principal",
			latest:      []*svcapitypes.AuthorizedPrincipal{principal("123456789012")},
			wantRemoved: []string{"123456789012"},
		},
		{
			name: "order does not matter",
			desired: []*svcapitypes.AuthorizedPrincipal{
				principal("123456789012"),
				principal("application.opensearchservice.amazonaws.com"),
			},
			latest: []*svcapitypes.AuthorizedPrincipal{
				principal("application.opensearchservice.amazonaws.com"),
				principal("123456789012"),
			},
		},
		{
			name: "duplicate desired entries authorize once",
			desired: []*svcapitypes.AuthorizedPrincipal{
				principal("123456789012"),
				principal("123456789012"),
			},
			wantAdded: []string{"123456789012"},
		},
		{
			name:      "missing supported region re-authorizes",
			desired:   []*svcapitypes.AuthorizedPrincipal{principal("123456789012", "us-east-1", "us-west-2")},
			latest:    []*svcapitypes.AuthorizedPrincipal{principal("123456789012", "us-east-1")},
			wantAdded: []string{"123456789012"},
		},
		{
			name:    "reordered supported regions are equal",
			desired: []*svcapitypes.AuthorizedPrincipal{principal("123456789012", "us-west-2", "us-east-1")},
			latest:  []*svcapitypes.AuthorizedPrincipal{principal("123456789012", "us-east-1", "us-west-2")},
		},
		{
			name:    "unset service options never re-authorize",
			desired: []*svcapitypes.AuthorizedPrincipal{principal("123456789012")},
			latest:  []*svcapitypes.AuthorizedPrincipal{principal("123456789012", "us-east-1")},
		},
		{
			name:    "unreported service options never re-authorize",
			desired: []*svcapitypes.AuthorizedPrincipal{principal("123456789012", "us-east-1")},
			latest:  []*svcapitypes.AuthorizedPrincipal{principal("123456789012")},
		},
		{
			name:    "wider observed regions never re-authorize",
			desired: []*svcapitypes.AuthorizedPrincipal{principal("123456789012", "us-east-1")},
			latest:  []*svcapitypes.AuthorizedPrincipal{principal("123456789012", "us-east-1", "us-west-2")},
		},
		{
			name:        "empty desired revokes everything",
			desired:     []*svcapitypes.AuthorizedPrincipal{},
			latest:      []*svcapitypes.AuthorizedPrincipal{principal("123456789012")},
			wantRemoved: []string{"123456789012"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			added, removed := authorizedPrincipalsDiff(test.desired, test.latest)
			assertPrincipals(t, "added", added, test.wantAdded)
			assertPrincipals(t, "removed", removed, test.wantRemoved)
		})
	}
}

func TestSupportedRegionsMissing(t *testing.T) {
	options := func(regions ...string) *svcapitypes.ServiceOptions {
		return &svcapitypes.ServiceOptions{SupportedRegions: aws.StringSlice(regions)}
	}

	tests := []struct {
		name     string
		desired  *svcapitypes.ServiceOptions
		observed *svcapitypes.ServiceOptions
		want     bool
	}{
		{
			name: "both unset",
		},
		{
			name:     "desired unset, AWS supplied regions",
			observed: options("us-east-1"),
		},
		{
			name:    "desired set, AWS reported nothing",
			desired: options("us-east-1"),
		},
		{
			name:     "desired set, AWS reported empty list",
			desired:  options("us-east-1"),
			observed: options(),
		},
		{
			name:     "identical regions",
			desired:  options("us-east-1", "us-west-2"),
			observed: options("us-east-1", "us-west-2"),
		},
		{
			name:     "same regions in a different order",
			desired:  options("us-west-2", "us-east-1"),
			observed: options("us-east-1", "us-west-2"),
		},
		{
			name:     "AWS reported a wider set",
			desired:  options("us-east-1"),
			observed: options("us-east-1", "us-west-2", "eu-west-1"),
		},
		{
			name:     "duplicates in the spec",
			desired:  options("us-east-1", "us-east-1"),
			observed: options("us-east-1"),
		},
		{
			name:     "empty region strings are ignored",
			desired:  options("us-east-1", ""),
			observed: options("us-east-1"),
		},
		{
			name:     "a desired region is not authorized",
			desired:  options("us-east-1", "us-west-2"),
			observed: options("us-east-1"),
			want:     true,
		},
		{
			name:     "no desired region is authorized",
			desired:  options("eu-west-1"),
			observed: options("us-east-1"),
			want:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := supportedRegionsMissing(test.desired, test.observed); got != test.want {
				t.Errorf("supportedRegionsMissing() = %v, want %v", got, test.want)
			}
		})
	}
}

func assertPrincipals(t *testing.T, label string, got []*svcapitypes.AuthorizedPrincipal, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", label, principalNames(got), want)
	}
	for i := range want {
		if aws.ToString(got[i].Principal) != want[i] {
			t.Errorf("%s = %v, want %v", label, principalNames(got), want)
			return
		}
	}
}

func principalNames(principals []*svcapitypes.AuthorizedPrincipal) []string {
	names := make([]string, 0, len(principals))
	for _, p := range principals {
		names = append(names, aws.ToString(p.Principal))
	}
	return names
}
