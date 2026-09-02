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
	"sort"
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
		{
			name:        "empty principal sets neither",
			principal:   "",
			wantService: "",
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

func TestSupportedRegionsDiff(t *testing.T) {
	options := func(regions ...string) *svcapitypes.ServiceOptions {
		return &svcapitypes.ServiceOptions{SupportedRegions: aws.StringSlice(regions)}
	}

	tests := []struct {
		name        string
		desired     *svcapitypes.ServiceOptions
		latest      *svcapitypes.ServiceOptions
		wantAdded   []string
		wantRemoved []string
	}{
		{
			name: "both unset",
		},
		{
			name:      "authorize the first region",
			desired:   options("us-west-2"),
			wantAdded: []string{"us-west-2"},
		},
		{
			name:      "widen the region set",
			desired:   options("us-east-1", "us-west-2"),
			latest:    options("us-west-2"),
			wantAdded: []string{"us-east-1"},
		},
		{
			name:        "narrow the region set",
			desired:     options("us-west-2"),
			latest:      options("us-east-1", "us-west-2"),
			wantRemoved: []string{"us-east-1"},
		},
		{
			name:        "swap regions",
			desired:     options("eu-west-1"),
			latest:      options("us-west-2"),
			wantAdded:   []string{"eu-west-1"},
			wantRemoved: []string{"us-west-2"},
		},
		{
			name:    "same regions in a different order",
			desired: options("us-west-2", "us-east-1"),
			latest:  options("us-east-1", "us-west-2"),
		},
		{
			name:    "duplicates in the spec",
			desired: options("us-west-2", "us-west-2"),
			latest:  options("us-west-2"),
		},
		{
			name:    "empty region strings are ignored",
			desired: options("us-west-2", ""),
			latest:  options("us-west-2"),
		},
		{
			name:        "unset desired removes everything",
			latest:      options("us-west-2"),
			wantRemoved: []string{"us-west-2"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			added, removed := supportedRegionsDiff(test.desired, test.latest)
			sort.Strings(added)
			sort.Strings(removed)
			assertRegions(t, "added", added, test.wantAdded)
			assertRegions(t, "removed", removed, test.wantRemoved)
		})
	}
}

func assertRegions(t *testing.T, label string, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s = %v, want %v", label, got, want)
			return
		}
	}
}

func TestSupportedRegionsDeclared(t *testing.T) {
	tests := []struct {
		name    string
		options *svcapitypes.ServiceOptions
		want    bool
	}{
		{
			name: "no service options",
		},
		{
			name:    "service options without regions",
			options: &svcapitypes.ServiceOptions{},
		},
		{
			name:    "explicitly empty regions",
			options: &svcapitypes.ServiceOptions{SupportedRegions: []*string{}},
			want:    true,
		},
		{
			name:    "regions listed",
			options: &svcapitypes.ServiceOptions{SupportedRegions: aws.StringSlice([]string{"us-west-2"})},
			want:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := supportedRegionsDeclared(test.options); got != test.want {
				t.Errorf("supportedRegionsDeclared() = %v, want %v", got, test.want)
			}
		})
	}
}
