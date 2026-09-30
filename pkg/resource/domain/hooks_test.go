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
	"errors"
	"fmt"
	"testing"

	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/smithy-go"
)

func TestIsChangeAlreadyInProgress(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "non-API error",
			err:  errors.New("connection reset"),
			want: false,
		},
		{
			name: "change in progress is transient",
			err: &svcsdktypes.ValidationException{
				Message: awsString("A change/update is in progress. Please wait for it to complete before requesting another change."),
			},
			want: true,
		},
		{
			name: "wrapped change in progress is transient",
			err: fmt.Errorf("operation error OpenSearch: UpdateDomainConfig: %w",
				&svcsdktypes.ValidationException{
					Message: awsString("A change/update is in progress. Please wait for it to complete before requesting another change."),
				}),
			want: true,
		},
		{
			name: "invalid spec stays terminal",
			err: &svcsdktypes.ValidationException{
				Message: awsString("You must choose an even number of data nodes for a two Availability Zone deployment"),
			},
			want: false,
		},
		{
			name: "other API error code is not matched",
			err: &smithy.GenericAPIError{
				Code:    "ResourceNotFoundException",
				Message: "A change/update is in progress",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isChangeAlreadyInProgress(tt.err); got != tt.want {
				t.Errorf("isChangeAlreadyInProgress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func awsString(s string) *string { return &s }
