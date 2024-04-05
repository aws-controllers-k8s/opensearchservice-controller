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
	"context"
	"errors"
	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackrtlog "github.com/aws-controllers-k8s/runtime/pkg/runtime/log"

	ackrequeue "github.com/aws-controllers-k8s/runtime/pkg/requeue"
)

var (
	requeueWaitWhileProcessing = ackrequeue.NeededAfter(
		errors.New("domain is currently processing changes, cannot be modified or deleted."),
		ackrequeue.DefaultRequeueAfterDuration,
	)
)

// domainProcessing returns true if the supplied domain is in a state of
// processing
func domainProcessing(r *resource) bool {
	if r.ko.Status.Processing == nil {
		return false
	}
	return *r.ko.Status.Processing
}

func (rm *resourceManager) customUpdateDomain(ctx context.Context, desired, latest *resource,
	delta *ackcompare.Delta) (updated *resource, err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.customUpdateDomain")
	defer exit(err)

	// Default `updated` to `desired` because it is likely
	// EC2 `modify` APIs do NOT return output, only errors.
	// If the `modify` calls (i.e. `sync`) do NOT return
	// an error, then the update was successful and desired.Spec
	// (now updated.Spec) reflects the latest resource state.
	updated = rm.concreteResource(desired.DeepCopy())

	return updated, nil
}
