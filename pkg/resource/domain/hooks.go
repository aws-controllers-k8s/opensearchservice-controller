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
	"fmt"

	ackv1alpha1 "github.com/aws-controllers-k8s/runtime/apis/core/v1alpha1"
	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackcondition "github.com/aws-controllers-k8s/runtime/pkg/condition"
	ackrequeue "github.com/aws-controllers-k8s/runtime/pkg/requeue"
	ackrtlog "github.com/aws-controllers-k8s/runtime/pkg/runtime/log"
	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdk "github.com/aws/aws-sdk-go-v2/service/opensearch"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	svcapitypes "github.com/aws-controllers-k8s/opensearchservice-controller/apis/v1alpha1"
)

var (
	requeueWaitWhileProcessing = ackrequeue.NeededAfter(
		errors.New("domain is currently processing changes, cannot be modified or deleted"),
		ackrequeue.DefaultRequeueAfterDuration,
	)
)

func customPreCompare(delta *ackcompare.Delta, a *resource, b *resource) {
	if a.ko.Spec.AutoTuneOptions != nil && b.ko.Spec.AutoTuneOptions != nil {
		if len(a.ko.Spec.AutoTuneOptions.MaintenanceSchedules) != len(b.ko.Spec.AutoTuneOptions.MaintenanceSchedules) {
			delta.Add("Spec.AutoTuneOptions.MaintenanceSchedules", a.ko.Spec.AutoTuneOptions.MaintenanceSchedules, b.ko.Spec.AutoTuneOptions.MaintenanceSchedules)
		} else if len(a.ko.Spec.AutoTuneOptions.MaintenanceSchedules) > 0 {
			if !cmp.Equal(a.ko.Spec.AutoTuneOptions.MaintenanceSchedules, b.ko.Spec.AutoTuneOptions.MaintenanceSchedules) {
				delta.Add("Spec.AutoTuneOptions.MaintenanceSchedules", a.ko.Spec.AutoTuneOptions.MaintenanceSchedules, b.ko.Spec.AutoTuneOptions.MaintenanceSchedules)
			}
		}
	}
}

func checkDomainStatus(resp *svcsdk.DescribeDomainOutput, ko *svcapitypes.Domain) {
	if resp.DomainStatus.AutoTuneOptions != nil {
		if ready, err := isAutoTuneOptionReady(string(resp.DomainStatus.AutoTuneOptions.State), resp.DomainStatus.AutoTuneOptions.ErrorMessage); err != nil {
			reason := err.Error()
			ackcondition.SetSynced(&resource{ko}, corev1.ConditionFalse, nil, &reason)
		} else if !ready {
			reason := fmt.Sprintf("waiting for AutotuneOptions to sync. Current state: %s", resp.DomainStatus.AutoTuneOptions.State)
			ackcondition.SetSynced(&resource{ko}, corev1.ConditionFalse, nil, &reason)
		}
		ko.Spec.AutoTuneOptions.DesiredState = aws.String(string(resp.DomainStatus.AutoTuneOptions.State))
	}

	if domainProcessing(&resource{ko}) {
		// Setting resource synced condition to false will trigger a requeue of
		// the resource. No need to return a requeue error here.
		ackcondition.SetSynced(&resource{ko}, corev1.ConditionFalse, nil, nil)
	} else {
		ackcondition.SetSynced(&resource{ko}, corev1.ConditionTrue, nil, nil)
	}
}

// domainProcessing returns true if the supplied domain is in a state of
// processing
func domainProcessing(r *resource) bool {
	if r.ko.Status.Processing == nil {
		return false
	}
	return *r.ko.Status.Processing
}

func isAutoTuneOptionReady(state string, errorMessage *string) (bool, error) {
	switch svcsdktypes.AutoTuneState(state) {
	case svcsdktypes.AutoTuneStateEnabled, svcsdktypes.AutoTuneStateDisabled:
		return true, nil

	case svcsdktypes.AutoTuneStateError:
		if errorMessage != nil {
			return false, fmt.Errorf("error: %s", *errorMessage)
		}
		return false, fmt.Errorf("there is an error when updating AutoTuneOptions")

	default:
		return false, nil
	}
}

func (rm *resourceManager) setAutoTuneOptions(ctx context.Context, res *svcapitypes.Domain) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.setAutoTuneOptions")
	defer func() { exit(err) }()

	resp, err := rm.sdkapi.DescribeDomainConfig(ctx, &svcsdk.DescribeDomainConfigInput{DomainName: res.Spec.Name})
	rm.metrics.RecordAPICall("READ_ONE", "DescribeDomainConfig", err)
	if err != nil {
		return err
	}
	if resp.DomainConfig.AutoTuneOptions != nil {
		respMaintSchedules := resp.DomainConfig.AutoTuneOptions.Options.MaintenanceSchedules
		maintSchedules := make([]*svcapitypes.AutoTuneMaintenanceSchedule, len(respMaintSchedules))
		for i, sched := range respMaintSchedules {
			maintSchedules[i] = &svcapitypes.AutoTuneMaintenanceSchedule{
				CronExpressionForRecurrence: sched.CronExpressionForRecurrence,
				Duration: &svcapitypes.Duration{
					Unit:  aws.String(string(sched.Duration.Unit)),
					Value: sched.Duration.Value,
				},
			}
			if sched.StartAt != nil {
				maintSchedules[i].StartAt = &v1.Time{Time: *sched.StartAt}
			}
		}
		res.Spec.AutoTuneOptions = &svcapitypes.AutoTuneOptionsInput{
			DesiredState:         aws.String(string(resp.DomainConfig.AutoTuneOptions.Options.DesiredState)),
			UseOffPeakWindow:     resp.DomainConfig.AutoTuneOptions.Options.UseOffPeakWindow,
			MaintenanceSchedules: maintSchedules,
		}
	} else {
		res.Spec.AutoTuneOptions = nil
	}

	return nil
}

func (rm *resourceManager) customUpdateDomain(ctx context.Context, desired, latest *resource,
	delta *ackcompare.Delta) (updated *resource, err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.customUpdateDomain")
	defer func() { exit(err) }()

	res := desired.ko.DeepCopy()
	updated = &resource{res}
	updated.SetStatus(latest)

	if latest.ko.Spec.AutoTuneOptions != nil &&
		latest.ko.Spec.AutoTuneOptions.DesiredState != nil {
		if ready, _ := isAutoTuneOptionReady(*latest.ko.Spec.AutoTuneOptions.DesiredState, nil); !ready {
			return updated, ackrequeue.Needed(fmt.Errorf("autoTuneOption is updating"))
		}
	}

	if domainProcessing(latest) {
		msg := "Domain is currently processing configuration changes"
		ackcondition.SetSynced(desired, corev1.ConditionFalse, &msg, nil)
		return updated, requeueWaitWhileProcessing
	}
	if latest.ko.Status.UpgradeProcessing != nil && *latest.ko.Status.UpgradeProcessing {
		msg := "Domain is currently upgrading software"
		ackcondition.SetSynced(desired, corev1.ConditionFalse, &msg, nil)
		return updated, requeueWaitWhileProcessing
	}

	if desired.ko.Spec.EngineVersion != nil && delta.DifferentAt("Spec.EngineVersion") {
		rlog.Debug("EngineVersion difference; will call UpgradeDomain")
		// do a domain upgrade instead of a change to domain config
		// this is the only advanced option supported in the UpgradeDomain api.
		const allowedAdvancedOption = "override_main_response_version"
		var advancedOptions map[string]*string
		if desired.ko.Spec.AdvancedOptions != nil && desired.ko.Spec.AdvancedOptions[allowedAdvancedOption] != nil {
			advancedOptions = make(map[string]*string)
			advancedOptions[allowedAdvancedOption] = desired.ko.Spec.AdvancedOptions[allowedAdvancedOption]
		}
		resp, err := rm.sdkapi.UpgradeDomain(ctx, &svcsdk.UpgradeDomainInput{
			AdvancedOptions:  aws.ToStringMap(advancedOptions),
			DomainName:       latest.ko.Spec.Name,
			PerformCheckOnly: nil,
			TargetVersion:    desired.ko.Spec.EngineVersion,
		})
		rm.metrics.RecordAPICall("UPGRADE", "UpgradeDomain", err)
		if err != nil {
			return nil, err
		}

		ko := desired.ko.DeepCopy()
		ko.Status = *latest.ko.Status.DeepCopy()
		if resp.TargetVersion != nil {
			// not sure that this is the right way to handle the in-progress upgrade
			ko.Status.ServiceSoftwareOptions.UpdateStatus = aws.String("PENDING_UPDATE")
			ko.Status.UpgradeProcessing = aws.Bool(true)
		} else {
			ko.Status.ServiceSoftwareOptions.UpdateStatus = nil
		}

		rm.setStatusDefaults(ko)
		r := &resource{ko}
		// Setting resource synced condition to false will trigger a requeue of
		// the resource. No need to return a requeue error here.
		ackcondition.SetSynced(r, corev1.ConditionFalse, nil, nil)
		return r, nil
	}

	input, err := rm.newCustomUpdateRequestPayload(ctx, desired, latest, delta)
	if err != nil {
		return updated, err
	}

	resp, err := rm.sdkapi.UpdateDomainConfig(ctx, input)
	rm.metrics.RecordAPICall("UPDATE", "UpdateDomainConfig", err)
	if err != nil {
		return updated, err
	}

	// Merge in the information we read from the API call above to the copy of
	// the original Kubernetes object we passed to the function
	ko := desired.ko.DeepCopy()
	ko.Status = *latest.ko.Status.DeepCopy()
	if ko.Status.ACKResourceMetadata == nil {
		ko.Status.ACKResourceMetadata = &ackv1alpha1.ResourceMetadata{}
	}

	if resp.DomainConfig.ChangeProgressDetails != nil {
		ko.Status.ChangeProgressDetails = &svcapitypes.ChangeProgressDetails{
			ChangeID: resp.DomainConfig.ChangeProgressDetails.ChangeId,
			Message:  resp.DomainConfig.ChangeProgressDetails.Message,
		}
	} else {
		ko.Status.ChangeProgressDetails = nil
	}

	if resp.DomainConfig.AccessPolicies != nil {
		ko.Spec.AccessPolicies = resp.DomainConfig.AccessPolicies.Options
	} else {
		ko.Spec.AccessPolicies = nil
	}
	if resp.DomainConfig.AdvancedOptions != nil {
		advancedOptions_ptr_string := make(map[string]*string)
		for k, v := range resp.DomainConfig.AdvancedOptions.Options {
			advancedOptions_ptr_string[k] = &v
		}
		ko.Spec.AdvancedOptions = advancedOptions_ptr_string
	} else {
		ko.Spec.AdvancedOptions = nil
	}
	if resp.DomainConfig.AdvancedSecurityOptions != nil && resp.DomainConfig.AdvancedSecurityOptions.Options != nil {
		var samlOptions *svcapitypes.SAMLOptionsInput
		if resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions != nil {
			var timeoutMinutes *int64
			if resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.SessionTimeoutMinutes != nil {
				timeoutMinutes = aws.Int64(int64(*resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.SessionTimeoutMinutes))
			}
			samlOptions = &svcapitypes.SAMLOptionsInput{
				Enabled:               resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.Enabled,
				RolesKey:              resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.RolesKey,
				SessionTimeoutMinutes: timeoutMinutes,
				SubjectKey:            resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.SubjectKey,
			}
			if resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.Idp != nil {
				samlOptions.IDp = &svcapitypes.SAMLIDp{
					EntityID:        resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.Idp.EntityId,
					MetadataContent: resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.Idp.MetadataContent,
				}
			}
		}
		ko.Spec.AdvancedSecurityOptions = &svcapitypes.AdvancedSecurityOptionsInput{
			AnonymousAuthEnabled:        resp.DomainConfig.AdvancedSecurityOptions.Options.AnonymousAuthEnabled,
			Enabled:                     resp.DomainConfig.AdvancedSecurityOptions.Options.Enabled,
			InternalUserDatabaseEnabled: resp.DomainConfig.AdvancedSecurityOptions.Options.InternalUserDatabaseEnabled,
			SAMLOptions:                 samlOptions,
		}
	} else {
		ko.Spec.AdvancedSecurityOptions = nil
	}
	if resp.DomainConfig.AutoTuneOptions != nil {
		respMaintSchedules := resp.DomainConfig.AutoTuneOptions.Options.MaintenanceSchedules
		maintSchedules := make([]*svcapitypes.AutoTuneMaintenanceSchedule, len(respMaintSchedules))
		for i, sched := range respMaintSchedules {
			maintSchedules[i] = &svcapitypes.AutoTuneMaintenanceSchedule{
				CronExpressionForRecurrence: sched.CronExpressionForRecurrence,
				Duration: &svcapitypes.Duration{
					Unit:  aws.String(string(sched.Duration.Unit)),
					Value: sched.Duration.Value,
				},
			}
			if sched.StartAt != nil {
				maintSchedules[i].StartAt = &v1.Time{Time: *sched.StartAt}
			}
		}
		ko.Spec.AutoTuneOptions = &svcapitypes.AutoTuneOptionsInput{
			DesiredState:         aws.String(string(resp.DomainConfig.AutoTuneOptions.Options.DesiredState)),
			UseOffPeakWindow:     resp.DomainConfig.AutoTuneOptions.Options.UseOffPeakWindow,
			MaintenanceSchedules: maintSchedules,
		}
	} else {
		ko.Spec.AutoTuneOptions = nil
	}
	if resp.DomainConfig.ClusterConfig != nil && resp.DomainConfig.ClusterConfig.Options != nil {
		var csOptions *svcapitypes.ColdStorageOptions
		if resp.DomainConfig.ClusterConfig.Options.ColdStorageOptions != nil {
			csOptions = &svcapitypes.ColdStorageOptions{
				Enabled: resp.DomainConfig.ClusterConfig.Options.ColdStorageOptions.Enabled,
			}
		}
		var zaConfig *svcapitypes.ZoneAwarenessConfig
		if resp.DomainConfig.ClusterConfig.Options.ZoneAwarenessConfig != nil {
			zaConfig = &svcapitypes.ZoneAwarenessConfig{}
			if resp.DomainConfig.ClusterConfig.Options.ZoneAwarenessConfig.AvailabilityZoneCount != nil {
				zaConfig.AvailabilityZoneCount = aws.Int64(int64(*resp.DomainConfig.ClusterConfig.Options.ZoneAwarenessConfig.AvailabilityZoneCount))
			}
		}
		ko.Spec.ClusterConfig = &svcapitypes.ClusterConfig{
			ColdStorageOptions:        csOptions,
			DedicatedMasterCount:      int64OrNil(resp.DomainConfig.ClusterConfig.Options.DedicatedMasterCount),
			DedicatedMasterEnabled:    resp.DomainConfig.ClusterConfig.Options.DedicatedMasterEnabled,
			InstanceCount:             int64OrNil(resp.DomainConfig.ClusterConfig.Options.InstanceCount),
			WarmCount:                 int64OrNil(resp.DomainConfig.ClusterConfig.Options.WarmCount),
			WarmEnabled:               resp.DomainConfig.ClusterConfig.Options.WarmEnabled,
			ZoneAwarenessConfig:       zaConfig,
			ZoneAwarenessEnabled:      resp.DomainConfig.ClusterConfig.Options.ZoneAwarenessEnabled,
			MultiAZWithStandbyEnabled: resp.DomainConfig.ClusterConfig.Options.MultiAZWithStandbyEnabled,
		}
		if resp.DomainConfig.ClusterConfig.Options.DedicatedMasterCount != nil {
			ko.Spec.ClusterConfig.DedicatedMasterCount = aws.Int64(int64(*resp.DomainConfig.ClusterConfig.Options.DedicatedMasterCount))
		}
		if resp.DomainConfig.ClusterConfig.Options.DedicatedMasterType != "" {
			ko.Spec.ClusterConfig.DedicatedMasterType = aws.String(string(resp.DomainConfig.ClusterConfig.Options.DedicatedMasterType))
		}
		if resp.DomainConfig.ClusterConfig.Options.InstanceCount != nil {
			ko.Spec.ClusterConfig.InstanceCount = aws.Int64(int64(*resp.DomainConfig.ClusterConfig.Options.InstanceCount))
		}
		if resp.DomainConfig.ClusterConfig.Options.InstanceType != "" {
			ko.Spec.ClusterConfig.InstanceType = aws.String(string(resp.DomainConfig.ClusterConfig.Options.InstanceType))
		}
		if resp.DomainConfig.ClusterConfig.Options.WarmCount != nil {
			ko.Spec.ClusterConfig.WarmCount = aws.Int64(int64(*resp.DomainConfig.ClusterConfig.Options.WarmCount))
		}
		if resp.DomainConfig.ClusterConfig.Options.WarmType != "" {
			ko.Spec.ClusterConfig.WarmType = aws.String(string(resp.DomainConfig.ClusterConfig.Options.WarmType))
		}
	} else {
		ko.Spec.ClusterConfig = nil
	}
	if resp.DomainConfig.CognitoOptions != nil && resp.DomainConfig.CognitoOptions.Options != nil {
		ko.Spec.CognitoOptions = &svcapitypes.CognitoOptions{
			Enabled:        resp.DomainConfig.CognitoOptions.Options.Enabled,
			IdentityPoolID: resp.DomainConfig.CognitoOptions.Options.IdentityPoolId,
			RoleARN:        resp.DomainConfig.CognitoOptions.Options.RoleArn,
			UserPoolID:     resp.DomainConfig.CognitoOptions.Options.UserPoolId,
		}
	} else {
		ko.Spec.CognitoOptions = nil
	}
	if resp.DomainConfig.DomainEndpointOptions != nil {
		ko.Spec.DomainEndpointOptions = &svcapitypes.DomainEndpointOptions{
			CustomEndpoint:               resp.DomainConfig.DomainEndpointOptions.Options.CustomEndpoint,
			CustomEndpointCertificateARN: resp.DomainConfig.DomainEndpointOptions.Options.CustomEndpointCertificateArn,
			CustomEndpointEnabled:        resp.DomainConfig.DomainEndpointOptions.Options.CustomEndpointEnabled,
			EnforceHTTPS:                 resp.DomainConfig.DomainEndpointOptions.Options.EnforceHTTPS,
			TLSSecurityPolicy:            aws.String(string(resp.DomainConfig.DomainEndpointOptions.Options.TLSSecurityPolicy)),
		}
	} else {
		ko.Spec.DomainEndpointOptions = nil
	}
	if resp.DomainConfig.EBSOptions != nil {
		ko.Spec.EBSOptions = &svcapitypes.EBSOptions{
			EBSEnabled: resp.DomainConfig.EBSOptions.Options.EBSEnabled,
		}
		if resp.DomainConfig.EBSOptions.Options.Iops != nil {
			ko.Spec.EBSOptions.IOPS = aws.Int64(int64(*resp.DomainConfig.EBSOptions.Options.Iops))
		}
		if resp.DomainConfig.EBSOptions.Options.Throughput != nil {
			ko.Spec.EBSOptions.Throughput = aws.Int64(int64(*resp.DomainConfig.EBSOptions.Options.Throughput))
		}
		if resp.DomainConfig.EBSOptions.Options.VolumeSize != nil {
			ko.Spec.EBSOptions.VolumeSize = aws.Int64(int64(*resp.DomainConfig.EBSOptions.Options.VolumeSize))
		}
		if resp.DomainConfig.EBSOptions.Options.VolumeType != "" {
			ko.Spec.EBSOptions.VolumeType = aws.String(string(resp.DomainConfig.EBSOptions.Options.VolumeType))
		}
	} else {
		ko.Spec.EBSOptions = nil
	}
	if resp.DomainConfig.EncryptionAtRestOptions != nil {
		ko.Spec.EncryptionAtRestOptions = &svcapitypes.EncryptionAtRestOptions{
			Enabled:  resp.DomainConfig.EncryptionAtRestOptions.Options.Enabled,
			KMSKeyID: resp.DomainConfig.EncryptionAtRestOptions.Options.KmsKeyId,
		}
	} else {
		ko.Spec.EncryptionAtRestOptions = nil
	}
	if resp.DomainConfig.EngineVersion != nil {
		ko.Spec.EngineVersion = resp.DomainConfig.EngineVersion.Options
	} else {
		ko.Spec.EngineVersion = nil
	}
	if resp.DomainConfig.IPAddressType != nil {
		ko.Spec.IPAddressType = aws.String(string(resp.DomainConfig.IPAddressType.Options))
	} else {
		ko.Spec.IPAddressType = nil
	}
	if resp.DomainConfig.NodeToNodeEncryptionOptions != nil {
		ko.Spec.NodeToNodeEncryptionOptions = &svcapitypes.NodeToNodeEncryptionOptions{
			Enabled: resp.DomainConfig.NodeToNodeEncryptionOptions.Options.Enabled,
		}
	} else {
		ko.Spec.NodeToNodeEncryptionOptions = nil
	}
	if resp.DomainConfig.SoftwareUpdateOptions != nil {
		ko.Spec.SoftwareUpdateOptions = &svcapitypes.SoftwareUpdateOptions{
			AutoSoftwareUpdateEnabled: resp.DomainConfig.SoftwareUpdateOptions.Options.AutoSoftwareUpdateEnabled,
		}
	} else {
		ko.Spec.SoftwareUpdateOptions = nil
	}
	if resp.DomainConfig.AIMLOptions != nil && resp.DomainConfig.AIMLOptions.Options != nil {
		if resp.DomainConfig.AIMLOptions.Options.NaturalLanguageQueryGenerationOptions != nil {
			ko.Spec.AIMLOptions = &svcapitypes.AIMLOptionsInput{
				NATuralLanguageQueryGenerationOptions: &svcapitypes.NATuralLanguageQueryGenerationOptionsInput{
					DesiredState: aws.String(string(resp.DomainConfig.AIMLOptions.Options.NaturalLanguageQueryGenerationOptions.DesiredState)),
				},
			}
		}
	} else {
		ko.Spec.AIMLOptions = nil
	}
	if resp.DomainConfig.OffPeakWindowOptions != nil && resp.DomainConfig.OffPeakWindowOptions.Options != nil {
		var offPeakWindow *svcapitypes.OffPeakWindow
		if resp.DomainConfig.OffPeakWindowOptions.Options.OffPeakWindow != nil {
			offPeakWindow = &svcapitypes.OffPeakWindow{
				WindowStartTime: &svcapitypes.WindowStartTime{
					Hours:   aws.Int64(resp.DomainConfig.OffPeakWindowOptions.Options.OffPeakWindow.WindowStartTime.Hours),
					Minutes: aws.Int64(resp.DomainConfig.OffPeakWindowOptions.Options.OffPeakWindow.WindowStartTime.Minutes),
				},
			}
		}
		ko.Spec.OffPeakWindowOptions = &svcapitypes.OffPeakWindowOptions{
			Enabled:       resp.DomainConfig.OffPeakWindowOptions.Options.Enabled,
			OffPeakWindow: offPeakWindow,
		}
	} else {
		ko.Spec.OffPeakWindowOptions = nil
	}

	rm.setStatusDefaults(ko)

	// When UpdateDomainConfig API is successful, it asynchronously
	// updates the Domain. Requeue to find the current
	// Domain status and set Synced condition accordingly
	r := &resource{ko}
	// Setting resource synced condition to false will trigger a requeue of
	// the resource. No need to return a requeue error here.
	ackcondition.SetSynced(r, corev1.ConditionFalse, nil, nil)
	return r, nil
}

// newCustomUpdateRequestPayload returns an SDK-specific struct for the HTTP
// request payload of the Update API call for the resource. It is different
// from the normal newUpdateRequestsPayload in that in addition to checking for
// nil-ness of the Spec fields, it also checks to see if the delta between
// desired and observed contains a diff for the specific field. This is
// required in order to fix
// https://github.com/aws-controllers-k8s/community/issues/917
func (rm *resourceManager) newCustomUpdateRequestPayload(
	ctx context.Context,
	desired *resource,
	latest *resource,
	delta *ackcompare.Delta,
) (*svcsdk.UpdateDomainConfigInput, error) {
	res := &svcsdk.UpdateDomainConfigInput{DomainName: latest.ko.Spec.Name}

	if desired.ko.Spec.AccessPolicies != nil && delta.DifferentAt("Spec.AccessPolicies") {
		res.AccessPolicies = desired.ko.Spec.AccessPolicies
	}

	if desired.ko.Spec.AdvancedOptions != nil && delta.DifferentAt("Spec.AdvancedOptions") {
		advancedOptions_string := make(map[string]string)
		for k, v := range desired.ko.Spec.AdvancedOptions {
			advancedOptions_string[k] = *v
		}
		res.AdvancedOptions = advancedOptions_string
	}

	if desired.ko.Spec.AdvancedSecurityOptions != nil && delta.DifferentAt("Spec.AdvancedSecurityOptions") {
		f2 := &svcsdktypes.AdvancedSecurityOptionsInput{}
		if desired.ko.Spec.AdvancedSecurityOptions.AnonymousAuthEnabled != nil {
			f2.AnonymousAuthEnabled = desired.ko.Spec.AdvancedSecurityOptions.AnonymousAuthEnabled
		}
		if desired.ko.Spec.AdvancedSecurityOptions.Enabled != nil {
			f2.Enabled = desired.ko.Spec.AdvancedSecurityOptions.Enabled
		}
		if desired.ko.Spec.AdvancedSecurityOptions.InternalUserDatabaseEnabled != nil {
			f2.InternalUserDatabaseEnabled = desired.ko.Spec.AdvancedSecurityOptions.InternalUserDatabaseEnabled
		}
		if desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions != nil {
			f2f3 := &svcsdktypes.MasterUserOptions{}
			if desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions.MasterUserARN != nil {
				f2f3.MasterUserARN = desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions.MasterUserARN
			}
			if desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions.MasterUserName != nil {
				f2f3.MasterUserName = desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions.MasterUserName
			}
			if desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions.MasterUserPassword != nil {
				tmpSecret, err := rm.rr.SecretValueFromReference(ctx, desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions.MasterUserPassword)
				if err != nil {
					return nil, ackrequeue.Needed(err)
				}
				if tmpSecret != "" {
					f2f3.MasterUserPassword = &tmpSecret
				}
			}
			f2.MasterUserOptions = f2f3
		}
		if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions != nil {
			f2f4 := &svcsdktypes.SAMLOptionsInput{}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.Enabled != nil {
				f2f4.Enabled = desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.Enabled
			}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.IDp != nil {
				f2f4f1 := &svcsdktypes.SAMLIdp{}
				if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.IDp.EntityID != nil {
					f2f4f1.EntityId = desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.IDp.EntityID
				}
				if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.IDp.MetadataContent != nil {
					f2f4f1.MetadataContent = desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.IDp.MetadataContent
				}
				f2f4.Idp = f2f4f1
			}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.MasterBackendRole != nil {
				f2f4.MasterBackendRole = desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.MasterBackendRole
			}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.MasterUserName != nil {
				f2f4.MasterUserName = desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.MasterUserName
			}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.RolesKey != nil {
				f2f4.RolesKey = desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.RolesKey
			}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.SessionTimeoutMinutes != nil {
				f2f4.SessionTimeoutMinutes = aws.Int32(int32(*desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.SessionTimeoutMinutes))
			}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.SubjectKey != nil {
				f2f4.SubjectKey = desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.SubjectKey
			}
			f2.SAMLOptions = f2f4
		}
		res.AdvancedSecurityOptions = f2
	}
	if desired.ko.Spec.AutoTuneOptions != nil && delta.DifferentAt("Spec.AutoTuneOptions") {
		f3 := &svcsdktypes.AutoTuneOptions{}
		if desired.ko.Spec.AutoTuneOptions.DesiredState != nil {
			f3.DesiredState = svcsdktypes.AutoTuneDesiredState(*desired.ko.Spec.AutoTuneOptions.DesiredState)
		}
		if desired.ko.Spec.AutoTuneOptions.UseOffPeakWindow != nil {
			f3.UseOffPeakWindow = desired.ko.Spec.AutoTuneOptions.UseOffPeakWindow
		}
		if desired.ko.Spec.AutoTuneOptions.MaintenanceSchedules != nil {
			f3f1 := []svcsdktypes.AutoTuneMaintenanceSchedule{}
			for _, f3f1iter := range desired.ko.Spec.AutoTuneOptions.MaintenanceSchedules {
				f3f1elem := &svcsdktypes.AutoTuneMaintenanceSchedule{}
				if f3f1iter.CronExpressionForRecurrence != nil {
					f3f1elem.CronExpressionForRecurrence = f3f1iter.CronExpressionForRecurrence
				}
				if f3f1iter.Duration != nil {
					f3f1elemf1 := &svcsdktypes.Duration{}
					if f3f1iter.Duration.Unit != nil {
						f3f1elemf1.Unit = svcsdktypes.TimeUnit(*f3f1iter.Duration.Unit)
					}
					if f3f1iter.Duration.Value != nil {
						f3f1elemf1.Value = f3f1iter.Duration.Value
					}
					f3f1elem.Duration = f3f1elemf1
				}
				if f3f1iter.StartAt != nil {
					f3f1elem.StartAt = &f3f1iter.StartAt.Time
				}
				f3f1 = append(f3f1, *f3f1elem)
			}
			f3.MaintenanceSchedules = f3f1
		}
		res.AutoTuneOptions = f3
	}

	if desired.ko.Spec.ClusterConfig != nil && delta.DifferentAt("Spec.ClusterConfig") {
		f4 := &svcsdktypes.ClusterConfig{}
		if desired.ko.Spec.ClusterConfig.ColdStorageOptions != nil {
			f4f0 := &svcsdktypes.ColdStorageOptions{}
			if desired.ko.Spec.ClusterConfig.ColdStorageOptions.Enabled != nil {
				f4f0.Enabled = desired.ko.Spec.ClusterConfig.ColdStorageOptions.Enabled
			}
			f4.ColdStorageOptions = f4f0
		}
		if desired.ko.Spec.ClusterConfig.DedicatedMasterCount != nil {
			f4.DedicatedMasterCount = aws.Int32(int32(*desired.ko.Spec.ClusterConfig.DedicatedMasterCount))
		}
		if desired.ko.Spec.ClusterConfig.DedicatedMasterEnabled != nil {
			f4.DedicatedMasterEnabled = desired.ko.Spec.ClusterConfig.DedicatedMasterEnabled
		}
		if desired.ko.Spec.ClusterConfig.DedicatedMasterType != nil {
			f4.DedicatedMasterType = svcsdktypes.OpenSearchPartitionInstanceType(*desired.ko.Spec.ClusterConfig.DedicatedMasterType)
		}
		if desired.ko.Spec.ClusterConfig.InstanceCount != nil {
			f4.InstanceCount = aws.Int32(int32(*desired.ko.Spec.ClusterConfig.InstanceCount))
		}
		if desired.ko.Spec.ClusterConfig.InstanceType != nil {
			f4.InstanceType = svcsdktypes.OpenSearchPartitionInstanceType(*desired.ko.Spec.ClusterConfig.InstanceType)
		}
		if desired.ko.Spec.ClusterConfig.WarmCount != nil {
			f4.WarmCount = aws.Int32(int32(*desired.ko.Spec.ClusterConfig.WarmCount))
		}
		if desired.ko.Spec.ClusterConfig.WarmEnabled != nil {
			f4.WarmEnabled = desired.ko.Spec.ClusterConfig.WarmEnabled
		}
		if desired.ko.Spec.ClusterConfig.WarmType != nil {
			f4.WarmType = svcsdktypes.OpenSearchWarmPartitionInstanceType(*desired.ko.Spec.ClusterConfig.WarmType)
		}
		if desired.ko.Spec.ClusterConfig.ZoneAwarenessConfig != nil {
			f4f9 := &svcsdktypes.ZoneAwarenessConfig{}
			if desired.ko.Spec.ClusterConfig.ZoneAwarenessConfig.AvailabilityZoneCount != nil {
				f4f9.AvailabilityZoneCount = aws.Int32(int32(*desired.ko.Spec.ClusterConfig.ZoneAwarenessConfig.AvailabilityZoneCount))
			}
			f4.ZoneAwarenessConfig = f4f9
		}
		if desired.ko.Spec.ClusterConfig.ZoneAwarenessEnabled != nil {
			f4.ZoneAwarenessEnabled = desired.ko.Spec.ClusterConfig.ZoneAwarenessEnabled
		}
		if desired.ko.Spec.ClusterConfig.MultiAZWithStandbyEnabled != nil {
			f4.MultiAZWithStandbyEnabled = desired.ko.Spec.ClusterConfig.MultiAZWithStandbyEnabled
		}
		res.ClusterConfig = f4
	}

	if desired.ko.Spec.CognitoOptions != nil && delta.DifferentAt("Spec.CognitoOptions") {
		f5 := &svcsdktypes.CognitoOptions{}
		if desired.ko.Spec.CognitoOptions.Enabled != nil {
			f5.Enabled = desired.ko.Spec.CognitoOptions.Enabled
		}
		if desired.ko.Spec.CognitoOptions.IdentityPoolID != nil {
			f5.IdentityPoolId = desired.ko.Spec.CognitoOptions.IdentityPoolID
		}
		if desired.ko.Spec.CognitoOptions.RoleARN != nil {
			f5.RoleArn = desired.ko.Spec.CognitoOptions.RoleARN
		}
		if desired.ko.Spec.CognitoOptions.UserPoolID != nil {
			f5.UserPoolId = desired.ko.Spec.CognitoOptions.UserPoolID
		}
		res.CognitoOptions = f5
	}

	if desired.ko.Spec.DomainEndpointOptions != nil && delta.DifferentAt("Spec.DomainEndpointOptions") {
		f6 := &svcsdktypes.DomainEndpointOptions{}
		if desired.ko.Spec.DomainEndpointOptions.CustomEndpoint != nil {
			f6.CustomEndpoint = desired.ko.Spec.DomainEndpointOptions.CustomEndpoint
		}
		if desired.ko.Spec.DomainEndpointOptions.CustomEndpointCertificateARN != nil {
			f6.CustomEndpointCertificateArn = desired.ko.Spec.DomainEndpointOptions.CustomEndpointCertificateARN
		}
		if desired.ko.Spec.DomainEndpointOptions.CustomEndpointEnabled != nil {
			f6.CustomEndpointEnabled = desired.ko.Spec.DomainEndpointOptions.CustomEndpointEnabled
		}
		if desired.ko.Spec.DomainEndpointOptions.EnforceHTTPS != nil {
			f6.EnforceHTTPS = desired.ko.Spec.DomainEndpointOptions.EnforceHTTPS
		}
		if desired.ko.Spec.DomainEndpointOptions.TLSSecurityPolicy != nil {
			f6.TLSSecurityPolicy = svcsdktypes.TLSSecurityPolicy(*desired.ko.Spec.DomainEndpointOptions.TLSSecurityPolicy)
		}
		res.DomainEndpointOptions = f6
	}

	if desired.ko.Spec.EBSOptions != nil && delta.DifferentAt("Spec.EBSOptions") {
		f8 := &svcsdktypes.EBSOptions{}
		if desired.ko.Spec.EBSOptions.EBSEnabled != nil {
			f8.EBSEnabled = desired.ko.Spec.EBSOptions.EBSEnabled
		}
		if desired.ko.Spec.EBSOptions.IOPS != nil {
			f8.Iops = aws.Int32(int32(*desired.ko.Spec.EBSOptions.IOPS))
		}
		if desired.ko.Spec.EBSOptions.Throughput != nil {
			f8.Throughput = aws.Int32(int32(*desired.ko.Spec.EBSOptions.Throughput))
		}
		if desired.ko.Spec.EBSOptions.VolumeSize != nil {
			f8.VolumeSize = aws.Int32(int32(*desired.ko.Spec.EBSOptions.VolumeSize))
		}
		if desired.ko.Spec.EBSOptions.VolumeType != nil {
			f8.VolumeType = svcsdktypes.VolumeType(*desired.ko.Spec.EBSOptions.VolumeType)
		}
		res.EBSOptions = f8
	}

	if desired.ko.Spec.EncryptionAtRestOptions != nil && delta.DifferentAt("Spec.EncryptionAtRestOptions") {
		f9 := &svcsdktypes.EncryptionAtRestOptions{}
		if desired.ko.Spec.EncryptionAtRestOptions.Enabled != nil {
			f9.Enabled = desired.ko.Spec.EncryptionAtRestOptions.Enabled
		}
		if desired.ko.Spec.EncryptionAtRestOptions.KMSKeyID != nil {
			f9.KmsKeyId = desired.ko.Spec.EncryptionAtRestOptions.KMSKeyID
		}
		res.EncryptionAtRestOptions = f9
	}

	if desired.ko.Spec.LogPublishingOptions != nil && delta.DifferentAt("Spec.LogPublishingOptions") {
		f11 := map[string]svcsdktypes.LogPublishingOption{}
		for f11key, f11valiter := range desired.ko.Spec.LogPublishingOptions {
			f11val := &svcsdktypes.LogPublishingOption{}
			if f11valiter.CloudWatchLogsLogGroupARN != nil {
				f11val.CloudWatchLogsLogGroupArn = f11valiter.CloudWatchLogsLogGroupARN
			}
			if f11valiter.Enabled != nil {
				f11val.Enabled = f11valiter.Enabled
			}
			f11[f11key] = *f11val
		}
		res.LogPublishingOptions = f11
	}

	if desired.ko.Spec.NodeToNodeEncryptionOptions != nil && delta.DifferentAt("Spec.NodeToNodeEncryptionOptions") {
		f12 := &svcsdktypes.NodeToNodeEncryptionOptions{}
		if desired.ko.Spec.NodeToNodeEncryptionOptions.Enabled != nil {
			f12.Enabled = desired.ko.Spec.NodeToNodeEncryptionOptions.Enabled
		}
		res.NodeToNodeEncryptionOptions = f12
	}

	if desired.ko.Spec.VPCOptions != nil && delta.DifferentAt("Spec.VPCOptions") {
		f14 := &svcsdktypes.VPCOptions{}
		if desired.ko.Spec.VPCOptions.SecurityGroupIDs != nil {
			f14f0 := []string{}
			for _, f14f0iter := range desired.ko.Spec.VPCOptions.SecurityGroupIDs {
				f14f0elem := *f14f0iter
				f14f0 = append(f14f0, f14f0elem)
			}
			f14.SecurityGroupIds = f14f0
		}
		if desired.ko.Spec.VPCOptions.SubnetIDs != nil {
			f14f1 := []string{}
			for _, f14f1iter := range desired.ko.Spec.VPCOptions.SubnetIDs {
				f14f1elem := *f14f1iter
				f14f1 = append(f14f1, f14f1elem)
			}
			f14.SubnetIds = f14f1
		}
		res.VPCOptions = f14
	}

	if desired.ko.Spec.IPAddressType != nil && delta.DifferentAt("Spec.IPAddressType") {
		res.IPAddressType = svcsdktypes.IPAddressType(*desired.ko.Spec.IPAddressType)
	}

	if desired.ko.Spec.SoftwareUpdateOptions != nil && delta.DifferentAt("Spec.SoftwareUpdateOptions") {
		f15 := &svcsdktypes.SoftwareUpdateOptions{}
		if desired.ko.Spec.SoftwareUpdateOptions.AutoSoftwareUpdateEnabled != nil {
			f15.AutoSoftwareUpdateEnabled = desired.ko.Spec.SoftwareUpdateOptions.AutoSoftwareUpdateEnabled
		}
		res.SoftwareUpdateOptions = f15
	}

	if desired.ko.Spec.AIMLOptions != nil && delta.DifferentAt("Spec.AIMLOptions") {
		f16 := &svcsdktypes.AIMLOptionsInput{}
		if desired.ko.Spec.AIMLOptions.NATuralLanguageQueryGenerationOptions != nil {
			f16f0 := &svcsdktypes.NaturalLanguageQueryGenerationOptionsInput{}
			if desired.ko.Spec.AIMLOptions.NATuralLanguageQueryGenerationOptions.DesiredState != nil {
				f16f0.DesiredState = svcsdktypes.NaturalLanguageQueryGenerationDesiredState(*desired.ko.Spec.AIMLOptions.NATuralLanguageQueryGenerationOptions.DesiredState)
			}
			f16.NaturalLanguageQueryGenerationOptions = f16f0
		}
		res.AIMLOptions = f16
	}

	if desired.ko.Spec.OffPeakWindowOptions != nil && delta.DifferentAt("Spec.OffPeakWindowOptions") {
		f17 := &svcsdktypes.OffPeakWindowOptions{}
		if desired.ko.Spec.OffPeakWindowOptions.Enabled != nil {
			f17.Enabled = desired.ko.Spec.OffPeakWindowOptions.Enabled
		}
		if desired.ko.Spec.OffPeakWindowOptions.OffPeakWindow != nil {
			f17f1 := &svcsdktypes.OffPeakWindow{}
			if desired.ko.Spec.OffPeakWindowOptions.OffPeakWindow.WindowStartTime != nil {
				f17f1f1 := &svcsdktypes.WindowStartTime{}
				if desired.ko.Spec.OffPeakWindowOptions.OffPeakWindow.WindowStartTime.Hours != nil {
					f17f1f1.Hours = *desired.ko.Spec.OffPeakWindowOptions.OffPeakWindow.WindowStartTime.Hours
				}
				if desired.ko.Spec.OffPeakWindowOptions.OffPeakWindow.WindowStartTime.Minutes != nil {
					f17f1f1.Minutes = *desired.ko.Spec.OffPeakWindowOptions.OffPeakWindow.WindowStartTime.Minutes
				}
				f17f1.WindowStartTime = f17f1f1
			}
			f17.OffPeakWindow = f17f1
		}
		res.OffPeakWindowOptions = f17
	}

	return res, nil
}

func int64OrNil(num *int32) *int64 {
	if num == nil {
		return nil
	}

	return aws.Int64(int64(*num))
}
