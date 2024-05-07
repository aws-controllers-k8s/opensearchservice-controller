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
	"github.com/aws-controllers-k8s/opensearchservice-controller/apis/v1alpha1"
	ackv1alpha1 "github.com/aws-controllers-k8s/runtime/apis/core/v1alpha1"
	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackcondition "github.com/aws-controllers-k8s/runtime/pkg/condition"
	ackrequeue "github.com/aws-controllers-k8s/runtime/pkg/requeue"
	ackrtlog "github.com/aws-controllers-k8s/runtime/pkg/runtime/log"
	"github.com/aws/aws-sdk-go/aws"
	svcsdk "github.com/aws/aws-sdk-go/service/opensearchservice"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	if domainProcessing(latest) {
		msg := "Domain is currently processing configuration changes"
		ackcondition.SetSynced(desired, corev1.ConditionFalse, &msg, nil)
		return desired, requeueWaitWhileProcessing
	}
	if latest.ko.Status.UpgradeProcessing != nil && *latest.ko.Status.UpgradeProcessing == true {
		msg := "Domain is currently upgrading software"
		ackcondition.SetSynced(desired, corev1.ConditionFalse, &msg, nil)
		return desired, requeueWaitWhileProcessing
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
		resp, err := rm.sdkapi.UpgradeDomainWithContext(ctx, &svcsdk.UpgradeDomainInput{
			AdvancedOptions:  advancedOptions,
			DomainName:       latest.ko.Spec.Name,
			PerformCheckOnly: nil,
			TargetVersion:    desired.ko.Spec.EngineVersion,
		})
		rm.metrics.RecordAPICall("UPGRADE", "UpgradeDomain", err)
		if err != nil {
			return nil, err
		}

		ko := desired.ko.DeepCopy()
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
		return nil, err
	}

	resp, err := rm.sdkapi.UpdateDomainConfigWithContext(ctx, input)
	rm.metrics.RecordAPICall("UPDATE", "UpdateDomainConfig", err)
	if err != nil {
		return nil, err
	}

	// Merge in the information we read from the API call above to the copy of
	// the original Kubernetes object we passed to the function
	ko := desired.ko.DeepCopy()

	if ko.Status.ACKResourceMetadata == nil {
		ko.Status.ACKResourceMetadata = &ackv1alpha1.ResourceMetadata{}
	}

	if resp.DomainConfig.ChangeProgressDetails != nil {
		ko.Status.ChangeProgressDetails = &v1alpha1.ChangeProgressDetails{
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
		ko.Spec.AdvancedOptions = resp.DomainConfig.AdvancedOptions.Options
	} else {
		ko.Spec.AdvancedOptions = nil
	}
	if resp.DomainConfig.AdvancedSecurityOptions != nil && resp.DomainConfig.AdvancedSecurityOptions.Options != nil {
		var samlOptions *v1alpha1.SAMLOptionsInput
		if resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions != nil {
			samlOptions = &v1alpha1.SAMLOptionsInput{
				Enabled:               resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.Enabled,
				RolesKey:              resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.RolesKey,
				SessionTimeoutMinutes: resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.SessionTimeoutMinutes,
				SubjectKey:            resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.SubjectKey,
			}
			if resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.Idp != nil {
				samlOptions.IDp = &v1alpha1.SAMLIDp{
					EntityID:        resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.Idp.EntityId,
					MetadataContent: resp.DomainConfig.AdvancedSecurityOptions.Options.SAMLOptions.Idp.MetadataContent,
				}
			}
		}
		ko.Spec.AdvancedSecurityOptions = &v1alpha1.AdvancedSecurityOptionsInput{
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
		maintSchedules := make([]*v1alpha1.AutoTuneMaintenanceSchedule, len(respMaintSchedules))
		for i, sched := range respMaintSchedules {
			maintSchedules[i] = &v1alpha1.AutoTuneMaintenanceSchedule{
				CronExpressionForRecurrence: sched.CronExpressionForRecurrence,
				Duration: &v1alpha1.Duration{
					Unit:  sched.Duration.Unit,
					Value: sched.Duration.Value,
				},
			}
			if sched.StartAt != nil {
				maintSchedules[i].StartAt = &v1.Time{Time: *sched.StartAt}
			}
		}
		ko.Spec.AutoTuneOptions = &v1alpha1.AutoTuneOptionsInput{
			DesiredState:         resp.DomainConfig.AutoTuneOptions.Options.DesiredState,
			MaintenanceSchedules: maintSchedules,
		}
	} else {
		ko.Spec.AutoTuneOptions = nil
	}
	if resp.DomainConfig.ClusterConfig != nil && resp.DomainConfig.ClusterConfig.Options != nil {
		var csOptions *v1alpha1.ColdStorageOptions
		if resp.DomainConfig.ClusterConfig.Options.ColdStorageOptions != nil {
			csOptions = &v1alpha1.ColdStorageOptions{
				Enabled: resp.DomainConfig.ClusterConfig.Options.ColdStorageOptions.Enabled,
			}
		}
		var zaConfig *v1alpha1.ZoneAwarenessConfig
		if resp.DomainConfig.ClusterConfig.Options.ZoneAwarenessConfig != nil {
			zaConfig = &v1alpha1.ZoneAwarenessConfig{
				AvailabilityZoneCount: resp.DomainConfig.ClusterConfig.Options.ZoneAwarenessConfig.AvailabilityZoneCount,
			}
		}
		ko.Spec.ClusterConfig = &v1alpha1.ClusterConfig{
			ColdStorageOptions:     csOptions,
			DedicatedMasterCount:   resp.DomainConfig.ClusterConfig.Options.DedicatedMasterCount,
			DedicatedMasterEnabled: resp.DomainConfig.ClusterConfig.Options.DedicatedMasterEnabled,
			DedicatedMasterType:    resp.DomainConfig.ClusterConfig.Options.DedicatedMasterType,
			InstanceCount:          resp.DomainConfig.ClusterConfig.Options.InstanceCount,
			InstanceType:           resp.DomainConfig.ClusterConfig.Options.InstanceType,
			WarmCount:              resp.DomainConfig.ClusterConfig.Options.WarmCount,
			WarmEnabled:            resp.DomainConfig.ClusterConfig.Options.WarmEnabled,
			WarmType:               resp.DomainConfig.ClusterConfig.Options.WarmType,
			ZoneAwarenessConfig:    zaConfig,
			ZoneAwarenessEnabled:   resp.DomainConfig.ClusterConfig.Options.ZoneAwarenessEnabled,
		}
	} else {
		ko.Spec.ClusterConfig = nil
	}
	if resp.DomainConfig.CognitoOptions != nil && resp.DomainConfig.CognitoOptions.Options != nil {
		ko.Spec.CognitoOptions = &v1alpha1.CognitoOptions{
			Enabled:        resp.DomainConfig.CognitoOptions.Options.Enabled,
			IdentityPoolID: resp.DomainConfig.CognitoOptions.Options.IdentityPoolId,
			RoleARN:        resp.DomainConfig.CognitoOptions.Options.RoleArn,
			UserPoolID:     resp.DomainConfig.CognitoOptions.Options.UserPoolId,
		}
	} else {
		ko.Spec.CognitoOptions = nil
	}
	if resp.DomainConfig.DomainEndpointOptions != nil {
		ko.Spec.DomainEndpointOptions = &v1alpha1.DomainEndpointOptions{
			CustomEndpoint:               resp.DomainConfig.DomainEndpointOptions.Options.CustomEndpoint,
			CustomEndpointCertificateARN: resp.DomainConfig.DomainEndpointOptions.Options.CustomEndpointCertificateArn,
			CustomEndpointEnabled:        resp.DomainConfig.DomainEndpointOptions.Options.CustomEndpointEnabled,
			EnforceHTTPS:                 resp.DomainConfig.DomainEndpointOptions.Options.EnforceHTTPS,
			TLSSecurityPolicy:            resp.DomainConfig.DomainEndpointOptions.Options.TLSSecurityPolicy,
		}
	} else {
		ko.Spec.DomainEndpointOptions = nil
	}
	if resp.DomainConfig.EBSOptions != nil {
		ko.Spec.EBSOptions = &v1alpha1.EBSOptions{
			EBSEnabled: resp.DomainConfig.EBSOptions.Options.EBSEnabled,
			IOPS:       resp.DomainConfig.EBSOptions.Options.Iops,
			Throughput: resp.DomainConfig.EBSOptions.Options.Throughput,
			VolumeSize: resp.DomainConfig.EBSOptions.Options.VolumeSize,
			VolumeType: resp.DomainConfig.EBSOptions.Options.VolumeType,
		}
	} else {
		ko.Spec.EBSOptions = nil
	}
	if resp.DomainConfig.EncryptionAtRestOptions != nil {
		ko.Spec.EncryptionAtRestOptions = &v1alpha1.EncryptionAtRestOptions{
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
	if resp.DomainConfig.NodeToNodeEncryptionOptions != nil {
		ko.Spec.NodeToNodeEncryptionOptions = &v1alpha1.NodeToNodeEncryptionOptions{
			Enabled: resp.DomainConfig.NodeToNodeEncryptionOptions.Options.Enabled,
		}
	} else {
		ko.Spec.NodeToNodeEncryptionOptions = nil
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
		res.SetAccessPolicies(*desired.ko.Spec.AccessPolicies)
	}

	if desired.ko.Spec.AdvancedOptions != nil && delta.DifferentAt("Spec.AdvancedOptions") {
		res.SetAdvancedOptions(desired.ko.Spec.AdvancedOptions)
	}

	if desired.ko.Spec.AdvancedSecurityOptions != nil && delta.DifferentAt("Spec.AdvancedSecurityOptions") {
		f2 := &svcsdk.AdvancedSecurityOptionsInput_{}
		if desired.ko.Spec.AdvancedSecurityOptions.AnonymousAuthEnabled != nil {
			f2.SetAnonymousAuthEnabled(*desired.ko.Spec.AdvancedSecurityOptions.AnonymousAuthEnabled)
		}
		if desired.ko.Spec.AdvancedSecurityOptions.Enabled != nil {
			f2.SetEnabled(*desired.ko.Spec.AdvancedSecurityOptions.Enabled)
		}
		if desired.ko.Spec.AdvancedSecurityOptions.InternalUserDatabaseEnabled != nil {
			f2.SetInternalUserDatabaseEnabled(*desired.ko.Spec.AdvancedSecurityOptions.InternalUserDatabaseEnabled)
		}
		if desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions != nil {
			f2f3 := &svcsdk.MasterUserOptions{}
			if desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions.MasterUserARN != nil {
				f2f3.SetMasterUserARN(*desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions.MasterUserARN)
			}
			if desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions.MasterUserName != nil {
				f2f3.SetMasterUserName(*desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions.MasterUserName)
			}
			if desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions.MasterUserPassword != nil {
				tmpSecret, err := rm.rr.SecretValueFromReference(ctx, desired.ko.Spec.AdvancedSecurityOptions.MasterUserOptions.MasterUserPassword)
				if err != nil {
					return nil, ackrequeue.Needed(err)
				}
				if tmpSecret != "" {
					f2f3.SetMasterUserPassword(tmpSecret)
				}
			}
			f2.SetMasterUserOptions(f2f3)
		}
		if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions != nil {
			f2f4 := &svcsdk.SAMLOptionsInput_{}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.Enabled != nil {
				f2f4.SetEnabled(*desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.Enabled)
			}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.IDp != nil {
				f2f4f1 := &svcsdk.SAMLIdp{}
				if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.IDp.EntityID != nil {
					f2f4f1.SetEntityId(*desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.IDp.EntityID)
				}
				if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.IDp.MetadataContent != nil {
					f2f4f1.SetMetadataContent(*desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.IDp.MetadataContent)
				}
				f2f4.SetIdp(f2f4f1)
			}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.MasterBackendRole != nil {
				f2f4.SetMasterBackendRole(*desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.MasterBackendRole)
			}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.MasterUserName != nil {
				f2f4.SetMasterUserName(*desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.MasterUserName)
			}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.RolesKey != nil {
				f2f4.SetRolesKey(*desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.RolesKey)
			}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.SessionTimeoutMinutes != nil {
				f2f4.SetSessionTimeoutMinutes(*desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.SessionTimeoutMinutes)
			}
			if desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.SubjectKey != nil {
				f2f4.SetSubjectKey(*desired.ko.Spec.AdvancedSecurityOptions.SAMLOptions.SubjectKey)
			}
			f2.SetSAMLOptions(f2f4)
		}
		res.SetAdvancedSecurityOptions(f2)
	}
	if desired.ko.Spec.AutoTuneOptions != nil && delta.DifferentAt("Spec.AutoTuneOptions") {
		f3 := &svcsdk.AutoTuneOptions{}
		if desired.ko.Spec.AutoTuneOptions.DesiredState != nil {
			f3.SetDesiredState(*desired.ko.Spec.AutoTuneOptions.DesiredState)
		}
		if desired.ko.Spec.AutoTuneOptions.MaintenanceSchedules != nil {
			f3f1 := []*svcsdk.AutoTuneMaintenanceSchedule{}
			for _, f3f1iter := range desired.ko.Spec.AutoTuneOptions.MaintenanceSchedules {
				f3f1elem := &svcsdk.AutoTuneMaintenanceSchedule{}
				if f3f1iter.CronExpressionForRecurrence != nil {
					f3f1elem.SetCronExpressionForRecurrence(*f3f1iter.CronExpressionForRecurrence)
				}
				if f3f1iter.Duration != nil {
					f3f1elemf1 := &svcsdk.Duration{}
					if f3f1iter.Duration.Unit != nil {
						f3f1elemf1.SetUnit(*f3f1iter.Duration.Unit)
					}
					if f3f1iter.Duration.Value != nil {
						f3f1elemf1.SetValue(*f3f1iter.Duration.Value)
					}
					f3f1elem.SetDuration(f3f1elemf1)
				}
				if f3f1iter.StartAt != nil {
					f3f1elem.SetStartAt(f3f1iter.StartAt.Time)
				}
				f3f1 = append(f3f1, f3f1elem)
			}
			f3.SetMaintenanceSchedules(f3f1)
		}
		res.SetAutoTuneOptions(f3)
	}

	if desired.ko.Spec.ClusterConfig != nil && delta.DifferentAt("Spec.ClusterConfig") {
		f4 := &svcsdk.ClusterConfig{}
		if desired.ko.Spec.ClusterConfig.ColdStorageOptions != nil {
			f4f0 := &svcsdk.ColdStorageOptions{}
			if desired.ko.Spec.ClusterConfig.ColdStorageOptions.Enabled != nil {
				f4f0.SetEnabled(*desired.ko.Spec.ClusterConfig.ColdStorageOptions.Enabled)
			}
			f4.SetColdStorageOptions(f4f0)
		}
		if desired.ko.Spec.ClusterConfig.DedicatedMasterCount != nil {
			f4.SetDedicatedMasterCount(*desired.ko.Spec.ClusterConfig.DedicatedMasterCount)
		}
		if desired.ko.Spec.ClusterConfig.DedicatedMasterEnabled != nil {
			f4.SetDedicatedMasterEnabled(*desired.ko.Spec.ClusterConfig.DedicatedMasterEnabled)
		}
		if desired.ko.Spec.ClusterConfig.DedicatedMasterType != nil {
			f4.SetDedicatedMasterType(*desired.ko.Spec.ClusterConfig.DedicatedMasterType)
		}
		if desired.ko.Spec.ClusterConfig.InstanceCount != nil {
			f4.SetInstanceCount(*desired.ko.Spec.ClusterConfig.InstanceCount)
		}
		if desired.ko.Spec.ClusterConfig.InstanceType != nil {
			f4.SetInstanceType(*desired.ko.Spec.ClusterConfig.InstanceType)
		}
		if desired.ko.Spec.ClusterConfig.WarmCount != nil {
			f4.SetWarmCount(*desired.ko.Spec.ClusterConfig.WarmCount)
		}
		if desired.ko.Spec.ClusterConfig.WarmEnabled != nil {
			f4.SetWarmEnabled(*desired.ko.Spec.ClusterConfig.WarmEnabled)
		}
		if desired.ko.Spec.ClusterConfig.WarmType != nil {
			f4.SetWarmType(*desired.ko.Spec.ClusterConfig.WarmType)
		}
		if desired.ko.Spec.ClusterConfig.ZoneAwarenessConfig != nil {
			f4f9 := &svcsdk.ZoneAwarenessConfig{}
			if desired.ko.Spec.ClusterConfig.ZoneAwarenessConfig.AvailabilityZoneCount != nil {
				f4f9.SetAvailabilityZoneCount(*desired.ko.Spec.ClusterConfig.ZoneAwarenessConfig.AvailabilityZoneCount)
			}
			f4.SetZoneAwarenessConfig(f4f9)
		}
		if desired.ko.Spec.ClusterConfig.ZoneAwarenessEnabled != nil {
			f4.SetZoneAwarenessEnabled(*desired.ko.Spec.ClusterConfig.ZoneAwarenessEnabled)
		}
		res.SetClusterConfig(f4)
	}

	if desired.ko.Spec.CognitoOptions != nil && delta.DifferentAt("Spec.CognitoOptions") {
		f5 := &svcsdk.CognitoOptions{}
		if desired.ko.Spec.CognitoOptions.Enabled != nil {
			f5.SetEnabled(*desired.ko.Spec.CognitoOptions.Enabled)
		}
		if desired.ko.Spec.CognitoOptions.IdentityPoolID != nil {
			f5.SetIdentityPoolId(*desired.ko.Spec.CognitoOptions.IdentityPoolID)
		}
		if desired.ko.Spec.CognitoOptions.RoleARN != nil {
			f5.SetRoleArn(*desired.ko.Spec.CognitoOptions.RoleARN)
		}
		if desired.ko.Spec.CognitoOptions.UserPoolID != nil {
			f5.SetUserPoolId(*desired.ko.Spec.CognitoOptions.UserPoolID)
		}
		res.SetCognitoOptions(f5)
	}

	if desired.ko.Spec.DomainEndpointOptions != nil && delta.DifferentAt("Spec.DomainEndpointOptions") {
		f6 := &svcsdk.DomainEndpointOptions{}
		if desired.ko.Spec.DomainEndpointOptions.CustomEndpoint != nil {
			f6.SetCustomEndpoint(*desired.ko.Spec.DomainEndpointOptions.CustomEndpoint)
		}
		if desired.ko.Spec.DomainEndpointOptions.CustomEndpointCertificateARN != nil {
			f6.SetCustomEndpointCertificateArn(*desired.ko.Spec.DomainEndpointOptions.CustomEndpointCertificateARN)
		}
		if desired.ko.Spec.DomainEndpointOptions.CustomEndpointEnabled != nil {
			f6.SetCustomEndpointEnabled(*desired.ko.Spec.DomainEndpointOptions.CustomEndpointEnabled)
		}
		if desired.ko.Spec.DomainEndpointOptions.EnforceHTTPS != nil {
			f6.SetEnforceHTTPS(*desired.ko.Spec.DomainEndpointOptions.EnforceHTTPS)
		}
		if desired.ko.Spec.DomainEndpointOptions.TLSSecurityPolicy != nil {
			f6.SetTLSSecurityPolicy(*desired.ko.Spec.DomainEndpointOptions.TLSSecurityPolicy)
		}
		res.SetDomainEndpointOptions(f6)
	}

	if desired.ko.Spec.EBSOptions != nil && delta.DifferentAt("Spec.EBSOptions") {
		f8 := &svcsdk.EBSOptions{}
		if desired.ko.Spec.EBSOptions.EBSEnabled != nil {
			f8.SetEBSEnabled(*desired.ko.Spec.EBSOptions.EBSEnabled)
		}
		if desired.ko.Spec.EBSOptions.IOPS != nil {
			f8.SetIops(*desired.ko.Spec.EBSOptions.IOPS)
		}
		if desired.ko.Spec.EBSOptions.Throughput != nil {
			f8.SetThroughput(*desired.ko.Spec.EBSOptions.Throughput)
		}
		if desired.ko.Spec.EBSOptions.VolumeSize != nil {
			f8.SetVolumeSize(*desired.ko.Spec.EBSOptions.VolumeSize)
		}
		if desired.ko.Spec.EBSOptions.VolumeType != nil {
			f8.SetVolumeType(*desired.ko.Spec.EBSOptions.VolumeType)
		}
		res.SetEBSOptions(f8)
	}

	if desired.ko.Spec.EncryptionAtRestOptions != nil && delta.DifferentAt("Spec.EncryptionAtRestOptions") {
		f9 := &svcsdk.EncryptionAtRestOptions{}
		if desired.ko.Spec.EncryptionAtRestOptions.Enabled != nil {
			f9.SetEnabled(*desired.ko.Spec.EncryptionAtRestOptions.Enabled)
		}
		if desired.ko.Spec.EncryptionAtRestOptions.KMSKeyID != nil {
			f9.SetKmsKeyId(*desired.ko.Spec.EncryptionAtRestOptions.KMSKeyID)
		}
		res.SetEncryptionAtRestOptions(f9)
	}

	if desired.ko.Spec.LogPublishingOptions != nil && delta.DifferentAt("Spec.LogPublishingOptions") {
		f11 := map[string]*svcsdk.LogPublishingOption{}
		for f11key, f11valiter := range desired.ko.Spec.LogPublishingOptions {
			f11val := &svcsdk.LogPublishingOption{}
			if f11valiter.CloudWatchLogsLogGroupARN != nil {
				f11val.SetCloudWatchLogsLogGroupArn(*f11valiter.CloudWatchLogsLogGroupARN)
			}
			if f11valiter.Enabled != nil {
				f11val.SetEnabled(*f11valiter.Enabled)
			}
			f11[f11key] = f11val
		}
		res.SetLogPublishingOptions(f11)
	}

	if desired.ko.Spec.NodeToNodeEncryptionOptions != nil && delta.DifferentAt("Spec.NodeToNodeEncryptionOptions") {
		f12 := &svcsdk.NodeToNodeEncryptionOptions{}
		if desired.ko.Spec.NodeToNodeEncryptionOptions.Enabled != nil {
			f12.SetEnabled(*desired.ko.Spec.NodeToNodeEncryptionOptions.Enabled)
		}
		res.SetNodeToNodeEncryptionOptions(f12)
	}

	if desired.ko.Spec.VPCOptions != nil && delta.DifferentAt("Spec.VPCOptions") {
		f14 := &svcsdk.VPCOptions{}
		if desired.ko.Spec.VPCOptions.SecurityGroupIDs != nil {
			f14f0 := []*string{}
			for _, f14f0iter := range desired.ko.Spec.VPCOptions.SecurityGroupIDs {
				var f14f0elem string
				f14f0elem = *f14f0iter
				f14f0 = append(f14f0, &f14f0elem)
			}
			f14.SetSecurityGroupIds(f14f0)
		}
		if desired.ko.Spec.VPCOptions.SubnetIDs != nil {
			f14f1 := []*string{}
			for _, f14f1iter := range desired.ko.Spec.VPCOptions.SubnetIDs {
				var f14f1elem string
				f14f1elem = *f14f1iter
				f14f1 = append(f14f1, &f14f1elem)
			}
			f14.SetSubnetIds(f14f1)
		}
		res.SetVPCOptions(f14)
	}

	return res, nil
}
