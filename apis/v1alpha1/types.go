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

// Code generated by ack-generate. DO NOT EDIT.

package v1alpha1

import (
	ackv1alpha1 "github.com/aws-controllers-k8s/runtime/apis/core/v1alpha1"
	"github.com/aws/aws-sdk-go/aws"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Hack to avoid import errors during build...
var (
	_ = &metav1.Time{}
	_ = &aws.JSONValue{}
	_ = ackv1alpha1.AWSAccountID("")
)

type AWSDomainInformation struct {
	// The name of an domain. Domain names are unique across the domains owned by
	// an account within an AWS region. Domain names start with a letter or number
	// and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).
	DomainName *string `json:"domainName,omitempty"`
}

// The configured access rules for the domain's document and search endpoints,
// and the current status of those rules.
type AccessPoliciesStatus struct {
	// Access policy rules for a domain service endpoints. For more information,
	// see Configuring access policies (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html#createdomain-configure-access-policies).
	// The maximum size of a policy document is 100 KB.
	Options *string `json:"options,omitempty"`
}

// Status of the advanced options for the specified domain. Currently, the following
// advanced options are available:
//
//   - Option to allow references to indices in an HTTP request body. Must
//     be false when configuring access to individual sub-resources. By default,
//     the value is true. See Advanced cluster parameters for more information.
//
//   - Option to specify the percentage of heap space allocated to field data.
//     By default, this setting is unbounded.
//
// For more information, see Advanced cluster parameters (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html#createdomain-configure-advanced-options).
type AdvancedOptionsStatus struct {
	// Exposes select native OpenSearch configuration values from opensearch.yml.
	// Currently, the following advanced options are available:
	//
	//    * Option to allow references to indices in an HTTP request body. Must
	//    be false when configuring access to individual sub-resources. By default,
	//    the value is true. See Advanced cluster parameters for more information.
	//
	//    * Option to specify the percentage of heap space allocated to field data.
	//    By default, this setting is unbounded.
	//
	// For more information, see Advanced cluster parameters (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html#createdomain-configure-advanced-options).
	Options map[string]*string `json:"options,omitempty"`
}

// The advanced security configuration: whether advanced security is enabled,
// whether the internal database option is enabled.
type AdvancedSecurityOptions struct {
	AnonymousAuthDisableDate    *metav1.Time `json:"anonymousAuthDisableDate,omitempty"`
	AnonymousAuthEnabled        *bool        `json:"anonymousAuthEnabled,omitempty"`
	Enabled                     *bool        `json:"enabled,omitempty"`
	InternalUserDatabaseEnabled *bool        `json:"internalUserDatabaseEnabled,omitempty"`
	// Describes the SAML application configured for the domain.
	SAMLOptions *SAMLOptionsOutput `json:"sAMLOptions,omitempty"`
}

// The advanced security configuration: whether advanced security is enabled,
// whether the internal database option is enabled, master username and password
// (if internal database is enabled), and master user ARN (if IAM is enabled).
type AdvancedSecurityOptionsInput struct {
	AnonymousAuthEnabled        *bool `json:"anonymousAuthEnabled,omitempty"`
	Enabled                     *bool `json:"enabled,omitempty"`
	InternalUserDatabaseEnabled *bool `json:"internalUserDatabaseEnabled,omitempty"`
	// Credentials for the master user: username and password, ARN, or both.
	MasterUserOptions *MasterUserOptions `json:"masterUserOptions,omitempty"`
	// The SAML application configuration for the domain.
	SAMLOptions *SAMLOptionsInput `json:"sAMLOptions,omitempty"`
}

// The status of advanced security options for the specified domain.
type AdvancedSecurityOptionsStatus struct {
	// The advanced security configuration: whether advanced security is enabled,
	// whether the internal database option is enabled.
	Options *AdvancedSecurityOptions `json:"options,omitempty"`
}

// Specifies the Auto-Tune maintenance schedule. See Auto-Tune for Amazon OpenSearch
// Service (https://docs.aws.amazon.com/opensearch-service/latest/developerguide/auto-tune.html)
// for more information.
type AutoTuneMaintenanceSchedule struct {
	CronExpressionForRecurrence *string `json:"cronExpressionForRecurrence,omitempty"`
	// The maintenance schedule duration: duration value and duration unit. See
	// Auto-Tune for Amazon OpenSearch Service (https://docs.aws.amazon.com/opensearch-service/latest/developerguide/auto-tune.html)
	// for more information.
	Duration *Duration    `json:"duration,omitempty"`
	StartAt  *metav1.Time `json:"startAt,omitempty"`
}

// The Auto-Tune options: the Auto-Tune desired state for the domain, rollback
// state when disabling Auto-Tune options and list of maintenance schedules.
type AutoTuneOptions struct {
	// The Auto-Tune desired state. Valid values are ENABLED and DISABLED.
	DesiredState         *string                        `json:"desiredState,omitempty"`
	MaintenanceSchedules []*AutoTuneMaintenanceSchedule `json:"maintenanceSchedules,omitempty"`
}

// The Auto-Tune options: the Auto-Tune desired state for the domain and list
// of maintenance schedules.
type AutoTuneOptionsInput struct {
	// The Auto-Tune desired state. Valid values are ENABLED and DISABLED.
	DesiredState         *string                        `json:"desiredState,omitempty"`
	MaintenanceSchedules []*AutoTuneMaintenanceSchedule `json:"maintenanceSchedules,omitempty"`
}

// The Auto-Tune options: the Auto-Tune desired state for the domain and list
// of maintenance schedules.
type AutoTuneOptionsOutput struct {
	ErrorMessage *string `json:"errorMessage,omitempty"`
	// The Auto-Tune state for the domain. For valid states see Auto-Tune for Amazon
	// OpenSearch Service (https://docs.aws.amazon.com/opensearch-service/latest/developerguide/auto-tune.html).
	State *string `json:"state,omitempty"`
}

// Provides the current Auto-Tune status for the domain.
type AutoTuneStatus struct {
	ErrorMessage    *string `json:"errorMessage,omitempty"`
	PendingDeletion *bool   `json:"pendingDeletion,omitempty"`
	// The Auto-Tune state for the domain. For valid states see Auto-Tune for Amazon
	// OpenSearch Service (https://docs.aws.amazon.com/opensearch-service/latest/developerguide/auto-tune.html).
	State *string `json:"state,omitempty"`
}

// Specifies change details of the domain configuration change.
type ChangeProgressDetails struct {
	ChangeID *string `json:"changeID,omitempty"`
	Message  *string `json:"message,omitempty"`
}

// The progress details of a specific domain configuration change.
type ChangeProgressStatusDetails struct {
	ChangeID            *string   `json:"changeID,omitempty"`
	CompletedProperties []*string `json:"completedProperties,omitempty"`
	PendingProperties   []*string `json:"pendingProperties,omitempty"`
}

// The configuration for the domain cluster, such as the type and number of
// instances.
type ClusterConfig struct {
	// Specifies the configuration for cold storage options such as enabled
	ColdStorageOptions     *ColdStorageOptions `json:"coldStorageOptions,omitempty"`
	DedicatedMasterCount   *int64              `json:"dedicatedMasterCount,omitempty"`
	DedicatedMasterEnabled *bool               `json:"dedicatedMasterEnabled,omitempty"`
	DedicatedMasterType    *string             `json:"dedicatedMasterType,omitempty"`
	InstanceCount          *int64              `json:"instanceCount,omitempty"`
	InstanceType           *string             `json:"instanceType,omitempty"`
	WarmCount              *int64              `json:"warmCount,omitempty"`
	WarmEnabled            *bool               `json:"warmEnabled,omitempty"`
	WarmType               *string             `json:"warmType,omitempty"`
	// The zone awareness configuration for the domain cluster, such as the number
	// of availability zones.
	ZoneAwarenessConfig  *ZoneAwarenessConfig `json:"zoneAwarenessConfig,omitempty"`
	ZoneAwarenessEnabled *bool                `json:"zoneAwarenessEnabled,omitempty"`
}

// The configuration status for the specified domain.
type ClusterConfigStatus struct {
	// The configuration for the domain cluster, such as the type and number of
	// instances.
	Options *ClusterConfig `json:"options,omitempty"`
}

// Options to specify the Cognito user and identity pools for OpenSearch Dashboards
// authentication. For more information, see Configuring Amazon Cognito authentication
// for OpenSearch Dashboards (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/cognito-auth.html).
type CognitoOptions struct {
	Enabled        *bool   `json:"enabled,omitempty"`
	IdentityPoolID *string `json:"identityPoolID,omitempty"`
	RoleARN        *string `json:"roleARN,omitempty"`
	UserPoolID     *string `json:"userPoolID,omitempty"`
}

// The status of the Cognito options for the specified domain.
type CognitoOptionsStatus struct {
	// Options to specify the Cognito user and identity pools for OpenSearch Dashboards
	// authentication. For more information, see Configuring Amazon Cognito authentication
	// for OpenSearch Dashboards (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/cognito-auth.html).
	Options *CognitoOptions `json:"options,omitempty"`
}

// Specifies the configuration for cold storage options such as enabled
type ColdStorageOptions struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// A map from an EngineVersion to a list of compatible EngineVersion s to which
// the domain can be upgraded.
type CompatibleVersionsMap struct {
	SourceVersion *string `json:"sourceVersion,omitempty"`
}

// The configuration of a domain.
type DomainConfig struct {
	// Specifies change details of the domain configuration change.
	ChangeProgressDetails *ChangeProgressDetails `json:"changeProgressDetails,omitempty"`
}

// Options to configure the endpoint for the domain.
type DomainEndpointOptions struct {
	CustomEndpoint *string `json:"customEndpoint,omitempty"`
	// The Amazon Resource Name (ARN) of the domain. See Identifiers for IAM Entities
	// (http://docs.aws.amazon.com/IAM/latest/UserGuide/index.html) in Using AWS
	// Identity and Access Management for more information.
	CustomEndpointCertificateARN *string `json:"customEndpointCertificateARN,omitempty"`
	CustomEndpointEnabled        *bool   `json:"customEndpointEnabled,omitempty"`
	EnforceHTTPS                 *bool   `json:"enforceHTTPS,omitempty"`
	TLSSecurityPolicy            *string `json:"tlsSecurityPolicy,omitempty"`
}

// The configured endpoint options for the domain and their current status.
type DomainEndpointOptionsStatus struct {
	// Options to configure the endpoint for the domain.
	Options *DomainEndpointOptions `json:"options,omitempty"`
}

type DomainInfo struct {
	// The name of an domain. Domain names are unique across the domains owned by
	// an account within an AWS region. Domain names start with a letter or number
	// and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).
	DomainName *string `json:"domainName,omitempty"`
}

// Information on a package associated with a domain.
type DomainPackageDetails struct {
	// The name of an domain. Domain names are unique across the domains owned by
	// an account within an AWS region. Domain names start with a letter or number
	// and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).
	DomainName *string `json:"domainName,omitempty"`
}

// The current status of a domain.
type DomainStatus_SDK struct {
	// The Amazon Resource Name (ARN) of the domain. See Identifiers for IAM Entities
	// (http://docs.aws.amazon.com/IAM/latest/UserGuide/index.html) in Using AWS
	// Identity and Access Management for more information.
	ARN *string `json:"arn,omitempty"`
	// Access policy rules for a domain service endpoints. For more information,
	// see Configuring access policies (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html#createdomain-configure-access-policies).
	// The maximum size of a policy document is 100 KB.
	AccessPolicies *string `json:"accessPolicies,omitempty"`
	// Exposes select native OpenSearch configuration values from opensearch.yml.
	// Currently, the following advanced options are available:
	//
	//    * Option to allow references to indices in an HTTP request body. Must
	//    be false when configuring access to individual sub-resources. By default,
	//    the value is true. See Advanced cluster parameters for more information.
	//
	//    * Option to specify the percentage of heap space allocated to field data.
	//    By default, this setting is unbounded.
	//
	// For more information, see Advanced cluster parameters (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html#createdomain-configure-advanced-options).
	AdvancedOptions map[string]*string `json:"advancedOptions,omitempty"`
	// The advanced security configuration: whether advanced security is enabled,
	// whether the internal database option is enabled.
	AdvancedSecurityOptions *AdvancedSecurityOptions `json:"advancedSecurityOptions,omitempty"`
	// The Auto-Tune options: the Auto-Tune desired state for the domain and list
	// of maintenance schedules.
	AutoTuneOptions *AutoTuneOptionsOutput `json:"autoTuneOptions,omitempty"`
	// Specifies change details of the domain configuration change.
	ChangeProgressDetails *ChangeProgressDetails `json:"changeProgressDetails,omitempty"`
	// The configuration for the domain cluster, such as the type and number of
	// instances.
	ClusterConfig *ClusterConfig `json:"clusterConfig,omitempty"`
	// Options to specify the Cognito user and identity pools for OpenSearch Dashboards
	// authentication. For more information, see Configuring Amazon Cognito authentication
	// for OpenSearch Dashboards (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/cognito-auth.html).
	CognitoOptions *CognitoOptions `json:"cognitoOptions,omitempty"`
	Created        *bool           `json:"created,omitempty"`
	Deleted        *bool           `json:"deleted,omitempty"`
	// Options to configure the endpoint for the domain.
	DomainEndpointOptions *DomainEndpointOptions `json:"domainEndpointOptions,omitempty"`
	// Unique identifier for the domain.
	DomainID *string `json:"domainID,omitempty"`
	// The name of an domain. Domain names are unique across the domains owned by
	// an account within an AWS region. Domain names start with a letter or number
	// and can contain the following characters: a-z (lowercase), 0-9, and - (hyphen).
	DomainName *string `json:"domainName,omitempty"`
	// Options to enable, disable, and specify the properties of EBS storage volumes.
	EBSOptions *EBSOptions `json:"ebsOptions,omitempty"`
	// Specifies encryption at rest options.
	EncryptionAtRestOptions *EncryptionAtRestOptions `json:"encryptionAtRestOptions,omitempty"`
	// The endpoint to which service requests are submitted. For example, search-imdb-movies-oopcnjfn6ugofer3zx5iadxxca.eu-west-1.es.amazonaws.com
	// or doc-imdb-movies-oopcnjfn6ugofer3zx5iadxxca.eu-west-1.es.amazonaws.com.
	Endpoint             *string                         `json:"endpoint,omitempty"`
	Endpoints            map[string]*string              `json:"endpoints,omitempty"`
	EngineVersion        *string                         `json:"engineVersion,omitempty"`
	LogPublishingOptions map[string]*LogPublishingOption `json:"logPublishingOptions,omitempty"`
	// The node-to-node encryption options.
	NodeToNodeEncryptionOptions *NodeToNodeEncryptionOptions `json:"nodeToNodeEncryptionOptions,omitempty"`
	Processing                  *bool                        `json:"processing,omitempty"`
	// The current options of an domain service software options.
	ServiceSoftwareOptions *ServiceSoftwareOptions `json:"serviceSoftwareOptions,omitempty"`
	// The time, in UTC format, when the service takes a daily automated snapshot
	// of the specified domain. Default is 0 hours.
	SnapshotOptions   *SnapshotOptions `json:"snapshotOptions,omitempty"`
	UpgradeProcessing *bool            `json:"upgradeProcessing,omitempty"`
	// Options to specify the subnets and security groups for the VPC endpoint.
	// For more information, see Launching your Amazon OpenSearch Service domains
	// using a VPC (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html).
	VPCOptions *VPCDerivedInfo `json:"vpcOptions,omitempty"`
}

type DryRunResults struct {
	Message *string `json:"message,omitempty"`
}

// The maintenance schedule duration: duration value and duration unit. See
// Auto-Tune for Amazon OpenSearch Service (https://docs.aws.amazon.com/opensearch-service/latest/developerguide/auto-tune.html)
// for more information.
type Duration struct {
	// The unit of a maintenance schedule duration. Valid value is HOUR. See Auto-Tune
	// for Amazon OpenSearch Service (https://docs.aws.amazon.com/opensearch-service/latest/developerguide/auto-tune.html)
	// for more information.
	Unit *string `json:"unit,omitempty"`
	// Integer to specify the value of a maintenance schedule duration. See Auto-Tune
	// for Amazon OpenSearch Service (https://docs.aws.amazon.com/opensearch-service/latest/developerguide/auto-tune.html)
	// for more information.
	Value *int64 `json:"value,omitempty"`
}

// Options to enable, disable, and specify the properties of EBS storage volumes.
type EBSOptions struct {
	EBSEnabled *bool  `json:"ebsEnabled,omitempty"`
	IOPS       *int64 `json:"iops,omitempty"`
	Throughput *int64 `json:"throughput,omitempty"`
	VolumeSize *int64 `json:"volumeSize,omitempty"`
	// The type of EBS volume, standard, gp2, gp3 or io1. See Configuring EBS-based
	// Storage (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/opensearch-createupdatedomains.html#opensearch-createdomain-configure-ebs)
	// for more information.
	VolumeType *string `json:"volumeType,omitempty"`
}

// Status of the EBS options for the specified domain.
type EBSOptionsStatus struct {
	// Options to enable, disable, and specify the properties of EBS storage volumes.
	Options *EBSOptions `json:"options,omitempty"`
}

// Specifies encryption at rest options.
type EncryptionAtRestOptions struct {
	Enabled  *bool   `json:"enabled,omitempty"`
	KMSKeyID *string `json:"kmsKeyID,omitempty"`
}

// Status of the encryption At Rest options for the specified domain.
type EncryptionAtRestOptionsStatus struct {
	// Specifies encryption at rest options.
	Options *EncryptionAtRestOptions `json:"options,omitempty"`
}

type InstanceTypeDetails struct {
	AdvancedSecurityEnabled *bool   `json:"advancedSecurityEnabled,omitempty"`
	AppLogsEnabled          *bool   `json:"appLogsEnabled,omitempty"`
	CognitoEnabled          *bool   `json:"cognitoEnabled,omitempty"`
	EncryptionEnabled       *bool   `json:"encryptionEnabled,omitempty"`
	InstanceType            *string `json:"instanceType,omitempty"`
	WarmEnabled             *bool   `json:"warmEnabled,omitempty"`
}

// Log Publishing option that is set for a given domain. Attributes and their
// details:
//
//   - CloudWatchLogsLogGroupArn: ARN of the Cloudwatch log group to publish
//     logs to.
//
//   - Enabled: Whether the log publishing for a given log type is enabled
//     or not.
type LogPublishingOption struct {
	// ARN of the Cloudwatch log group to publish logs to.
	CloudWatchLogsLogGroupARN *string `json:"cloudWatchLogsLogGroupARN,omitempty"`
	Enabled                   *bool   `json:"enabled,omitempty"`
}

// The configured log publishing options for the domain and their current status.
type LogPublishingOptionsStatus struct {
	Options map[string]*LogPublishingOption `json:"options,omitempty"`
}

// Credentials for the master user: username and password, ARN, or both.
type MasterUserOptions struct {
	// The Amazon Resource Name (ARN) of the domain. See Identifiers for IAM Entities
	// (http://docs.aws.amazon.com/IAM/latest/UserGuide/index.html) in Using AWS
	// Identity and Access Management for more information.
	MasterUserARN      *string                         `json:"masterUserARN,omitempty"`
	MasterUserName     *string                         `json:"masterUserName,omitempty"`
	MasterUserPassword *ackv1alpha1.SecretKeyReference `json:"masterUserPassword,omitempty"`
}

// The node-to-node encryption options.
type NodeToNodeEncryptionOptions struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// Status of the node-to-node encryption options for the specified domain.
type NodeToNodeEncryptionOptionsStatus struct {
	// The node-to-node encryption options.
	Options *NodeToNodeEncryptionOptions `json:"options,omitempty"`
}

// Provides the current status of the entity.
type OptionStatus struct {
	PendingDeletion *bool `json:"pendingDeletion,omitempty"`
}

// Contains the specific price and frequency of a recurring charges for a reserved
// OpenSearch instance, or for a reserved OpenSearch instance offering.
type RecurringCharge struct {
	RecurringChargeFrequency *string `json:"recurringChargeFrequency,omitempty"`
}

// Details of a reserved OpenSearch instance.
type ReservedInstance struct {
	CurrencyCode               *string `json:"currencyCode,omitempty"`
	InstanceType               *string `json:"instanceType,omitempty"`
	ReservedInstanceID         *string `json:"reservedInstanceID,omitempty"`
	ReservedInstanceOfferingID *string `json:"reservedInstanceOfferingID,omitempty"`
	State                      *string `json:"state,omitempty"`
}

// Details of a reserved OpenSearch instance offering.
type ReservedInstanceOffering struct {
	CurrencyCode               *string `json:"currencyCode,omitempty"`
	InstanceType               *string `json:"instanceType,omitempty"`
	ReservedInstanceOfferingID *string `json:"reservedInstanceOfferingID,omitempty"`
}

// The SAML identity povider's information.
type SAMLIDp struct {
	EntityID        *string `json:"entityID,omitempty"`
	MetadataContent *string `json:"metadataContent,omitempty"`
}

// The SAML application configuration for the domain.
type SAMLOptionsInput struct {
	Enabled *bool `json:"enabled,omitempty"`
	// The SAML identity povider's information.
	IDp                   *SAMLIDp `json:"idp,omitempty"`
	MasterBackendRole     *string  `json:"masterBackendRole,omitempty"`
	MasterUserName        *string  `json:"masterUserName,omitempty"`
	RolesKey              *string  `json:"rolesKey,omitempty"`
	SessionTimeoutMinutes *int64   `json:"sessionTimeoutMinutes,omitempty"`
	SubjectKey            *string  `json:"subjectKey,omitempty"`
}

// Describes the SAML application configured for the domain.
type SAMLOptionsOutput struct {
	Enabled *bool `json:"enabled,omitempty"`
	// The SAML identity povider's information.
	IDp                   *SAMLIDp `json:"idp,omitempty"`
	RolesKey              *string  `json:"rolesKey,omitempty"`
	SessionTimeoutMinutes *int64   `json:"sessionTimeoutMinutes,omitempty"`
	SubjectKey            *string  `json:"subjectKey,omitempty"`
}

// The current options of an domain service software options.
type ServiceSoftwareOptions struct {
	AutomatedUpdateDate *metav1.Time `json:"automatedUpdateDate,omitempty"`
	Cancellable         *bool        `json:"cancellable,omitempty"`
	CurrentVersion      *string      `json:"currentVersion,omitempty"`
	Description         *string      `json:"description,omitempty"`
	NewVersion          *string      `json:"newVersion,omitempty"`
	OptionalDeployment  *bool        `json:"optionalDeployment,omitempty"`
	UpdateAvailable     *bool        `json:"updateAvailable,omitempty"`
	UpdateStatus        *string      `json:"updateStatus,omitempty"`
}

// The time, in UTC format, when the service takes a daily automated snapshot
// of the specified domain. Default is 0 hours.
type SnapshotOptions struct {
	AutomatedSnapshotStartHour *int64 `json:"automatedSnapshotStartHour,omitempty"`
}

// Status of a daily automated snapshot.
type SnapshotOptionsStatus struct {
	// The time, in UTC format, when the service takes a daily automated snapshot
	// of the specified domain. Default is 0 hours.
	Options *SnapshotOptions `json:"options,omitempty"`
}

// A key value pair for a resource tag.
type Tag struct {
	// A string of length from 1 to 128 characters that specifies the key for a
	// tag. Tag keys must be unique for the domain to which they're attached.
	Key *string `json:"key,omitempty"`
	// A string of length from 0 to 256 characters that specifies the value for
	// a tag. Tag values can be null and don't have to be unique in a tag set.
	Value *string `json:"value,omitempty"`
}

// Options to specify the subnets and security groups for the VPC endpoint.
// For more information, see Launching your Amazon OpenSearch Service domains
// using a VPC (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html).
type VPCDerivedInfo struct {
	AvailabilityZones []*string `json:"availabilityZones,omitempty"`
	SecurityGroupIDs  []*string `json:"securityGroupIDs,omitempty"`
	SubnetIDs         []*string `json:"subnetIDs,omitempty"`
	VPCID             *string   `json:"vpcID,omitempty"`
}

// Status of the VPC options for the specified domain.
type VPCDerivedInfoStatus struct {
	// Options to specify the subnets and security groups for the VPC endpoint.
	// For more information, see Launching your Amazon OpenSearch Service domains
	// using a VPC (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html).
	Options *VPCDerivedInfo `json:"options,omitempty"`
}

// Options to specify the subnets and security groups for the VPC endpoint.
// For more information, see Launching your Amazon OpenSearch Service domains
// using a VPC (http://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html).
type VPCOptions struct {
	SecurityGroupIDs []*string `json:"securityGroupIDs,omitempty"`
	SubnetIDs        []*string `json:"subnetIDs,omitempty"`
}

// The status of the OpenSearch version options for the specified OpenSearch
// domain.
type VersionStatus struct {
	Options *string `json:"options,omitempty"`
}

// The zone awareness configuration for the domain cluster, such as the number
// of availability zones.
type ZoneAwarenessConfig struct {
	AvailabilityZoneCount *int64 `json:"availabilityZoneCount,omitempty"`
}
