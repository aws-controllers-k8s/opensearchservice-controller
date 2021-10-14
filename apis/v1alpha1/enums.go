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

type AutoTuneDesiredState string

const (
	AutoTuneDesiredState_ENABLED  AutoTuneDesiredState = "ENABLED"
	AutoTuneDesiredState_DISABLED AutoTuneDesiredState = "DISABLED"
)

type AutoTuneState string

const (
	AutoTuneState_ENABLED                           AutoTuneState = "ENABLED"
	AutoTuneState_DISABLED                          AutoTuneState = "DISABLED"
	AutoTuneState_ENABLE_IN_PROGRESS                AutoTuneState = "ENABLE_IN_PROGRESS"
	AutoTuneState_DISABLE_IN_PROGRESS               AutoTuneState = "DISABLE_IN_PROGRESS"
	AutoTuneState_DISABLED_AND_ROLLBACK_SCHEDULED   AutoTuneState = "DISABLED_AND_ROLLBACK_SCHEDULED"
	AutoTuneState_DISABLED_AND_ROLLBACK_IN_PROGRESS AutoTuneState = "DISABLED_AND_ROLLBACK_IN_PROGRESS"
	AutoTuneState_DISABLED_AND_ROLLBACK_COMPLETE    AutoTuneState = "DISABLED_AND_ROLLBACK_COMPLETE"
	AutoTuneState_DISABLED_AND_ROLLBACK_ERROR       AutoTuneState = "DISABLED_AND_ROLLBACK_ERROR"
	AutoTuneState_ERROR                             AutoTuneState = "ERROR"
)

type AutoTuneType string

const (
	AutoTuneType_SCHEDULED_ACTION AutoTuneType = "SCHEDULED_ACTION"
)

type DeploymentStatus string

const (
	DeploymentStatus_PENDING_UPDATE DeploymentStatus = "PENDING_UPDATE"
	DeploymentStatus_IN_PROGRESS    DeploymentStatus = "IN_PROGRESS"
	DeploymentStatus_COMPLETED      DeploymentStatus = "COMPLETED"
	DeploymentStatus_NOT_ELIGIBLE   DeploymentStatus = "NOT_ELIGIBLE"
	DeploymentStatus_ELIGIBLE       DeploymentStatus = "ELIGIBLE"
)

type DescribePackagesFilterName string

const (
	DescribePackagesFilterName_PackageID     DescribePackagesFilterName = "PackageID"
	DescribePackagesFilterName_PackageName   DescribePackagesFilterName = "PackageName"
	DescribePackagesFilterName_PackageStatus DescribePackagesFilterName = "PackageStatus"
)

type DomainPackageStatus string

const (
	DomainPackageStatus_ASSOCIATING         DomainPackageStatus = "ASSOCIATING"
	DomainPackageStatus_ASSOCIATION_FAILED  DomainPackageStatus = "ASSOCIATION_FAILED"
	DomainPackageStatus_ACTIVE              DomainPackageStatus = "ACTIVE"
	DomainPackageStatus_DISSOCIATING        DomainPackageStatus = "DISSOCIATING"
	DomainPackageStatus_DISSOCIATION_FAILED DomainPackageStatus = "DISSOCIATION_FAILED"
)

type EngineType string

const (
	EngineType_OpenSearch    EngineType = "OpenSearch"
	EngineType_Elasticsearch EngineType = "Elasticsearch"
)

type InboundConnectionStatusCode string

const (
	InboundConnectionStatusCode_PENDING_ACCEPTANCE InboundConnectionStatusCode = "PENDING_ACCEPTANCE"
	InboundConnectionStatusCode_APPROVED           InboundConnectionStatusCode = "APPROVED"
	InboundConnectionStatusCode_PROVISIONING       InboundConnectionStatusCode = "PROVISIONING"
	InboundConnectionStatusCode_ACTIVE             InboundConnectionStatusCode = "ACTIVE"
	InboundConnectionStatusCode_REJECTING          InboundConnectionStatusCode = "REJECTING"
	InboundConnectionStatusCode_REJECTED           InboundConnectionStatusCode = "REJECTED"
	InboundConnectionStatusCode_DELETING           InboundConnectionStatusCode = "DELETING"
	InboundConnectionStatusCode_DELETED            InboundConnectionStatusCode = "DELETED"
)

type LogType string

const (
	LogType_INDEX_SLOW_LOGS     LogType = "INDEX_SLOW_LOGS"
	LogType_SEARCH_SLOW_LOGS    LogType = "SEARCH_SLOW_LOGS"
	LogType_ES_APPLICATION_LOGS LogType = "ES_APPLICATION_LOGS"
	LogType_AUDIT_LOGS          LogType = "AUDIT_LOGS"
)

type OpenSearchPartitionInstanceType string

const (
	OpenSearchPartitionInstanceType_m3_medium_search         OpenSearchPartitionInstanceType = "m3.medium.search"
	OpenSearchPartitionInstanceType_m3_large_search          OpenSearchPartitionInstanceType = "m3.large.search"
	OpenSearchPartitionInstanceType_m3_xlarge_search         OpenSearchPartitionInstanceType = "m3.xlarge.search"
	OpenSearchPartitionInstanceType_m3_2xlarge_search        OpenSearchPartitionInstanceType = "m3.2xlarge.search"
	OpenSearchPartitionInstanceType_m4_large_search          OpenSearchPartitionInstanceType = "m4.large.search"
	OpenSearchPartitionInstanceType_m4_xlarge_search         OpenSearchPartitionInstanceType = "m4.xlarge.search"
	OpenSearchPartitionInstanceType_m4_2xlarge_search        OpenSearchPartitionInstanceType = "m4.2xlarge.search"
	OpenSearchPartitionInstanceType_m4_4xlarge_search        OpenSearchPartitionInstanceType = "m4.4xlarge.search"
	OpenSearchPartitionInstanceType_m4_10xlarge_search       OpenSearchPartitionInstanceType = "m4.10xlarge.search"
	OpenSearchPartitionInstanceType_m5_large_search          OpenSearchPartitionInstanceType = "m5.large.search"
	OpenSearchPartitionInstanceType_m5_xlarge_search         OpenSearchPartitionInstanceType = "m5.xlarge.search"
	OpenSearchPartitionInstanceType_m5_2xlarge_search        OpenSearchPartitionInstanceType = "m5.2xlarge.search"
	OpenSearchPartitionInstanceType_m5_4xlarge_search        OpenSearchPartitionInstanceType = "m5.4xlarge.search"
	OpenSearchPartitionInstanceType_m5_12xlarge_search       OpenSearchPartitionInstanceType = "m5.12xlarge.search"
	OpenSearchPartitionInstanceType_m5_24xlarge_search       OpenSearchPartitionInstanceType = "m5.24xlarge.search"
	OpenSearchPartitionInstanceType_r5_large_search          OpenSearchPartitionInstanceType = "r5.large.search"
	OpenSearchPartitionInstanceType_r5_xlarge_search         OpenSearchPartitionInstanceType = "r5.xlarge.search"
	OpenSearchPartitionInstanceType_r5_2xlarge_search        OpenSearchPartitionInstanceType = "r5.2xlarge.search"
	OpenSearchPartitionInstanceType_r5_4xlarge_search        OpenSearchPartitionInstanceType = "r5.4xlarge.search"
	OpenSearchPartitionInstanceType_r5_12xlarge_search       OpenSearchPartitionInstanceType = "r5.12xlarge.search"
	OpenSearchPartitionInstanceType_r5_24xlarge_search       OpenSearchPartitionInstanceType = "r5.24xlarge.search"
	OpenSearchPartitionInstanceType_c5_large_search          OpenSearchPartitionInstanceType = "c5.large.search"
	OpenSearchPartitionInstanceType_c5_xlarge_search         OpenSearchPartitionInstanceType = "c5.xlarge.search"
	OpenSearchPartitionInstanceType_c5_2xlarge_search        OpenSearchPartitionInstanceType = "c5.2xlarge.search"
	OpenSearchPartitionInstanceType_c5_4xlarge_search        OpenSearchPartitionInstanceType = "c5.4xlarge.search"
	OpenSearchPartitionInstanceType_c5_9xlarge_search        OpenSearchPartitionInstanceType = "c5.9xlarge.search"
	OpenSearchPartitionInstanceType_c5_18xlarge_search       OpenSearchPartitionInstanceType = "c5.18xlarge.search"
	OpenSearchPartitionInstanceType_t3_nano_search           OpenSearchPartitionInstanceType = "t3.nano.search"
	OpenSearchPartitionInstanceType_t3_micro_search          OpenSearchPartitionInstanceType = "t3.micro.search"
	OpenSearchPartitionInstanceType_t3_small_search          OpenSearchPartitionInstanceType = "t3.small.search"
	OpenSearchPartitionInstanceType_t3_medium_search         OpenSearchPartitionInstanceType = "t3.medium.search"
	OpenSearchPartitionInstanceType_t3_large_search          OpenSearchPartitionInstanceType = "t3.large.search"
	OpenSearchPartitionInstanceType_t3_xlarge_search         OpenSearchPartitionInstanceType = "t3.xlarge.search"
	OpenSearchPartitionInstanceType_t3_2xlarge_search        OpenSearchPartitionInstanceType = "t3.2xlarge.search"
	OpenSearchPartitionInstanceType_ultrawarm1_medium_search OpenSearchPartitionInstanceType = "ultrawarm1.medium.search"
	OpenSearchPartitionInstanceType_ultrawarm1_large_search  OpenSearchPartitionInstanceType = "ultrawarm1.large.search"
	OpenSearchPartitionInstanceType_ultrawarm1_xlarge_search OpenSearchPartitionInstanceType = "ultrawarm1.xlarge.search"
	OpenSearchPartitionInstanceType_t2_micro_search          OpenSearchPartitionInstanceType = "t2.micro.search"
	OpenSearchPartitionInstanceType_t2_small_search          OpenSearchPartitionInstanceType = "t2.small.search"
	OpenSearchPartitionInstanceType_t2_medium_search         OpenSearchPartitionInstanceType = "t2.medium.search"
	OpenSearchPartitionInstanceType_r3_large_search          OpenSearchPartitionInstanceType = "r3.large.search"
	OpenSearchPartitionInstanceType_r3_xlarge_search         OpenSearchPartitionInstanceType = "r3.xlarge.search"
	OpenSearchPartitionInstanceType_r3_2xlarge_search        OpenSearchPartitionInstanceType = "r3.2xlarge.search"
	OpenSearchPartitionInstanceType_r3_4xlarge_search        OpenSearchPartitionInstanceType = "r3.4xlarge.search"
	OpenSearchPartitionInstanceType_r3_8xlarge_search        OpenSearchPartitionInstanceType = "r3.8xlarge.search"
	OpenSearchPartitionInstanceType_i2_xlarge_search         OpenSearchPartitionInstanceType = "i2.xlarge.search"
	OpenSearchPartitionInstanceType_i2_2xlarge_search        OpenSearchPartitionInstanceType = "i2.2xlarge.search"
	OpenSearchPartitionInstanceType_d2_xlarge_search         OpenSearchPartitionInstanceType = "d2.xlarge.search"
	OpenSearchPartitionInstanceType_d2_2xlarge_search        OpenSearchPartitionInstanceType = "d2.2xlarge.search"
	OpenSearchPartitionInstanceType_d2_4xlarge_search        OpenSearchPartitionInstanceType = "d2.4xlarge.search"
	OpenSearchPartitionInstanceType_d2_8xlarge_search        OpenSearchPartitionInstanceType = "d2.8xlarge.search"
	OpenSearchPartitionInstanceType_c4_large_search          OpenSearchPartitionInstanceType = "c4.large.search"
	OpenSearchPartitionInstanceType_c4_xlarge_search         OpenSearchPartitionInstanceType = "c4.xlarge.search"
	OpenSearchPartitionInstanceType_c4_2xlarge_search        OpenSearchPartitionInstanceType = "c4.2xlarge.search"
	OpenSearchPartitionInstanceType_c4_4xlarge_search        OpenSearchPartitionInstanceType = "c4.4xlarge.search"
	OpenSearchPartitionInstanceType_c4_8xlarge_search        OpenSearchPartitionInstanceType = "c4.8xlarge.search"
	OpenSearchPartitionInstanceType_r4_large_search          OpenSearchPartitionInstanceType = "r4.large.search"
	OpenSearchPartitionInstanceType_r4_xlarge_search         OpenSearchPartitionInstanceType = "r4.xlarge.search"
	OpenSearchPartitionInstanceType_r4_2xlarge_search        OpenSearchPartitionInstanceType = "r4.2xlarge.search"
	OpenSearchPartitionInstanceType_r4_4xlarge_search        OpenSearchPartitionInstanceType = "r4.4xlarge.search"
	OpenSearchPartitionInstanceType_r4_8xlarge_search        OpenSearchPartitionInstanceType = "r4.8xlarge.search"
	OpenSearchPartitionInstanceType_r4_16xlarge_search       OpenSearchPartitionInstanceType = "r4.16xlarge.search"
	OpenSearchPartitionInstanceType_i3_large_search          OpenSearchPartitionInstanceType = "i3.large.search"
	OpenSearchPartitionInstanceType_i3_xlarge_search         OpenSearchPartitionInstanceType = "i3.xlarge.search"
	OpenSearchPartitionInstanceType_i3_2xlarge_search        OpenSearchPartitionInstanceType = "i3.2xlarge.search"
	OpenSearchPartitionInstanceType_i3_4xlarge_search        OpenSearchPartitionInstanceType = "i3.4xlarge.search"
	OpenSearchPartitionInstanceType_i3_8xlarge_search        OpenSearchPartitionInstanceType = "i3.8xlarge.search"
	OpenSearchPartitionInstanceType_i3_16xlarge_search       OpenSearchPartitionInstanceType = "i3.16xlarge.search"
	OpenSearchPartitionInstanceType_r6g_large_search         OpenSearchPartitionInstanceType = "r6g.large.search"
	OpenSearchPartitionInstanceType_r6g_xlarge_search        OpenSearchPartitionInstanceType = "r6g.xlarge.search"
	OpenSearchPartitionInstanceType_r6g_2xlarge_search       OpenSearchPartitionInstanceType = "r6g.2xlarge.search"
	OpenSearchPartitionInstanceType_r6g_4xlarge_search       OpenSearchPartitionInstanceType = "r6g.4xlarge.search"
	OpenSearchPartitionInstanceType_r6g_8xlarge_search       OpenSearchPartitionInstanceType = "r6g.8xlarge.search"
	OpenSearchPartitionInstanceType_r6g_12xlarge_search      OpenSearchPartitionInstanceType = "r6g.12xlarge.search"
	OpenSearchPartitionInstanceType_m6g_large_search         OpenSearchPartitionInstanceType = "m6g.large.search"
	OpenSearchPartitionInstanceType_m6g_xlarge_search        OpenSearchPartitionInstanceType = "m6g.xlarge.search"
	OpenSearchPartitionInstanceType_m6g_2xlarge_search       OpenSearchPartitionInstanceType = "m6g.2xlarge.search"
	OpenSearchPartitionInstanceType_m6g_4xlarge_search       OpenSearchPartitionInstanceType = "m6g.4xlarge.search"
	OpenSearchPartitionInstanceType_m6g_8xlarge_search       OpenSearchPartitionInstanceType = "m6g.8xlarge.search"
	OpenSearchPartitionInstanceType_m6g_12xlarge_search      OpenSearchPartitionInstanceType = "m6g.12xlarge.search"
	OpenSearchPartitionInstanceType_c6g_large_search         OpenSearchPartitionInstanceType = "c6g.large.search"
	OpenSearchPartitionInstanceType_c6g_xlarge_search        OpenSearchPartitionInstanceType = "c6g.xlarge.search"
	OpenSearchPartitionInstanceType_c6g_2xlarge_search       OpenSearchPartitionInstanceType = "c6g.2xlarge.search"
	OpenSearchPartitionInstanceType_c6g_4xlarge_search       OpenSearchPartitionInstanceType = "c6g.4xlarge.search"
	OpenSearchPartitionInstanceType_c6g_8xlarge_search       OpenSearchPartitionInstanceType = "c6g.8xlarge.search"
	OpenSearchPartitionInstanceType_c6g_12xlarge_search      OpenSearchPartitionInstanceType = "c6g.12xlarge.search"
	OpenSearchPartitionInstanceType_r6gd_large_search        OpenSearchPartitionInstanceType = "r6gd.large.search"
	OpenSearchPartitionInstanceType_r6gd_xlarge_search       OpenSearchPartitionInstanceType = "r6gd.xlarge.search"
	OpenSearchPartitionInstanceType_r6gd_2xlarge_search      OpenSearchPartitionInstanceType = "r6gd.2xlarge.search"
	OpenSearchPartitionInstanceType_r6gd_4xlarge_search      OpenSearchPartitionInstanceType = "r6gd.4xlarge.search"
	OpenSearchPartitionInstanceType_r6gd_8xlarge_search      OpenSearchPartitionInstanceType = "r6gd.8xlarge.search"
	OpenSearchPartitionInstanceType_r6gd_12xlarge_search     OpenSearchPartitionInstanceType = "r6gd.12xlarge.search"
	OpenSearchPartitionInstanceType_r6gd_16xlarge_search     OpenSearchPartitionInstanceType = "r6gd.16xlarge.search"
	OpenSearchPartitionInstanceType_t4g_small_search         OpenSearchPartitionInstanceType = "t4g.small.search"
	OpenSearchPartitionInstanceType_t4g_medium_search        OpenSearchPartitionInstanceType = "t4g.medium.search"
)

type OpenSearchWarmPartitionInstanceType string

const (
	OpenSearchWarmPartitionInstanceType_ultrawarm1_medium_search OpenSearchWarmPartitionInstanceType = "ultrawarm1.medium.search"
	OpenSearchWarmPartitionInstanceType_ultrawarm1_large_search  OpenSearchWarmPartitionInstanceType = "ultrawarm1.large.search"
	OpenSearchWarmPartitionInstanceType_ultrawarm1_xlarge_search OpenSearchWarmPartitionInstanceType = "ultrawarm1.xlarge.search"
)

type OptionState string

const (
	OptionState_RequiresIndexDocuments OptionState = "RequiresIndexDocuments"
	OptionState_Processing             OptionState = "Processing"
	OptionState_Active                 OptionState = "Active"
)

type OutboundConnectionStatusCode string

const (
	OutboundConnectionStatusCode_VALIDATING         OutboundConnectionStatusCode = "VALIDATING"
	OutboundConnectionStatusCode_VALIDATION_FAILED  OutboundConnectionStatusCode = "VALIDATION_FAILED"
	OutboundConnectionStatusCode_PENDING_ACCEPTANCE OutboundConnectionStatusCode = "PENDING_ACCEPTANCE"
	OutboundConnectionStatusCode_APPROVED           OutboundConnectionStatusCode = "APPROVED"
	OutboundConnectionStatusCode_PROVISIONING       OutboundConnectionStatusCode = "PROVISIONING"
	OutboundConnectionStatusCode_ACTIVE             OutboundConnectionStatusCode = "ACTIVE"
	OutboundConnectionStatusCode_REJECTING          OutboundConnectionStatusCode = "REJECTING"
	OutboundConnectionStatusCode_REJECTED           OutboundConnectionStatusCode = "REJECTED"
	OutboundConnectionStatusCode_DELETING           OutboundConnectionStatusCode = "DELETING"
	OutboundConnectionStatusCode_DELETED            OutboundConnectionStatusCode = "DELETED"
)

type PackageStatus string

const (
	PackageStatus_COPYING           PackageStatus = "COPYING"
	PackageStatus_COPY_FAILED       PackageStatus = "COPY_FAILED"
	PackageStatus_VALIDATING        PackageStatus = "VALIDATING"
	PackageStatus_VALIDATION_FAILED PackageStatus = "VALIDATION_FAILED"
	PackageStatus_AVAILABLE         PackageStatus = "AVAILABLE"
	PackageStatus_DELETING          PackageStatus = "DELETING"
	PackageStatus_DELETED           PackageStatus = "DELETED"
	PackageStatus_DELETE_FAILED     PackageStatus = "DELETE_FAILED"
)

type PackageType string

const (
	PackageType_TXT_DICTIONARY PackageType = "TXT-DICTIONARY"
)

type ReservedInstancePaymentOption string

const (
	ReservedInstancePaymentOption_ALL_UPFRONT     ReservedInstancePaymentOption = "ALL_UPFRONT"
	ReservedInstancePaymentOption_PARTIAL_UPFRONT ReservedInstancePaymentOption = "PARTIAL_UPFRONT"
	ReservedInstancePaymentOption_NO_UPFRONT      ReservedInstancePaymentOption = "NO_UPFRONT"
)

type RollbackOnDisable string

const (
	RollbackOnDisable_NO_ROLLBACK      RollbackOnDisable = "NO_ROLLBACK"
	RollbackOnDisable_DEFAULT_ROLLBACK RollbackOnDisable = "DEFAULT_ROLLBACK"
)

type ScheduledAutoTuneActionType string

const (
	ScheduledAutoTuneActionType_JVM_HEAP_SIZE_TUNING ScheduledAutoTuneActionType = "JVM_HEAP_SIZE_TUNING"
	ScheduledAutoTuneActionType_JVM_YOUNG_GEN_TUNING ScheduledAutoTuneActionType = "JVM_YOUNG_GEN_TUNING"
)

type ScheduledAutoTuneSeverityType string

const (
	ScheduledAutoTuneSeverityType_LOW    ScheduledAutoTuneSeverityType = "LOW"
	ScheduledAutoTuneSeverityType_MEDIUM ScheduledAutoTuneSeverityType = "MEDIUM"
	ScheduledAutoTuneSeverityType_HIGH   ScheduledAutoTuneSeverityType = "HIGH"
)

type TLSSecurityPolicy string

const (
	TLSSecurityPolicy_Policy_Min_TLS_1_0_2019_07 TLSSecurityPolicy = "Policy-Min-TLS-1-0-2019-07"
	TLSSecurityPolicy_Policy_Min_TLS_1_2_2019_07 TLSSecurityPolicy = "Policy-Min-TLS-1-2-2019-07"
)

type TimeUnit string

const (
	TimeUnit_HOURS TimeUnit = "HOURS"
)

type UpgradeStatus string

const (
	UpgradeStatus_IN_PROGRESS           UpgradeStatus = "IN_PROGRESS"
	UpgradeStatus_SUCCEEDED             UpgradeStatus = "SUCCEEDED"
	UpgradeStatus_SUCCEEDED_WITH_ISSUES UpgradeStatus = "SUCCEEDED_WITH_ISSUES"
	UpgradeStatus_FAILED                UpgradeStatus = "FAILED"
)

type UpgradeStep string

const (
	UpgradeStep_PRE_UPGRADE_CHECK UpgradeStep = "PRE_UPGRADE_CHECK"
	UpgradeStep_SNAPSHOT          UpgradeStep = "SNAPSHOT"
	UpgradeStep_UPGRADE           UpgradeStep = "UPGRADE"
)

type VolumeType string

const (
	VolumeType_standard VolumeType = "standard"
	VolumeType_gp2      VolumeType = "gp2"
	VolumeType_io1      VolumeType = "io1"
)
