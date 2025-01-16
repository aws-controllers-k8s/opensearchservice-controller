# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
#	 http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

"""Integration tests for the OpenSearchService API Domain resource
"""

from dataclasses import dataclass, field
import logging
import time
from typing import Dict

from acktest.resources import random_suffix_name
from acktest.k8s import resource as k8s
import pytest

from e2e import condition
from e2e import domain
from e2e import service_marker, CRD_GROUP, CRD_VERSION, load_opensearch_resource
from e2e.replacement_values import REPLACEMENT_VALUES
from e2e.bootstrap_resources import BootstrapResources, get_bootstrap_resources

RESOURCE_PLURAL = 'domains'

DELETE_WAIT_AFTER_SECONDS = 60*2

MODIFY_WAIT_AFTER_SECONDS = 60 * 15

# This is the time to wait *after* the domain returns Processing=False from the
# Opensearch DescribeDomain API call and before we check to see that the CR's
# Status.Conditions contains a True ResourceSynced condition.
CHECK_STATUS_WAIT_SECONDS = 60

# It can take a LONG time for the domain's endpoint/endpoints field to be
# returned, even after Processing=False and the ResourceSynced condition is set
# to True on a domain. Domain resources are requeued on success which means the
# controller will poll for latest status, including endpoint/endpoints, every
# 30 seconds, so 2 minutes *should* be enough here.
CHECK_ENDPOINT_WAIT_SECONDS = 60*2


@dataclass
class Domain:
    name: str
    data_node_count: int
    master_node_count: int = 0
    is_zone_aware: bool = False
    is_vpc: bool = False
    vpc_id: str = None
    vpc_subnets: list = field(default_factory=list)


@pytest.fixture(scope="module")
def resources():
    return get_bootstrap_resources()


@pytest.fixture
def es_7_9_domain(os_client, resources: BootstrapResources):
    resource = Domain(name=random_suffix_name("my-os-domain1", 20), data_node_count=1)
    mup = resources.MasterUserPasswordSecret

    replacements = REPLACEMENT_VALUES.copy()
    replacements["DOMAIN_NAME"] = resource.name
    replacements["MASTER_USER_PASS_SECRET_NAMESPACE"] = mup.ns
    replacements["MASTER_USER_PASS_SECRET_NAME"] = mup.name
    replacements["MASTER_USER_PASS_SECRET_KEY"] = mup.key

    resource_data = load_opensearch_resource(
        "domain_es7.9",
        additional_replacements=replacements,
    )

    # Create the k8s resource
    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, RESOURCE_PLURAL,
        resource.name, namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    k8s.wait_resource_consumed_by_controller(ref)
    condition.assert_not_synced(ref)

    # An OpenSearch Domain gets its `DomainStatus.Created` field set to
    # `True` almost immediately, however the `DomainStatus.Processing` field
    # is set to `True` while OpenSearch is being installed onto the worker
    # node(s). If you attempt to delete a Domain that is both Created and
    # Processing == True, OpenSearchService will set the
    # `DomainStatus.Deleted` field to True as well, so the `Created`,
    # `Processing` and `Deleted` fields will all be True. It typically takes
    # upwards of 4-6 minutes for an ES Domain to reach Created = True &&
    # Processing = False and then another 2 minutes or so after calling
    # DeleteDomain for the OpenSearch Domain to no longer appear in
    # DescribeDomain API call.
    domain.wait_until(ref.name, domain.processing_matches(False))

    logging.info(f"ES Domain {resource.name} creation succeeded and DomainStatus.Processing is now False")

    time.sleep(CHECK_STATUS_WAIT_SECONDS)
    condition.assert_synced(ref)

    yield ref, resource

    # Delete the k8s resource on teardown of the module
    k8s.delete_custom_resource(ref)

    logging.info(f"Deleted CR for OpenSearch Domain {resource.name}. Waiting {DELETE_WAIT_AFTER_SECONDS} before checking existence in AWS API")
    time.sleep(DELETE_WAIT_AFTER_SECONDS)

    # Domain should no longer appear in OpenSearchService
    domain.wait_until_deleted(ref.name)


@pytest.fixture
def es_2d3m_multi_az_no_vpc_7_9_domain(os_client, resources: BootstrapResources):
    resource = Domain(name=random_suffix_name("my-os-domain2", 20), data_node_count=2,master_node_count=3,is_zone_aware=True)
    mup = resources.MasterUserPasswordSecret

    replacements = REPLACEMENT_VALUES.copy()
    replacements["DOMAIN_NAME"] = resource.name
    replacements["MASTER_USER_PASS_SECRET_NAMESPACE"] = mup.ns
    replacements["MASTER_USER_PASS_SECRET_NAME"] = mup.name
    replacements["MASTER_USER_PASS_SECRET_KEY"] = mup.key
    replacements["MASTER_NODE_COUNT"] = str(resource.master_node_count)
    replacements["DATA_NODE_COUNT"] = str(resource.data_node_count)

    resource_data = load_opensearch_resource(
        "domain_es_xdym_multi_az7.9",
        additional_replacements=replacements,
    )

    # Create the k8s resource
    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, RESOURCE_PLURAL,
        resource.name, namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    k8s.wait_resource_consumed_by_controller(ref)
    condition.assert_not_synced(ref)

    domain.wait_until(ref.name, domain.processing_matches(False))

    logging.info(f"ES Domain {resource.name} creation succeeded and DomainStatus.Processing is now False")

    time.sleep(CHECK_STATUS_WAIT_SECONDS)
    condition.assert_synced(ref)

    yield ref, resource

    # Delete the k8s resource on teardown of the module
    k8s.delete_custom_resource(ref)

    logging.info(f"Deleted CR for OpenSearch Domain {resource.name}. Waiting {DELETE_WAIT_AFTER_SECONDS} before checking existence in AWS API")
    time.sleep(DELETE_WAIT_AFTER_SECONDS)

    # Domain should no longer appear in OpenSearchService
    domain.wait_until_deleted(ref.name)


@pytest.fixture
def es_2d3m_multi_az_vpc_2_subnet7_9_domain(os_client, resources: BootstrapResources):
    resource = Domain(
        name=random_suffix_name("my-os-domain3", 20),
        data_node_count=2,
        master_node_count=3,
        is_zone_aware=True,
        is_vpc=True,
        vpc_id=resources.VPC.vpc_id,
        vpc_subnets=resources.VPC.private_subnets.subnet_ids,
    )
    mup = resources.MasterUserPasswordSecret

    replacements = REPLACEMENT_VALUES.copy()
    replacements["DOMAIN_NAME"] = resource.name
    replacements["MASTER_USER_PASS_SECRET_NAMESPACE"] = mup.ns
    replacements["MASTER_USER_PASS_SECRET_NAME"] = mup.name
    replacements["MASTER_USER_PASS_SECRET_KEY"] = mup.key
    replacements["MASTER_NODE_COUNT"] = str(resource.master_node_count)
    replacements["DATA_NODE_COUNT"] = str(resource.data_node_count)
    replacements["SUBNETS"] = str(resource.vpc_subnets)

    resource_data = load_opensearch_resource(
        "domain_es_xdym_multi_az_vpc7.9",
        additional_replacements=replacements,
    )
    logging.debug(resource_data)

    # Create the k8s resource
    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, RESOURCE_PLURAL,
        resource.name, namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    k8s.wait_resource_consumed_by_controller(ref)
    condition.assert_not_synced(ref)

    domain.wait_until(ref.name, domain.processing_matches(False))

    logging.info(f"OpenSearch Domain {resource.name} creation succeeded and DomainStatus.Processing is now False")

    time.sleep(CHECK_STATUS_WAIT_SECONDS)
    condition.assert_synced(ref)

    yield ref, resource

    # Delete the k8s resource on teardown of the module
    k8s.delete_custom_resource(ref)

    logging.info(f"Deleted CR for OpenSearch Domain {resource.name}. Waiting {DELETE_WAIT_AFTER_SECONDS} before checking existence in AWS API")
    time.sleep(DELETE_WAIT_AFTER_SECONDS)

    # Domain should no longer appear in OpenSearchService
    domain.wait_until_deleted(ref.name)


@service_marker
@pytest.mark.canary
class TestDomain:
    def test_create_delete_es_7_9(self, es_7_9_domain):
        ref, resource = es_7_9_domain

        latest = domain.get(resource.name)

        assert latest['DomainStatus']['EngineVersion'] == 'Elasticsearch_7.9'
        assert latest['DomainStatus']['Created'] is True
        assert latest['DomainStatus']['ClusterConfig']['InstanceCount'] == resource.data_node_count
        assert latest['DomainStatus']['ClusterConfig']['ZoneAwarenessEnabled'] == resource.is_zone_aware

        time.sleep(CHECK_ENDPOINT_WAIT_SECONDS)

        cr = k8s.get_resource(ref)
        assert cr is not None
        assert 'status' in cr
        domain.assert_endpoint(cr)

        # now we will modify the engine version to test upgrades
        # similar to creating a new domain, this takes a long time, often 20+ minutes
        updates = {
            "spec": {"engineVersion": "Elasticsearch_7.10"},
        }
        k8s.patch_custom_resource(ref, updates)

        # wait for 15 minutes, it's always going to take at least this long
        time.sleep(MODIFY_WAIT_AFTER_SECONDS)
        # now loop to see if it's done, with a max elapsed time so the test doesn't run forever
        count = 0
        while count < 30:
            count += 1
            latest = domain.get(resource.name)
            assert latest is not None
            if latest['DomainStatus']['UpgradeProcessing'] is True:
                time.sleep(CHECK_STATUS_WAIT_SECONDS)
                continue
            else:
                assert latest['DomainStatus']['EngineVersion'] == "Elasticsearch_7.10"
                break

    def test_create_delete_es_2d3m_multi_az_no_vpc_7_9(self, es_2d3m_multi_az_no_vpc_7_9_domain):
        ref, resource = es_2d3m_multi_az_no_vpc_7_9_domain

        latest = domain.get(resource.name)

        assert latest['DomainStatus']['EngineVersion'] == 'Elasticsearch_7.9'
        assert latest['DomainStatus']['Created'] == True
        assert latest['DomainStatus']['ClusterConfig']['InstanceCount'] == resource.data_node_count
        assert latest['DomainStatus']['ClusterConfig']['DedicatedMasterCount'] == resource.master_node_count
        assert latest['DomainStatus']['ClusterConfig']['ZoneAwarenessEnabled'] == resource.is_zone_aware

        time.sleep(CHECK_ENDPOINT_WAIT_SECONDS)

        cr = k8s.get_resource(ref)
        assert cr is not None
        assert 'status' in cr
        domain.assert_endpoint(cr)

        # modify some cluster parameters to test updates
        updates = {
            "spec": {"softwareUpdateOptions": {"autoSoftwareUpdateEnabled": True}},
        }
        # updates = {
        #     "spec": {
        #         "AutoTuneOptions": {
        #             "UseOffPeakWindow": False
        #         },
        #         "ClusterConfig": {
        #             "MultiAZWithStandbyEnabled": False
        #         },
        #         "OffPeakWindowOptions": {
        #             "Enabled": True,
        #             "OffPeakWindow": {
        #                 "WindowStartTime": {
        #                     "Hours": 23,
        #                     "Minutes": 30
        #                 }
        #             }
        #         },
        #         "SoftwareUpdateOptions": {
        #             "AutoSoftwareUpdateEnabled": True
        #         }
        #     }
        # }
        k8s.patch_custom_resource(ref, updates)
        time.sleep(CHECK_STATUS_WAIT_SECONDS)
        print("after check wait:", domain.get(resource.name))
        assert k8s.wait_on_condition(ref, condition.CONDITION_TYPE_RESOURCE_SYNCED, "True", wait_periods=10)
        latest = domain.get(resource.name)
        print("latest:", latest)

        # assert latest['DomainStatus']['AutoTuneOptions']['UseOffPeakWindow'] is False
        # assert latest['DomainStatus']['ClusterConfig']['MultiAZWithStandbyEnabled'] is False
        # assert latest['DomainStatus']['OffPeakWindowOptions']["Enabled"] is True
        # assert latest['DomainStatus']['OffPeakWindowOptions']["OffPeakWindow"]["WindowStartTime"]["Hours"] == 23
        # assert latest['DomainStatus']['OffPeakWindowOptions']["OffPeakWindow"]["WindowStartTime"]["Minutes"] == 30
        assert latest['DomainStatus']['SoftwareUpdateOptions']["AutoSoftwareUpdateEnabled"] is True

    def test_create_delete_es_2d3m_multi_az_vpc_2_subnet7_9(self, es_2d3m_multi_az_vpc_2_subnet7_9_domain):
        ref, resource = es_2d3m_multi_az_vpc_2_subnet7_9_domain

        latest = domain.get(resource.name)

        assert latest['DomainStatus']['EngineVersion'] == 'Elasticsearch_7.9'
        assert latest['DomainStatus']['Created'] == True
        assert latest['DomainStatus']['ClusterConfig']['InstanceCount'] == resource.data_node_count
        assert latest['DomainStatus']['ClusterConfig']['DedicatedMasterCount'] == resource.master_node_count
        assert latest['DomainStatus']['ClusterConfig']['ZoneAwarenessEnabled'] == resource.is_zone_aware
        assert latest['DomainStatus']['VPCOptions']['VPCId'] == resource.vpc_id
        assert set(latest['DomainStatus']['VPCOptions']['SubnetIds']) == set(resource.vpc_subnets)

        time.sleep(CHECK_ENDPOINT_WAIT_SECONDS)

        cr = k8s.get_resource(ref)
        assert cr is not None
        assert 'status' in cr
        domain.assert_endpoints(cr)
