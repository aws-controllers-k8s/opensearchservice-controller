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

import boto3
import datetime
import pytest
import logging
import time
from typing import Dict

from acktest.k8s import resource as k8s

from e2e import service_marker, CRD_GROUP, CRD_VERSION, load_opensearch_resource
from e2e.replacement_values import REPLACEMENT_VALUES
from dataclasses import dataclass, field
from e2e.bootstrap_resources import BootstrapResources, get_bootstrap_resources

RESOURCE_PLURAL = 'domains'

DELETE_WAIT_INTERVAL_SLEEP_SECONDS = 20
DELETE_WAIT_AFTER_SECONDS = 30
DELETE_TIMEOUT_SECONDS = 10*60

CREATE_WAIT_INTERVAL_SLEEP_SECONDS = 20
CREATE_TIMEOUT_SECONDS = 30*60


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

def wait_for_create_or_die(os_client, resource, timeout):
    aws_res = os_client.describe_domain(DomainName=resource.name)
    while aws_res['DomainStatus']['Processing'] == True:
        if datetime.datetime.now() >= timeout:
            pytest.fail("Timed out waiting for OpenSearch Domain to get DomainStatus.Processing == False")
        time.sleep(CREATE_WAIT_INTERVAL_SLEEP_SECONDS)

        aws_res = os_client.describe_domain(DomainName=resource.name)

    return aws_res


def wait_for_delete_or_die(os_client, resource, timeout):
    while True:
        if datetime.datetime.now() >= timeout:
            pytest.fail("Timed out waiting for OpenSearch Domain to being deleted in OpenSearchService API")
        time.sleep(DELETE_WAIT_INTERVAL_SLEEP_SECONDS)

        try:
            aws_res = os_client.describe_domain(DomainName=resource.name)
            if aws_res['DomainStatus']['Deleted'] == False:
                pytest.fail("DomainStatus.Deleted is False for OpenSearch Domain that was deleted.")
        except os_client.exceptions.ResourceNotFoundException:
            break

@pytest.fixture
def es_7_9_domain(os_client):
    resource = Domain(name="my-os-domain", data_node_count=1)

    replacements = REPLACEMENT_VALUES.copy()
    replacements["DOMAIN_NAME"] = resource.name

    resource_data = load_opensearch_resource(
        "domain_es7.9",
        additional_replacements=replacements,
    )
    logging.debug(resource_data)

    # Create the k8s resource
    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, RESOURCE_PLURAL,
        resource.name, namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    logging.debug(cr)

    # Let's check that the domain appears in OpenSearchService
    aws_res = os_client.describe_domain(DomainName=resource.name)

    logging.debug(aws_res)

    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=CREATE_TIMEOUT_SECONDS)

    # An OpenSerach Domain gets its `DomainStatus.Created` field set to
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
    aws_res = wait_for_create_or_die(os_client, resource, timeout)
    logging.info(f"ES Domain {resource.name} creation succeeded and DomainStatus.Processing is now False")

    yield (resource, aws_res)

    # Delete the k8s resource on teardown of the module
    k8s.delete_custom_resource(ref)

    logging.info(f"Deleted CR for OpenSearch Domain {resource.name}. Waiting {DELETE_WAIT_AFTER_SECONDS} before checking existence in AWS API")
    time.sleep(DELETE_WAIT_AFTER_SECONDS)

    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=DELETE_TIMEOUT_SECONDS)

    # Domain should no longer appear in OpenSearchService
    wait_for_delete_or_die(os_client, resource, timeout)

@pytest.fixture
def es_2d3m_multi_az_no_vpc_7_9_domain(os_client):
    resource = Domain(name="my-os-domain2",data_node_count=2,master_node_count=3,is_zone_aware=True)

    replacements = REPLACEMENT_VALUES.copy()
    replacements["DOMAIN_NAME"] = resource.name
    replacements["MASTER_NODE_COUNT"] = str(resource.master_node_count)
    replacements["DATA_NODE_COUNT"] = str(resource.data_node_count)

    resource_data = load_opensearch_resource(
        "domain_es_xdym_multi_az7.9",
        additional_replacements=replacements,
    )
    logging.debug(resource_data)

    # Create the k8s resource
    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, RESOURCE_PLURAL,
        resource.name, namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    logging.debug(cr)

    # Let's check that the domain appears in OpenSearchService
    aws_res = os_client.describe_domain(DomainName=resource.name)

    logging.debug(aws_res)

    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=CREATE_TIMEOUT_SECONDS)

    aws_res = wait_for_create_or_die(os_client, resource, timeout)
    logging.info(f"ES Domain {resource.name} creation succeeded and DomainStatus.Processing is now False")

    yield (resource, aws_res)

    # Delete the k8s resource on teardown of the module
    k8s.delete_custom_resource(ref)

    logging.info(f"Deleted CR for OpenSearch Domain {resource.name}. Waiting {DELETE_WAIT_AFTER_SECONDS} before checking existence in AWS API")
    time.sleep(DELETE_WAIT_AFTER_SECONDS)

    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=DELETE_TIMEOUT_SECONDS)

    # Domain should no longer appear in OpenSearchService
    wait_for_delete_or_die(os_client, resource, timeout)

@pytest.fixture
def es_2d3m_multi_az_vpc_2_subnet7_9_domain(os_client, resources: BootstrapResources):
    resource = Domain(
        name="my-os-domain3",
        data_node_count=2,
        master_node_count=3,
        is_zone_aware=True,
        is_vpc=True,
        vpc_id=resources.VPC.vpc_id,
        vpc_subnets=resources.VPC.private_subnets.subnet_ids,
    )

    logging.debug(resource)

    replacements = REPLACEMENT_VALUES.copy()
    replacements["DOMAIN_NAME"] = resource.name
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
    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    logging.debug(cr)

    # Let's check that the domain appears in OpenSearchService
    aws_res = os_client.describe_domain(DomainName=resource.name)

    logging.debug(aws_res)

    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=CREATE_TIMEOUT_SECONDS)

    aws_res = wait_for_create_or_die(os_client, resource, timeout)
    logging.info(f"OpenSearch Domain {resource.name} creation succeeded and DomainStatus.Processing is now False")

    yield (resource, aws_res)

    # Delete the k8s resource on teardown of the module
    k8s.delete_custom_resource(ref)

    logging.info(f"Deleted CR for OpenSearch Domain {resource.name}. Waiting {DELETE_WAIT_AFTER_SECONDS} before checking existence in AWS API")
    time.sleep(DELETE_WAIT_AFTER_SECONDS)

    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=DELETE_TIMEOUT_SECONDS)

    # Domain should no longer appear in OpenSearchService
    wait_for_delete_or_die(os_client, resource, timeout)

@service_marker
@pytest.mark.canary
class TestDomain:
    def test_create_delete_es_7_9(self, es_7_9_domain):
        (resource, aws_res) = es_7_9_domain

        assert aws_res['DomainStatus']['EngineVersion'] == 'Elasticsearch_7.9'
        assert aws_res['DomainStatus']['Created'] == True
        assert aws_res['DomainStatus']['ClusterConfig']['InstanceCount'] == resource.data_node_count
        assert aws_res['DomainStatus']['ClusterConfig']['ZoneAwarenessEnabled'] == resource.is_zone_aware    

    def test_create_delete_es_2d3m_multi_az_no_vpc_7_9(self, es_2d3m_multi_az_no_vpc_7_9_domain):
        (resource, aws_res) = es_2d3m_multi_az_no_vpc_7_9_domain

        assert aws_res['DomainStatus']['EngineVersion'] == 'Elasticsearch_7.9'
        assert aws_res['DomainStatus']['Created'] == True
        assert aws_res['DomainStatus']['ClusterConfig']['InstanceCount'] == resource.data_node_count
        assert aws_res['DomainStatus']['ClusterConfig']['DedicatedMasterCount'] == resource.master_node_count
        assert aws_res['DomainStatus']['ClusterConfig']['ZoneAwarenessEnabled'] == resource.is_zone_aware

    def test_create_delete_es_2d3m_multi_az_vpc_2_subnet7_9(self, es_2d3m_multi_az_vpc_2_subnet7_9_domain):
        (resource, aws_res) = es_2d3m_multi_az_vpc_2_subnet7_9_domain

        assert aws_res['DomainStatus']['EngineVersion'] == 'Elasticsearch_7.9'
        assert aws_res['DomainStatus']['Created'] == True
        assert aws_res['DomainStatus']['ClusterConfig']['InstanceCount'] == resource.data_node_count
        assert aws_res['DomainStatus']['ClusterConfig']['DedicatedMasterCount'] == resource.master_node_count
        assert aws_res['DomainStatus']['ClusterConfig']['ZoneAwarenessEnabled'] == resource.is_zone_aware
        assert aws_res['DomainStatus']['VPCOptions']['VPCId'] == resource.vpc_id
        assert set(aws_res['DomainStatus']['VPCOptions']['SubnetIds']) == set(resource.vpc_subnets)