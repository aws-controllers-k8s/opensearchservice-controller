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

"""Integration tests for the OpenSearchService API VpcEndpoint resource
"""

import logging
import time

from acktest.resources import random_suffix_name
from acktest.k8s import resource as k8s
import pytest

from e2e import domain
from e2e import vpc_endpoint
from e2e import service_marker, CRD_GROUP, CRD_VERSION, load_opensearch_resource
from e2e.replacement_values import REPLACEMENT_VALUES
from e2e.bootstrap_resources import BootstrapResources, get_bootstrap_resources

RESOURCE_PLURAL = 'vpcendpoints'
DOMAIN_RESOURCE_PLURAL = 'domains'

CREATE_WAIT_AFTER_SECONDS = 30
DELETE_WAIT_AFTER_SECONDS = 60


@pytest.fixture(scope="module")
def resources():
    return get_bootstrap_resources()


@pytest.fixture
def vpc_domain(os_client, resources: BootstrapResources):
    domain_name = random_suffix_name("my-os-vpce-domain", 24)
    mup = resources.MasterUserPasswordSecret

    replacements = REPLACEMENT_VALUES.copy()
    replacements["DOMAIN_NAME"] = domain_name
    replacements["MASTER_USER_PASS_SECRET_NAMESPACE"] = mup.ns
    replacements["MASTER_USER_PASS_SECRET_NAME"] = mup.name
    replacements["MASTER_USER_PASS_SECRET_KEY"] = mup.key
    replacements["MASTER_NODE_COUNT"] = "3"
    replacements["DATA_NODE_COUNT"] = "2"
    replacements["SUBNETS"] = str(resources.VPC.private_subnets.subnet_ids)

    resource_data = load_opensearch_resource(
        "domain_es_xdym_multi_az_vpc7.9",
        additional_replacements=replacements,
    )

    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, DOMAIN_RESOURCE_PLURAL,
        domain_name, namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    k8s.wait_resource_consumed_by_controller(ref)

    domain.wait_until(ref.name, domain.processing_matches(False))
    assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=30)

    yield ref, domain_name

    k8s.delete_custom_resource(ref)
    time.sleep(DELETE_WAIT_AFTER_SECONDS)
    domain.wait_until_deleted(ref.name)


@service_marker
@pytest.mark.canary
class TestVpcEndpoint:
    def test_create_delete(self, vpc_domain, resources: BootstrapResources):
        domain_ref, domain_name = vpc_domain

        endpoint_name = random_suffix_name("my-os-vpce", 20)

        replacements = REPLACEMENT_VALUES.copy()
        replacements["VPC_ENDPOINT_NAME"] = endpoint_name
        replacements["DOMAIN_NAME"] = domain_name
        replacements["SUBNETS"] = str(resources.VPC.private_subnets.subnet_ids)

        resource_data = load_opensearch_resource(
            "vpc_endpoint",
            additional_replacements=replacements,
        )

        ref = k8s.CustomResourceReference(
            CRD_GROUP, CRD_VERSION, RESOURCE_PLURAL,
            endpoint_name, namespace="default",
        )
        k8s.create_custom_resource(ref, resource_data)
        k8s.wait_resource_consumed_by_controller(ref)

        time.sleep(CREATE_WAIT_AFTER_SECONDS)

        cr = k8s.get_resource(ref)
        assert cr is not None
        assert 'status' in cr
        assert 'vpcEndpointID' in cr['status']
        endpoint_id = cr['status']['vpcEndpointID']

        vpc_endpoint.wait_until(endpoint_id, vpc_endpoint.status_matches("ACTIVE"))
        assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=30)

        latest = vpc_endpoint.get(endpoint_id)
        assert latest is not None
        assert set(latest['VpcOptions']['SubnetIds']) == set(resources.VPC.private_subnets.subnet_ids)

        k8s.delete_custom_resource(ref)
        time.sleep(DELETE_WAIT_AFTER_SECONDS)
        vpc_endpoint.wait_until_deleted(endpoint_id)
