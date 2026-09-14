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

"""Integration tests for the OpenSearchService API VpcEndpointAccess resource
"""

import contextlib
import time

from acktest.resources import random_suffix_name
from acktest.k8s import resource as k8s
from acktest.aws.identity import get_account_id, get_region
import pytest

from e2e import domain
from e2e import vpc_endpoint_access
from e2e import service_marker, CRD_GROUP, CRD_VERSION, load_opensearch_resource
from e2e.replacement_values import REPLACEMENT_VALUES
from e2e.bootstrap_resources import BootstrapResources, get_bootstrap_resources

RESOURCE_PLURAL = 'vpcendpointaccesses'
DOMAIN_RESOURCE_PLURAL = 'domains'

SERVICE_PRINCIPAL = "application.opensearchservice.amazonaws.com"

DELETE_WAIT_AFTER_SECONDS = 60


@pytest.fixture(scope="module")
def resources():
    return get_bootstrap_resources()


@pytest.fixture
def vpc_domain(os_client, resources: BootstrapResources):
    domain_name = random_suffix_name("my-os-vpcea-domain", 24)
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


@contextlib.contextmanager
def access(domain_name, principal, resource_name="vpc_endpoint_access"):
    access_name = random_suffix_name("my-os-vpcea", 20)

    replacements = REPLACEMENT_VALUES.copy()
    replacements["VPC_ENDPOINT_ACCESS_NAME"] = access_name
    replacements["DOMAIN_NAME"] = domain_name
    replacements["PRINCIPAL"] = principal
    replacements["REGION"] = get_region()

    resource_data = load_opensearch_resource(
        resource_name,
        additional_replacements=replacements,
    )

    ref = k8s.CustomResourceReference(
        CRD_GROUP, CRD_VERSION, RESOURCE_PLURAL,
        access_name, namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)
    try:
        k8s.wait_resource_consumed_by_controller(ref)
        yield ref
    finally:
        if k8s.get_resource_exists(ref):
            k8s.delete_custom_resource(ref)
            vpc_endpoint_access.wait_until_authorized(domain_name, principal, False)


@service_marker
@pytest.mark.canary
class TestVpcEndpointAccess:
    def test_create_update_delete(self, vpc_domain):
        domain_ref, domain_name = vpc_domain
        region = get_region()
        account_id = get_account_id()

        with access(domain_name, SERVICE_PRINCIPAL) as ref:
            vpc_endpoint_access.wait_until_authorized(domain_name, SERVICE_PRINCIPAL, True)
            assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=10)

            cr = k8s.get_resource(ref)
            assert cr is not None
            assert cr['spec']['principal'] == SERVICE_PRINCIPAL
            assert vpc_endpoint_access.get_supported_regions(domain_name, SERVICE_PRINCIPAL) == {region}

            updates = {"spec": {"serviceOptions": {"supportedRegions": [region, "eu-west-1"]}}}
            k8s.patch_custom_resource(ref, updates)

            vpc_endpoint_access.wait_until_supported_regions(
                domain_name, SERVICE_PRINCIPAL, {region, "eu-west-1"},
            )
            assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=10)

            updates = {"spec": {"serviceOptions": {"supportedRegions": [region]}}}
            k8s.patch_custom_resource(ref, updates)

            vpc_endpoint_access.wait_until_supported_regions(
                domain_name, SERVICE_PRINCIPAL, {region},
            )
            assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=10)

            updates = {"spec": {"principal": account_id}}
            with pytest.raises(Exception):
                k8s.patch_custom_resource(ref, updates)

        with access(
            domain_name, SERVICE_PRINCIPAL,
            resource_name="vpc_endpoint_access_default_region",
        ) as ref:
            vpc_endpoint_access.wait_until_authorized(domain_name, SERVICE_PRINCIPAL, True)
            assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=10)
            assert vpc_endpoint_access.get_supported_regions(domain_name, SERVICE_PRINCIPAL) == {region}

            cr = k8s.get_resource(ref)
            assert cr['spec']['serviceOptions']['supportedRegions'] == [region]
            terminal = k8s.get_resource_condition(ref, "ACK.Terminal")
            assert terminal is None or terminal['status'] == "False"

        with access(
            domain_name, account_id,
            resource_name="vpc_endpoint_access_default_region",
        ) as ref:
            vpc_endpoint_access.wait_until_authorized(domain_name, account_id, True)
            assert k8s.wait_on_condition(ref, "ACK.ResourceSynced", "True", wait_periods=10)
