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
"""Bootstraps the resources required to run the OpenSearch Service
integration tests.
"""

import logging

from acktest.bootstrapping import Resources, BootstrapFailureException
from e2e import bootstrap_directory
from e2e.bootstrap_resources import (
    BootstrapResources,
    VPC,
    ServiceLinkedRole
)
from e2e import secret


def service_bootstrap() -> Resources:
    logging.getLogger().setLevel(logging.INFO)
    
    resources = BootstrapResources(
        VPC=VPC(name_prefix="opensearch-vpc", num_private_subnet=2),
        SLR=ServiceLinkedRole(
            aws_service_name="opensearchservice.amazonaws.com",
            default_name="AWSServiceRoleForAmazonOpenSearchService",
            description="An SLR to allow Amazon OpenSearch Service to work within a private VPC"
        ),
        MasterUserPasswordSecret=secret.Secret(
            ns="default",
            name="passwords",
            key="master_user_pass",
            val="Secretpass123456!",
        ),
    )

    try:
        resources.bootstrap()
    except BootstrapFailureException as ex:
        exit(254)

    return resources

if __name__ == "__main__":
    config = service_bootstrap()
    # Write config to current directory by default
    config.serialize(bootstrap_directory)
