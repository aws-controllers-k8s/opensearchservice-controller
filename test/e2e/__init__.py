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

import functools
import pytest
from typing import Dict, Any
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from acktest.resources import load_resource_file

SERVICE_NAME = "opensearchservice"
CRD_GROUP = "opensearchservice.services.k8s.aws"
CRD_VERSION = "v1alpha1"

# Adaptive mode adds client-side rate limiting on top of backoff. Its limiter is
# per client object, so each xdist worker process converges independently; more
# attempts buy backoff, not throughput, so keep the count low and let the
# polling loops tolerate the throttle instead.
RETRY_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})

THROTTLE_CODES = frozenset({
    "ThrottlingException",
    "Throttling",
    "ThrottledException",
    "TooManyRequestsException",
    "RequestLimitExceeded",
    "RequestThrottled",
    "RequestThrottledException",
})


def is_throttling_error(err: BaseException) -> bool:
    return (
        isinstance(err, ClientError)
        and err.response.get("Error", {}).get("Code") in THROTTLE_CODES
    )


@functools.lru_cache
def opensearch_client():
    return boto3.client("opensearch", config=RETRY_CONFIG)

# PyTest marker for the current service
service_marker = pytest.mark.service(arg=SERVICE_NAME)
bootstrap_directory = Path(__file__).parent
resource_directory = Path(__file__).parent / "resources"

def load_opensearch_resource(resource_name: str, additional_replacements: Dict[str, Any] = {}):
    """ Overrides the default `load_resource_file` to access the specific resources
    directory for the current service.
    """
    return load_resource_file(resource_directory, resource_name, additional_replacements=additional_replacements)
