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

"""Utilities for working with VpcEndpoint resources"""

import datetime
import time
import typing

import boto3
from botocore.config import Config
import pytest

DEFAULT_WAIT_UNTIL_TIMEOUT_SECONDS = 60*15
DEFAULT_WAIT_UNTIL_INTERVAL_SECONDS = 15
DEFAULT_WAIT_UNTIL_DELETED_TIMEOUT_SECONDS = 60*15
DEFAULT_WAIT_UNTIL_DELETED_INTERVAL_SECONDS = 15

_RETRY_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

VpcEndpointMatchFunc = typing.NewType(
    'VpcEndpointMatchFunc',
    typing.Callable[[dict], bool],
)


class StatusMatcher:
    def __init__(self, status: str):
        self.match_on = status

    def __call__(self, record: dict) -> bool:
        return record is not None and record['Status'] == self.match_on


def status_matches(status: str) -> VpcEndpointMatchFunc:
    return StatusMatcher(status)


def wait_until(
        vpc_endpoint_id: str,
        match_fn: VpcEndpointMatchFunc,
        timeout_seconds: int = DEFAULT_WAIT_UNTIL_TIMEOUT_SECONDS,
        interval_seconds: int = DEFAULT_WAIT_UNTIL_INTERVAL_SECONDS,
    ) -> None:
    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=timeout_seconds)

    while not match_fn(get(vpc_endpoint_id)):
        if datetime.datetime.now() >= timeout:
            pytest.fail(
                f"failed to match VpcEndpoint {vpc_endpoint_id} before timeout"
            )
        time.sleep(interval_seconds)


def wait_until_deleted(
        vpc_endpoint_id: str,
        timeout_seconds: int = DEFAULT_WAIT_UNTIL_DELETED_TIMEOUT_SECONDS,
        interval_seconds: int = DEFAULT_WAIT_UNTIL_DELETED_INTERVAL_SECONDS,
    ) -> None:
    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=timeout_seconds)

    while True:
        if datetime.datetime.now() >= timeout:
            pytest.fail(
                f"Timed out waiting for VpcEndpoint {vpc_endpoint_id} to be "
                f"deleted in OpenSearch API"
            )
        time.sleep(interval_seconds)

        if get(vpc_endpoint_id) is None:
            break


def get(vpc_endpoint_id):
    """Returns a dict containing the VpcEndpoint record from the OpenSearch
    API.

    If no such VpcEndpoint exists, returns None.
    """
    c = boto3.client('opensearch', config=_RETRY_CONFIG)
    resp = c.describe_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id])
    endpoints = resp.get('VpcEndpoints', [])
    if len(endpoints) == 0:
        return None
    return endpoints[0]
