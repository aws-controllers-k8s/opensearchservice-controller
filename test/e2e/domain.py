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

"""Utilities for working with Domain resources"""

import datetime
import time
import typing

import boto3
import pytest

DEFAULT_WAIT_UNTIL_TIMEOUT_SECONDS = 60*30
DEFAULT_WAIT_UNTIL_INTERVAL_SECONDS = 20
DEFAULT_WAIT_UNTIL_DELETED_TIMEOUT_SECONDS = 60*10
DEFAULT_WAIT_UNTIL_DELETED_INTERVAL_SECONDS = 15

DomainMatchFunc = typing.NewType(
    'DomainMatchFunc',
    typing.Callable[[dict], bool],
)

class ProcessingMatcher:
    def __init__(self, processing: bool):
        self.match_on = processing

    def __call__(self, record: dict) -> bool:
        return ('DomainStatus' in record
                and 'Processing' in record['DomainStatus']
                and record['DomainStatus']['Processing'] == self.match_on)


def processing_matches(processing: bool) -> DomainMatchFunc:
    return ProcessingMatcher(processing)


def wait_until(
        domain_name: str,
        match_fn: DomainMatchFunc,
        timeout_seconds: int = DEFAULT_WAIT_UNTIL_TIMEOUT_SECONDS,
        interval_seconds: int = DEFAULT_WAIT_UNTIL_INTERVAL_SECONDS,
    ) -> None:
    """Waits until a domain with a supplied name is returned from the
    OpenSearch API and the matching functor returns True.

    Usage:
        from e2e.domain import wait_until, processing_matches

        wait_until(
            domain_name,
            processing_matches(False),
        )

    Raises:
        pytest.fail upon timeout
    """
    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=timeout_seconds)

    while not match_fn(get(domain_name)):
        if datetime.datetime.now() >= timeout:
            pytest.fail(
                f"failed to match domain {domain_name} before timeout"
            )
        time.sleep(interval_seconds)


def wait_until_deleted(
        domain_name: str,
        timeout_seconds: int = DEFAULT_WAIT_UNTIL_DELETED_TIMEOUT_SECONDS,
        interval_seconds: int = DEFAULT_WAIT_UNTIL_DELETED_INTERVAL_SECONDS,
    ) -> None:
    """Waits until a domain with a supplied name is no longer returned from
    the OpenSearch API.

    Usage:
        from e2e.domain import wait_until_deleted

        wait_until_deleted(domain_name)

    Raises:
        pytest.fail upon timeout or if the domain's Deleted field is ever False
    """
    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=timeout_seconds)

    while True:
        if datetime.datetime.now() >= timeout:
            pytest.fail(
                f"Timed out waiting for domain {domain_name} to be "
                f"deleted in OpenSearch API"
            )
        time.sleep(interval_seconds)

        latest = get(domain_name)
        if latest is None:
            break

        if latest['DomainStatus']['Deleted'] == False:
            pytest.fail(
                f"'Deleted' is False for domain {domain_name} "
                f"that was deleted."
            )


def get(domain_name):
    """Returns a dict containing the domain record from the OpenSearch API.

    If no such domain exists, returns None.
    """
    c = boto3.client('opensearch')
    try:
        resp = c.describe_domain(DomainName=domain_name)
        assert 'DomainStatus' in resp
        return resp
    except c.exceptions.ResourceNotFoundException:
        return None

