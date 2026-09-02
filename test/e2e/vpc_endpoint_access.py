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

"""Utilities for working with VPCEndpointAccess resources"""

import datetime
import time

import boto3
from botocore.config import Config
import pytest

DEFAULT_WAIT_UNTIL_TIMEOUT_SECONDS = 60*5
DEFAULT_WAIT_UNTIL_INTERVAL_SECONDS = 15

_RETRY_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})


def get_authorized_principals(domain_name):
    """Returns the set of principals authorized to access the domain's VPC
    endpoints.
    """
    c = boto3.client('opensearch', config=_RETRY_CONFIG)
    principals = set()
    next_token = None
    while True:
        kwargs = {'DomainName': domain_name}
        if next_token:
            kwargs['NextToken'] = next_token
        resp = c.list_vpc_endpoint_access(**kwargs)
        for p in resp.get('AuthorizedPrincipalList', []):
            principals.add(p.get('Principal', ''))
        token = resp.get('NextToken')
        if not token or token == next_token:
            break
        next_token = token
    return principals


def wait_until_authorized(
        domain_name: str,
        principal: str,
        authorized: bool,
        timeout_seconds: int = DEFAULT_WAIT_UNTIL_TIMEOUT_SECONDS,
        interval_seconds: int = DEFAULT_WAIT_UNTIL_INTERVAL_SECONDS,
    ) -> None:
    """Waits until the supplied principal is authorized, or no longer
    authorized, to access the domain's VPC endpoints.

    Raises:
        pytest.fail upon timeout
    """
    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=timeout_seconds)

    while (principal in get_authorized_principals(domain_name)) != authorized:
        if datetime.datetime.now() >= timeout:
            pytest.fail(
                f"failed to see principal {principal} "
                f"{'authorized' if authorized else 'revoked'} on domain "
                f"{domain_name} before timeout"
            )
        time.sleep(interval_seconds)


def get_supported_regions(domain_name, principal):
    """Returns the set of Regions the principal is authorized for."""
    c = boto3.client('opensearch', config=_RETRY_CONFIG)
    resp = c.list_vpc_endpoint_access(DomainName=domain_name)
    for p in resp.get('AuthorizedPrincipalList', []):
        if p.get('Principal') == principal:
            return set(p.get('ServiceOptions', {}).get('SupportedRegions', []))
    return set()


def wait_until_supported_regions(
        domain_name: str,
        principal: str,
        regions: set,
        timeout_seconds: int = DEFAULT_WAIT_UNTIL_TIMEOUT_SECONDS,
        interval_seconds: int = DEFAULT_WAIT_UNTIL_INTERVAL_SECONDS,
    ) -> None:
    """Waits until the principal is authorized for exactly the supplied Regions.

    Raises:
        pytest.fail upon timeout
    """
    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(seconds=timeout_seconds)

    while get_supported_regions(domain_name, principal) != regions:
        if datetime.datetime.now() >= timeout:
            pytest.fail(
                f"failed to see principal {principal} authorized for {regions} "
                f"on domain {domain_name} before timeout"
            )
        time.sleep(interval_seconds)
