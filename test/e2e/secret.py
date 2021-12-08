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

"""Fixtures common to all RDS controller tests"""

import dataclasses

from acktest.k8s import resource as k8s

import logging

from dataclasses import dataclass, field

from acktest import bootstrapping


@dataclasses.dataclass
class Secret(bootstrapping.Bootstrappable):
    ns: str
    name: str
    key: str
    val: str

    def bootstrap(self):
        """Ensures a Kubernetes secret with the specified ns/name/key exists
        """
        k8s.create_opaque_secret(self.ns, self.name, self.key, self.val)

    def cleanup(self):
        """Ensures the Kubernetes secret does not exist
        """
        k8s.delete_secret(self.ns, self.name)
