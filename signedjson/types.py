# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import nacl.signing
from typing_extensions import Protocol


class BaseKey(Protocol):
    """Common base type for VerifyKey and SigningKey"""
    version = ""  # type: str
    alg = ""  # type: str

    def encode(self):
        # type: () -> bytes
        pass   # pragma: nocover


class VerifyKey(BaseKey):
    """The public part of a key pair, for use with verify_signed_json"""
    def verify(self, message, signature):
        # type: (bytes, bytes) -> bytes
        pass   # pragma: nocover


class SigningKey(BaseKey):
    """The private part of a key pair, for use with sign_json"""
    def sign(self, message):
        # type: (bytes) -> nacl.signing.SignedMessage
        pass   # pragma: nocover

    @property
    def verify_key(self):
        # type: () -> nacl.signing.VerifyKey
        pass   # pragma: nocover
