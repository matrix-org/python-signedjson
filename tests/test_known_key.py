# -*- coding: utf-8 -*-

# Copyright 2015 OpenMarket Ltd
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

import unittest

from unpaddedbase64 import decode_base64

import nacl.signing

from signedjson.sign import sign_json

SIGNING_KEY_SEED = decode_base64(
    "YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1"
)

KEY_ALG = "ed25519"
KEY_VER = 1
KEY_NAME = "%s:%d" % (KEY_ALG, KEY_VER)


class KnownKeyTestCase(unittest.TestCase):
    """ An entirely deterministic test using a given signing key seed, so that
    other implementations can compare that they get the same result. """

    def setUp(self):
        self.signing_key = nacl.signing.SigningKey(SIGNING_KEY_SEED)
        self.signing_key.alg = KEY_ALG
        self.signing_key.version = KEY_VER

    def test_sign_minimal(self):
        self.assertEquals(
            sign_json({}, "domain", self.signing_key),
            {
                'signatures': {
                    'domain': {
                        KEY_NAME: "K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMt"
                        "TdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ"
                    },
                }
            }
        )

    def test_sign_with_data(self):
        self.assertEquals(
            sign_json({'one': 1, 'two': "Two"}, "domain", self.signing_key),
            {
                'one': 1,
                'two': "Two",
                'signatures': {
                    'domain': {
                        KEY_NAME: "KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4s"
                        "L53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw"
                    },
                }
            }
        )
