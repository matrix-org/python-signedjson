# -*- coding: utf-8 -*-

# Copyright 2014 OpenMarket Ltd
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

from unpaddedbase64 import encode_base64

from signedjson.sign import (
    sign_json, verify_signed_json, signature_ids, SignatureVerifyException
)


class JsonSignTestCase(unittest.TestCase):
    def setUp(self):
        self.message = {'foo': 'bar', 'unsigned': {}}
        self.sigkey = MockSigningKey()
        self.assertEqual(self.sigkey.alg, 'mock')
        self.signed = sign_json(self.message, 'Alice', self.sigkey)
        self.verkey = MockVerifyKey()

    def test_sign_and_verify(self):
        self.assertIn('signatures', self.signed)
        self.assertIn('Alice', self.signed['signatures'])
        self.assertIn('mock:test', self.signed['signatures']['Alice'])
        self.assertEqual(
            self.signed['signatures']['Alice']['mock:test'],
            encode_base64(b'x_______')
        )
        self.assertEqual(self.sigkey.signed_bytes, b'{"foo":"bar"}')
        verify_signed_json(self.signed, 'Alice', self.verkey)

    def test_signature_ids(self):
        key_ids = signature_ids(
            self.signed, 'Alice', supported_algorithms=['mock']
        )
        self.assertListEqual(key_ids, ['mock:test'])

    def test_verify_fail(self):
        self.signed['signatures']['Alice']['mock:test'] = encode_base64(
            b'not a signature'
        )
        with self.assertRaises(SignatureVerifyException):
            verify_signed_json(self.signed, 'Alice', self.verkey)

    def test_verify_fail_no_signatures(self):
        with self.assertRaises(SignatureVerifyException):
            verify_signed_json({}, 'Alice', self.verkey)

    def test_verify_fail_no_signature_for_alice(self):
        with self.assertRaises(SignatureVerifyException):
            verify_signed_json({'signatures': {}}, 'Alice', self.verkey)

    def test_verify_fail_not_base64(self):
        invalid = {'signatures': {'Alice': {'mock:test': 'not base64'}}}
        with self.assertRaises(SignatureVerifyException):
            verify_signed_json(invalid, 'Alice', self.verkey)


class MockSigningKey(object):
    alg = "mock"
    version = "test"

    def sign(self, signed_bytes):
        self.signed_bytes = signed_bytes
        return MockSignature()


class MockVerifyKey(object):
    alg = "mock"
    version = "test"

    def verify(self, message, sig):
        if not sig == b"x_______":
            raise Exception()


class MockSignature(object):
    def __init__(self):
        self.signature = b"x_______"
