import unittest

from signedjson.key import (
    decode_signing_key_base64,
    decode_verify_key_base64,
    decode_verify_key_bytes,
    encode_signing_key_base64,
    encode_verify_key_base64,
    generate_signing_key,
    get_verify_key,
    is_signing_algorithm_supported,
    read_old_signing_keys,
    read_signing_keys,
    write_signing_keys,
)


class GenerateTestCase(unittest.TestCase):
    def test_generate_key(self):
        my_version = "my_version"
        my_key = generate_signing_key(my_version)
        self.assertEquals(my_key.alg, "ed25519")
        self.assertEquals(my_key.version, my_version)


class DecodeTestCase(unittest.TestCase):
    def setUp(self):
        self.version = "my_version"
        self.key = generate_signing_key(self.version)
        self.key_base64 = encode_signing_key_base64(self.key)
        self.verify_key = get_verify_key(self.key)
        self.verify_key_base64 = encode_verify_key_base64(self.verify_key)

    def test_decode(self):
        decoded_key = decode_signing_key_base64(
            "ed25519", self.version, self.key_base64
        )
        self.assertEquals(decoded_key.alg, "ed25519")
        self.assertEquals(decoded_key.version, self.version)

    def test_decode_invalid_base64(self):
        with self.assertRaises(Exception):
            decode_signing_key_base64("ed25519", self.version, "not base 64")

    def test_decode_signing_invalid_algorithm(self):
        with self.assertRaises(Exception):
            decode_signing_key_base64("not a valid alg", self.version, "")

    def test_decode_invalid_key(self):
        with self.assertRaises(Exception):
            decode_signing_key_base64("ed25519", self.version, "")

    def test_decode_verify_key(self):
        decoded_key = decode_verify_key_base64(
            "ed25519", self.version, self.verify_key_base64
        )
        self.assertEquals(decoded_key.alg, "ed25519")
        self.assertEquals(decoded_key.version, self.version)

    def test_decode_verify_key_invalid_base64(self):
        with self.assertRaises(Exception):
            decode_verify_key_base64("ed25519", self.version, "not base 64")

    def test_decode_verify_key_invalid_algorithm(self):
        with self.assertRaises(Exception):
            decode_verify_key_base64("not a valid alg", self.version, "")

    def test_decode_verify_key_invalid_key(self):
        with self.assertRaises(Exception):
            decode_verify_key_base64("ed25519", self.version, "")

    def test_read_keys(self):
        stream = ["ed25519 %s %s" % (self.version, self.key_base64)]
        keys = read_signing_keys(stream)
        self.assertEquals(len(keys), 1)

    def test_read_old_keys(self):
        stream = ["ed25519 %s 0 %s" % (self.version, self.verify_key_base64)]
        keys = read_old_signing_keys(stream)
        self.assertEquals(len(keys), 1)

    def test_decode_verify_invalid_algorithm(self):
        with self.assertRaises(Exception):
            decode_verify_key_bytes("not a valid alg", self.verify_key)

    def test_write_signing_keys(self):
        class MockStream(object):
            def write(self, data):
                pass

        write_signing_keys(MockStream(), [self.key])


class AlgorithmSupportedTestCase(unittest.TestCase):
    def test_ed25519(self):
        self.assertTrue(is_signing_algorithm_supported("ed25519:an_id"))

    def test_unsupported(self):
        self.assertFalse(is_signing_algorithm_supported("unsupported:"))
