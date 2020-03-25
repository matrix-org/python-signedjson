# -*- coding: utf-8 -*-

# Copyright 2014 OpenMarket Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C
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

from typing import Iterable, List, TextIO

import nacl.signing
from unpaddedbase64 import decode_base64, encode_base64

from signedjson.types import SigningKey, VerifyKey

NACL_ED25519 = "ed25519"
SUPPORTED_ALGORITHMS = [NACL_ED25519]


def generate_signing_key(version):
    # type: (str) -> SigningKey
    """Generate a new signing key
    Args:
        version: Identifies this key out the keys for this entity.
    Returns:
        A SigningKey object.
    """
    key = nacl.signing.SigningKey.generate()
    key.version = version
    key.alg = NACL_ED25519
    return key


def get_verify_key(signing_key):
    # type: (SigningKey) -> VerifyKey
    """Get a verify key from a signing key"""
    verify_key = signing_key.verify_key
    verify_key.version = signing_key.version
    verify_key.alg = signing_key.alg
    return verify_key


def decode_signing_key_base64(algorithm, version, key_base64):
    # type: (str, str, str) -> SigningKey
    """Decode a base64 encoded signing key
    Args:
        algorithm: The algorithm the key is for (currently "ed25519").
        version: Identifies this key out of the keys for this entity.
        key_base64: Base64 encoded bytes of the key.
    Returns:
        A SigningKey object.
    """
    if algorithm == NACL_ED25519:
        key_bytes = decode_base64(key_base64)
        key = nacl.signing.SigningKey(key_bytes)
        key.version = version
        key.alg = NACL_ED25519
        return key
    else:
        raise ValueError("Unsupported algorithm %s" % (algorithm,))


def encode_signing_key_base64(key):
    # type: (SigningKey) -> str
    """Encode a signing key as base64
    Args:
        key: A signing key to encode.
    Returns:
        base64 encoded string.
    """
    return encode_base64(key.encode())


def encode_verify_key_base64(key):
    # type: (VerifyKey) -> str
    """Encode a verify key as base64
    Args:
        key: A signing key to encode.
    Returns:
        base64 encoded string.
    """
    return encode_base64(key.encode())


def is_signing_algorithm_supported(key_id):
    # type: (str) -> bool
    """Is the signing algorithm for this key_id supported"""
    if key_id.startswith(NACL_ED25519 + ":"):
        return True
    else:
        return False


def decode_verify_key_base64(algorithm, version, key_base64):
    # type: (str, str, str) -> VerifyKey
    """Decode a base64 encoded verify key
    Args:
        algorithm (str): The algorithm the key is for (currently "ed25519").
        version (str): Identifies this key out of the keys for this entity.
        key_base64 (str): Base64 encoded bytes of the key.
    Returns:
        A VerifyKey object.
    """
    key_id = "%s:%s" % (algorithm, version)
    key_bytes = decode_base64(key_base64)
    return decode_verify_key_bytes(key_id, key_bytes)


def decode_verify_key_bytes(key_id, key_bytes):
    # type: (str, bytes) -> VerifyKey
    """Decode a raw verify key
    Args:
        key_id: Identifies this key out of the keys for this entity.
        key_bytes: Raw bytes of the key.
    Returns:
        A VerifyKey object.
    """
    if key_id.startswith(NACL_ED25519 + ":"):
        version = key_id[len(NACL_ED25519) + 1:]
        key = nacl.signing.VerifyKey(key_bytes)
        key.version = version
        key.alg = NACL_ED25519
        return key
    else:
        raise ValueError("Unsupported algorithm %r" % (key_id,))


def read_signing_keys(stream):
    # type: (Iterable[str]) -> List[SigningKey]
    """Reads a list of keys from a stream
    Args:
        stream : A stream to iterate for keys.
    Returns:
        list of SigningKey objects.
    """
    keys = []
    for line in stream:
        algorithm, version, key_base64 = line.split()
        key = decode_signing_key_base64(algorithm, version, key_base64)
        keys.append(key)
    return keys


def read_old_signing_keys(stream):
    # type: (Iterable[str]) -> List[VerifyKey]
    """Reads a list of old keys from a stream
    Args:
        stream : A stream to iterate for keys.
    Returns:
        list of VerifyKey objects.
    """
    keys = []
    for line in stream:
        algorithm, version, expired, key_base64 = line.split()
        key = decode_verify_key_base64(algorithm, version, key_base64)
        key.expired = int(expired)
        keys.append(key)
    return keys


def write_signing_keys(stream, keys):
    # type: (TextIO, Iterable[SigningKey]) -> None
    """Writes a list of keys to a stream.
    Args:
        stream: Stream to write keys to.
        keys: List of SigningKey objects.
    """
    for key in keys:
        key_base64 = encode_signing_key_base64(key)
        stream.write("%s %s %s\n" % (key.alg, key.version, key_base64,))
