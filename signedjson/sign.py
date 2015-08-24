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

from canonicaljson import encode_canonical_json
from unpaddedbase64 import encode_base64, decode_base64
from signedjson.key import SUPPORTED_ALGORITHMS

import logging

logger = logging.getLogger(__name__)


def sign_json(json_object, signature_name, signing_key):
    """Sign the JSON object. Stores the signature in json_object["signatures"].

    Args:
        json_object (dict): The JSON object to sign.
        signature_name (str): The name of the signing entity.
        signing_key (syutil.crypto.SigningKey): The key to sign the JSON with.

    Returns:
        The modified, signed JSON object."""

    signatures = json_object.pop("signatures", {})
    unsigned = json_object.pop("unsigned", None)

    message_bytes = encode_canonical_json(json_object)
    signed = signing_key.sign(message_bytes)
    signature_base64 = encode_base64(signed.signature)

    key_id = "%s:%s" % (signing_key.alg, signing_key.version)
    signatures.setdefault(signature_name, {})[key_id] = signature_base64

    # logger.debug("SIGNING: %s %s %s", signature_name, key_id, message_bytes)

    json_object["signatures"] = signatures
    if unsigned is not None:
        json_object["unsigned"] = unsigned

    return json_object


def signature_ids(json_object, signature_name,
                  supported_algorithms=SUPPORTED_ALGORITHMS):
    """Does the JSON object have a signature for the given name?
    Args:
        json_object (dict): The JSON object to check.
        signature_name (str): The name of the signing entity to check for
        supported_algorithms (list of str): List of supported signature
            algorithms
    Returns:
        list of key identifier strings.
    """
    key_ids = json_object.get("signatures", {}).get(signature_name, {}).keys()
    return list(
        key_id for key_id in key_ids
        if key_id.split(":")[0] in supported_algorithms
    )


class SignatureVerifyException(Exception):
    """A signature could not be verified"""
    pass


def verify_signed_json(json_object, signature_name, verify_key):
    """Check a signature on a signed JSON object.

    Args:
        json_object (dict): The signed JSON object to check.
        signature_name (str): The name of the signature to check.
        verify_key (syutil.crypto.VerifyKey): The key to verify the signature.

    Raises:
        InvalidSignature: If the signature isn't valid
    """

    try:
        signatures = json_object["signatures"]
    except KeyError:
        raise SignatureVerifyException("No signatures on this object")

    key_id = "%s:%s" % (verify_key.alg, verify_key.version)

    try:
        signature_b64 = signatures[signature_name][key_id]
    except:
        raise SignatureVerifyException(
            "Missing signature for %s, %s" % (signature_name, key_id)
        )

    try:
        signature = decode_base64(signature_b64)
    except:
        raise SignatureVerifyException(
            "Invalid signature base64 for %s, %s" % (signature_name, key_id)
        )

    json_object_copy = dict(json_object)
    del json_object_copy["signatures"]
    json_object_copy.pop("unsigned", None)

    message = encode_canonical_json(json_object_copy)

    # logger.debug("VERIFY: %s %s %s", signature_name, key_id, message)

    try:
        verify_key.verify(message, signature)
    except:
        logger.exception("Error verifying signature")
        raise SignatureVerifyException(
            "Unable to verify signature for %s " % signature_name
        )
