Signed JSON
===========

.. image:: https://img.shields.io/pypi/v/signedjson.svg
    :target: https://pypi.python.org/pypi/signedjson/
    :alt: Latest Version

.. image:: https://img.shields.io/travis/matrix-org/python-signedjson.svg
   :target: https://travis-ci.org/matrix-org/python-signedjson


Signs JSON objects with ED25519 signatures.


Features
--------

* More than one entity can sign the same object.
* Each entity can sign the object with more than one key making it easier to
  rotate keys
* ED25519 can be replaced with a different algorithm.
* Unprotected data can be added to the object under the ``"unsigned"`` key.


Installing
----------

.. code:: bash

   pip install signedjson

Using
-----

.. code:: python

    from signedjson.key import generate_signing_key, get_verify_key
    from signedjson.sign import (
        sign_json, verify_signed_json, SignatureVerifyException
    )

    signing_key = generate_signing_key('zxcvb')
    signed_json = sign_json({'my_key': 'my_data'}, 'Alice', signing_key)

    verify_key = get_verify_key(signing_key)

    try:
        verify_signed_json(signed_json, 'Alice', verify_key)
        print 'Signature is valid'
    except SignatureVerifyException:
        print 'Signature is invalid'

Format
------

.. code:: json

    {
        "<protected_name>": "<protected_value>",
        "signatures": {
            "<entity_name>": {
                "ed25519:<key_id>": "<unpadded_base64_signature>"
            }
        },
        "unsigned": {
            "<unprotected_name>": "<unprotected_value>",
        }
    }



