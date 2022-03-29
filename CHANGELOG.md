Signedjson 1.1.2 (2022-03-29)
=============================

Bugfixes
--------

- Do not require `importlib_metadata` on Python 3.8 and above. ([\#9](https://github.com/matrix-org/python-signedjson/issues/9))


Internal Changes
----------------

- Configure @matrix-org/synapse-core to be the code owner for the repository. ([\#11](https://github.com/matrix-org/python-signedjson/issues/11))
- Use `assertEqual` for Python 3.11. By @hugovk. ([\#17](https://github.com/matrix-org/python-signedjson/pull/17))
- Run linters (flake8, mypy, black, isort). ([\#20](https://github.com/matrix-org/python-signedjson/pull/20))
- Mark the package as containing type hints. ([\#20](https://github.com/matrix-org/python-signedjson/pull/20))


Signedjson 1.1.1 (2020-03-27)
=============================

Bugfixes
--------

- Fix incorrect typing annotation for `decode_signing_key_base64`. ([\#5](https://github.com/matrix-org/python-signedjson/issues/5))
- Reinstate `decode_verify_key_base64` function which was erroneously removed in 1.1.0. ([\#6](https://github.com/matrix-org/python-signedjson/issues/6))


Internal Changes
----------------

- Use `setuptools_scm` for the version number. ([\#7](https://github.com/matrix-org/python-signedjson/issues/7))
