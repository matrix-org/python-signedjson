#!/usr/bin/env python

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

from setuptools import setup
from codecs import open
import os

here = os.path.abspath(os.path.dirname(__file__))


def read_file(path_segments):
    """Read a UTF-8 file from the package. Takes a list of strings to join to
    make the path"""
    file_path = os.path.join(here, *path_segments)
    with open(file_path, encoding="utf-8") as f:
        return f.read()


setup(
    name="signedjson",
    packages=["signedjson"],
    description="Sign JSON with Ed25519 signatures",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    install_requires=[
        "canonicaljson>=1.0.0",
        "unpaddedbase64>=1.0.1",
        "pynacl>=0.3.0",
        "typing_extensions>=3.5",
        'typing>=3.5;python_version<"3.5"',
        "importlib_metadata",
    ],
    long_description=read_file(("README.rst",)),
    keywords="json",
)
