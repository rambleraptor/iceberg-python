# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Plaintext (no-op) encryption implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyiceberg.encryption import EncryptionKeyMetadata
    from pyiceberg.io import OutputFile


class PlaintextEncryptedOutputFile:
    """An encrypted output file that performs no encryption."""

    def __init__(self, output_file: OutputFile) -> None:
        """Initialize a plaintext encrypted output file.

        Args:
            output_file: The output file to wrap.
        """
        self._output_file = output_file

    def encrypting_output_file(self) -> OutputFile:
        """Get the output file.

        Returns:
            The wrapped output file (no encryption applied).
        """
        return self._output_file

    def key_metadata(self) -> EncryptionKeyMetadata | None:
        """Get the encryption key metadata.

        Returns:
            None (no encryption).
        """
        return None
