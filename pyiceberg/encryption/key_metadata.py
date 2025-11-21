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
"""Encryption key metadata implementations."""

from __future__ import annotations

import io
from typing import Any

from pyiceberg.avro.decoder import new_decoder
from pyiceberg.avro.encoder import BinaryEncoder
from pyiceberg.avro.resolver import construct_reader, construct_writer
from pyiceberg.avro.writer import Writer
from pyiceberg.schema import Schema
from pyiceberg.types import BinaryType, LongType, NestedField

__all__ = ["StandardKeyMetadata"]


# Schema for StandardKeyMetadata V1
STANDARD_KEY_METADATA_SCHEMA_V1 = Schema(
    NestedField(field_id=0, name="encryption_key", field_type=BinaryType(), required=True),
    NestedField(field_id=1, name="aad_prefix", field_type=BinaryType(), required=False),
    NestedField(field_id=2, name="file_length", field_type=LongType(), required=False),
)


class StandardKeyMetadata:
    """Standard encryption key metadata.

    This class stores the encryption key, AAD prefix, and optional file length.
    It can be serialized to and from Avro format.
    """

    def __init__(self, encryption_key: bytes, aad_prefix: bytes, file_length: int | None = None) -> None:
        """Initialize standard key metadata.

        Args:
            encryption_key: The encryption key bytes.
            aad_prefix: The AAD (Additional Authenticated Data) prefix bytes.
            file_length: The encrypted file length in bytes (optional).
        """
        self._encryption_key = encryption_key
        self._aad_prefix = aad_prefix
        self._file_length = file_length
        self._writer: Writer | None = None

    def encryption_key(self) -> bytes:
        """Get the encryption key bytes.

        Returns:
            The encryption key as bytes.
        """
        return self._encryption_key

    def aad_prefix(self) -> bytes:
        """Get the AAD prefix bytes.

        Returns:
            The AAD prefix as bytes.
        """
        return self._aad_prefix

    def file_length(self) -> int | None:
        """Get the encrypted file length.

        Returns:
            The file length in bytes, or None if not set.
        """
        return self._file_length

    def buffer(self) -> bytes:
        """Serialize the key metadata to bytes.

        Returns:
            The serialized key metadata as bytes.
        """
        output = io.BytesIO()
        encoder = BinaryEncoder(output)

        if self._writer is None:
            self._writer = construct_writer(STANDARD_KEY_METADATA_SCHEMA_V1)

        # Create a record as a tuple (indexed by position)
        # Field 0: encryption_key
        # Field 1: aad_prefix
        # Field 2: file_length
        record = (self._encryption_key, self._aad_prefix, self._file_length)

        # Use the writer directly
        self._writer.write(encoder, record)

        return output.getvalue()

    def copy(self) -> StandardKeyMetadata:
        """Create a copy of this key metadata.

        Returns:
            A copy of this key metadata.
        """
        return StandardKeyMetadata(self._encryption_key, self._aad_prefix, self._file_length)

    def copy_with_length(self, length: int) -> StandardKeyMetadata:
        """Copy this key metadata and set the file length.

        Args:
            length: The file length in bytes.

        Returns:
            A copy of this key metadata with the file length set.
        """
        return StandardKeyMetadata(self._encryption_key, self._aad_prefix, length)

    @staticmethod
    def parse(buffer: bytes) -> StandardKeyMetadata:
        """Parse key metadata from bytes.

        Args:
            buffer: The serialized key metadata bytes.

        Returns:
            A StandardKeyMetadata instance.
        """
        decoder = new_decoder(buffer)
        reader = construct_reader(STANDARD_KEY_METADATA_SCHEMA_V1)

        record: Any = reader.read(decoder)

        # Record is a tuple with positional fields
        # Field 0: encryption_key
        # Field 1: aad_prefix
        # Field 2: file_length
        encryption_key = record[0]
        aad_prefix = record[1] if record[1] is not None else b""
        file_length = record[2] if len(record) > 2 else None

        return StandardKeyMetadata(
            encryption_key=encryption_key,
            aad_prefix=aad_prefix,
            file_length=file_length,
        )
