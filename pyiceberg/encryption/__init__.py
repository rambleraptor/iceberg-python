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
"""Encryption support for Apache Iceberg."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pyiceberg.io import InputFile, OutputFile

__all__ = ["EncryptionManager", "PlaintextEncryptionManager"]


class EncryptionManager(ABC):
    """Abstract base class for encryption managers.

    An EncryptionManager is responsible for encrypting and decrypting files
    in an Iceberg table, including data files, manifest files, and manifest lists.
    """

    @abstractmethod
    def encrypt(self, output_file: OutputFile) -> EncryptedOutputFile:
        """Encrypt an output file.

        Args:
            output_file: The output file to encrypt.

        Returns:
            An encrypted output file wrapper.
        """
        ...

    @abstractmethod
    def decrypt(self, input_file: InputFile) -> InputFile:
        """Decrypt an input file.

        Args:
            input_file: The encrypted input file.

        Returns:
            A decrypted input file.
        """
        ...


class EncryptedOutputFile(Protocol):
    """Protocol for encrypted output files."""

    def encrypting_output_file(self) -> OutputFile:
        """Get the encrypting output file.

        Returns:
            The output file that will write encrypted data.
        """
        ...

    def key_metadata(self) -> EncryptionKeyMetadata | None:
        """Get the encryption key metadata.

        Returns:
            The encryption key metadata, or None if not encrypted.
        """
        ...


class EncryptionKeyMetadata(Protocol):
    """Protocol for encryption key metadata."""

    def buffer(self) -> bytes:
        """Get the serialized key metadata as bytes.

        Returns:
            The serialized key metadata.
        """
        ...

    def copy(self) -> EncryptionKeyMetadata:
        """Create a copy of this key metadata.

        Returns:
            A copy of this key metadata.
        """
        ...


class NativeEncryptionKeyMetadata(EncryptionKeyMetadata, Protocol):
    """Protocol for native encryption key metadata.

    Native encryption stores the encryption key and AAD prefix directly
    in the key metadata (after wrapping with a key encryption key).
    """

    def encryption_key(self) -> bytes:
        """Get the encryption key bytes.

        Returns:
            The encryption key as bytes.
        """
        ...

    def aad_prefix(self) -> bytes:
        """Get the AAD (Additional Authenticated Data) prefix.

        Returns:
            The AAD prefix as bytes.
        """
        ...

    def file_length(self) -> int | None:
        """Get the encrypted file length.

        Returns:
            The file length in bytes, or None if not set.
        """
        ...

    def copy_with_length(self, length: int) -> NativeEncryptionKeyMetadata:
        """Copy this key metadata and set the file length.

        Args:
            length: The file length in bytes.

        Returns:
            A copy of this key metadata with the file length set.
        """
        ...


class PlaintextEncryptionManager(EncryptionManager):
    """An encryption manager that does not perform any encryption.

    This is the default encryption manager when no encryption is configured.
    """

    _instance: PlaintextEncryptionManager | None = None

    def __new__(cls) -> PlaintextEncryptionManager:
        """Create a singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def instance(cls) -> PlaintextEncryptionManager:
        """Get the singleton instance.

        Returns:
            The singleton PlaintextEncryptionManager instance.
        """
        return cls()

    def encrypt(self, output_file: OutputFile) -> EncryptedOutputFile:
        """Return an unencrypted output file.

        Args:
            output_file: The output file.

        Returns:
            An EncryptedOutputFile wrapper with no encryption.
        """
        from pyiceberg.encryption.plaintext import PlaintextEncryptedOutputFile

        return PlaintextEncryptedOutputFile(output_file)

    def decrypt(self, input_file: InputFile) -> InputFile:
        """Return the input file unchanged.

        Args:
            input_file: The input file.

        Returns:
            The same input file (no decryption needed).
        """
        return input_file
