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
"""Standard encryption manager implementation."""

from __future__ import annotations

import base64
import os
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pyiceberg.encryption import EncryptionManager
from pyiceberg.encryption.ciphers import AesGcmDecryptor, AesGcmEncryptor
from pyiceberg.encryption.key_metadata import StandardKeyMetadata

if TYPE_CHECKING:
    from pyiceberg.encryption import EncryptedOutputFile
    from pyiceberg.io import InputFile, OutputFile

__all__ = ["StandardEncryptionManager", "NativeEncryptionOutputFile"]


# Constant for the key encryption key ID
KEY_ENCRYPTION_KEY_ID = "KEY_ENCRYPTION_KEY_ID"

# Default key length (256 bits = 32 bytes for AES-256)
DEFAULT_DATA_KEY_LENGTH = 32

# Cache expiration time (1 hour)
CACHE_EXPIRATION_SECONDS = 3600


@dataclass
class EncryptedKey:
    """Represents an encrypted key with metadata."""

    key_id: str
    encrypted_key_metadata: bytes
    encrypted_by_id: str
    unwrapped_key: bytes | None = None


@dataclass
class CachedKey:
    """A cached unwrapped key with expiration time."""

    key: bytes
    expiration: float


class StandardEncryptionManager(EncryptionManager):
    """Standard encryption manager with key encryption key management.

    This encryption manager uses a key encryption key (KEK) to wrap and unwrap
    data encryption keys (DEK). The DEKs are used to encrypt manifest lists and
    other Iceberg files.
    """

    def __init__(self, table_key_id: str | None = None, data_key_length: int = DEFAULT_DATA_KEY_LENGTH) -> None:
        """Initialize the standard encryption manager.

        Args:
            table_key_id: Optional table key ID for key management.
            data_key_length: Length of data encryption keys in bytes (default: 32 for AES-256).
        """
        self._table_key_id = table_key_id or "default-table-key"
        self._data_key_length = data_key_length

        # Transient state (not serialized)
        self._encryption_keys: dict[str, EncryptedKey] = {}
        self._unwrapped_key_cache: dict[str, CachedKey] = {}

    def _generate_key_id(self) -> str:
        """Generate a random key ID.

        Returns:
            A base64-encoded random key ID.
        """
        random_bytes = secrets.token_bytes(16)
        return base64.b64encode(random_bytes).decode("utf-8")

    def _new_key(self) -> bytes:
        """Generate a new random encryption key.

        Returns:
            A random key of the configured length.
        """
        return secrets.token_bytes(self._data_key_length)

    def _get_key_encryption_key_id(self) -> str:
        """Get or create the key encryption key.

        Returns:
            The key encryption key ID.
        """
        if KEY_ENCRYPTION_KEY_ID not in self._encryption_keys:
            unwrapped = self._new_key()
            # For simplicity, we store the KEK unwrapped (in real implementation, this would be wrapped by KMS)
            key = EncryptedKey(
                key_id=KEY_ENCRYPTION_KEY_ID,
                encrypted_key_metadata=unwrapped,  # In real KMS, this would be wrapped
                encrypted_by_id=self._table_key_id,
                unwrapped_key=unwrapped,
            )

            # Cache the key
            self._unwrapped_key_cache[KEY_ENCRYPTION_KEY_ID] = CachedKey(
                key=unwrapped, expiration=time.time() + CACHE_EXPIRATION_SECONDS
            )
            self._encryption_keys[KEY_ENCRYPTION_KEY_ID] = key

        return KEY_ENCRYPTION_KEY_ID

    def _get_unwrapped_key(self, key_id: str) -> bytes:
        """Get an unwrapped key from the cache or decrypt it.

        Args:
            key_id: The key ID to retrieve.

        Returns:
            The unwrapped key bytes.

        Raises:
            ValueError: If the key is not found.
        """
        # Check cache first
        if key_id in self._unwrapped_key_cache:
            cached = self._unwrapped_key_cache[key_id]
            if time.time() < cached.expiration:
                return cached.key
            else:
                # Cache expired, remove it
                del self._unwrapped_key_cache[key_id]

        # Get from encryption keys
        if key_id not in self._encryption_keys:
            raise ValueError(f"Key not found: {key_id}")

        encrypted_key = self._encryption_keys[key_id]

        # If already unwrapped, cache and return
        if encrypted_key.unwrapped_key is not None:
            self._unwrapped_key_cache[key_id] = CachedKey(
                key=encrypted_key.unwrapped_key, expiration=time.time() + CACHE_EXPIRATION_SECONDS
            )
            return encrypted_key.unwrapped_key

        # For KEK, it's stored unwrapped in encrypted_key_metadata
        if key_id == KEY_ENCRYPTION_KEY_ID:
            unwrapped = encrypted_key.encrypted_key_metadata
            self._unwrapped_key_cache[key_id] = CachedKey(
                key=unwrapped, expiration=time.time() + CACHE_EXPIRATION_SECONDS
            )
            return unwrapped

        # For other keys, we need to decrypt using the KEK
        kek = self._get_unwrapped_key(encrypted_key.encrypted_by_id)
        decryptor = AesGcmDecryptor(kek)
        unwrapped = decryptor.decrypt(encrypted_key.encrypted_key_metadata, key_id.encode("utf-8"))

        # Cache the unwrapped key
        self._unwrapped_key_cache[key_id] = CachedKey(key=unwrapped, expiration=time.time() + CACHE_EXPIRATION_SECONDS)

        return unwrapped

    def encrypt(self, output_file: OutputFile) -> EncryptedOutputFile:
        """Encrypt an output file.

        Args:
            output_file: The output file to encrypt.

        Returns:
            An encrypted output file wrapper with key metadata.
        """
        # Generate a new data encryption key
        dek = self._new_key()

        # Generate AAD prefix (random bytes)
        aad_prefix = secrets.token_bytes(16)

        # Create key metadata
        key_metadata = StandardKeyMetadata(encryption_key=dek, aad_prefix=aad_prefix)

        return NativeEncryptionOutputFile(output_file, key_metadata)

    def decrypt(self, input_file: InputFile) -> InputFile:
        """Decrypt an input file.

        Args:
            input_file: The encrypted input file.

        Returns:
            A decrypted input file.
        """
        # For now, return the input file as-is
        # In a full implementation, this would wrap the input file with decryption
        return input_file

    def add_manifest_list_key_metadata(self, key_metadata: StandardKeyMetadata) -> str:
        """Add manifest list key metadata and return a key ID.

        This method encrypts the manifest list key metadata using the key encryption key (KEK)
        and stores it with a generated key ID.

        Args:
            key_metadata: The manifest list key metadata to encrypt and store.

        Returns:
            The generated key ID for the encrypted manifest list key metadata.
        """
        # Generate a unique key ID
        manifest_list_key_id = self._generate_key_id()

        # Get the KEK
        kek_id = self._get_key_encryption_key_id()
        kek = self._get_unwrapped_key(kek_id)

        # Encrypt the key metadata using the KEK
        encryptor = AesGcmEncryptor(kek)
        key_metadata_bytes = key_metadata.buffer()
        encrypted_key_metadata = encryptor.encrypt(key_metadata_bytes, manifest_list_key_id.encode("utf-8"))

        # Store the encrypted key
        encrypted_key = EncryptedKey(
            key_id=manifest_list_key_id,
            encrypted_key_metadata=encrypted_key_metadata,
            encrypted_by_id=kek_id,
            unwrapped_key=None,
        )

        self._encryption_keys[manifest_list_key_id] = encrypted_key

        return manifest_list_key_id

    def get_encrypted_by_key(self, manifest_list_key_id: str) -> bytes:
        """Get the key that encrypted the manifest list key metadata.

        Args:
            manifest_list_key_id: The manifest list key ID.

        Returns:
            The key encryption key (KEK) bytes.

        Raises:
            ValueError: If the manifest list key is not found.
        """
        if manifest_list_key_id not in self._encryption_keys:
            raise ValueError(f"Manifest list key metadata not found: {manifest_list_key_id}")

        encrypted_key = self._encryption_keys[manifest_list_key_id]
        return self._get_unwrapped_key(encrypted_key.encrypted_by_id)

    def get_encrypted_key_metadata(self, manifest_list_key_id: str) -> bytes:
        """Get the encrypted key metadata for a manifest list.

        Args:
            manifest_list_key_id: The manifest list key ID.

        Returns:
            The encrypted key metadata bytes.

        Raises:
            ValueError: If the manifest list key is not found.
        """
        if manifest_list_key_id not in self._encryption_keys:
            raise ValueError(f"Manifest list key metadata not found: {manifest_list_key_id}")

        return self._encryption_keys[manifest_list_key_id].encrypted_key_metadata


class NativeEncryptionOutputFile:
    """An encrypted output file that uses native encryption."""

    def __init__(self, output_file: OutputFile, key_metadata: StandardKeyMetadata) -> None:
        """Initialize a native encryption output file.

        Args:
            output_file: The output file to encrypt.
            key_metadata: The encryption key metadata.
        """
        self._output_file = output_file
        self._key_metadata = key_metadata

    def encrypting_output_file(self) -> OutputFile:
        """Get the encrypting output file.

        Returns:
            The output file (encryption is applied when writing).
        """
        return self._output_file

    def key_metadata(self) -> StandardKeyMetadata:
        """Get the encryption key metadata.

        Returns:
            The encryption key metadata.
        """
        return self._key_metadata
