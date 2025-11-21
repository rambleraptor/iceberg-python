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
"""Encryption utility functions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyiceberg.encryption.ciphers import AesGcmDecryptor, AesGcmEncryptor
from pyiceberg.encryption.key_metadata import StandardKeyMetadata

if TYPE_CHECKING:
    from pyiceberg.encryption import EncryptionManager
    from pyiceberg.encryption.standard_encryption import StandardEncryptionManager
    from pyiceberg.manifest import ManifestListFile

__all__ = ["decrypt_manifest_list_key_metadata", "encrypt_manifest_list_key_metadata"]


def decrypt_manifest_list_key_metadata(manifest_list: ManifestListFile, encryption_manager: EncryptionManager) -> bytes:
    """Decrypt the key metadata for a manifest list.

    Args:
        manifest_list: A ManifestListFile.
        encryption_manager: The table's EncryptionManager.

    Returns:
        Decrypted key metadata bytes.

    Raises:
        ValueError: If the encryption manager is not a StandardEncryptionManager.
    """
    from pyiceberg.encryption.standard_encryption import StandardEncryptionManager

    if not isinstance(encryption_manager, StandardEncryptionManager):
        raise ValueError("Manifest list key metadata encryption requires a StandardEncryptionManager")

    manifest_list_key_id = manifest_list.encryption_key_id
    if manifest_list_key_id is None:
        raise ValueError("Manifest list has no encryption key ID")

    # Get the key encryption key
    key_encryption_key = encryption_manager.get_encrypted_by_key(manifest_list_key_id)

    # Get the encrypted key metadata
    encrypted_key_metadata = encryption_manager.get_encrypted_key_metadata(manifest_list_key_id)

    # Decrypt the key metadata
    decryptor = AesGcmDecryptor(key_encryption_key)
    decrypted_key_metadata = decryptor.decrypt(encrypted_key_metadata, manifest_list_key_id.encode("utf-8"))

    return decrypted_key_metadata


def encrypt_manifest_list_key_metadata(key: bytes, key_id: str, key_metadata: StandardKeyMetadata) -> bytes:
    """Encrypt the key metadata for a manifest list.

    Args:
        key: Key encryption key bytes.
        key_id: ID of the manifest list key.
        key_metadata: Manifest list key metadata.

    Returns:
        Encrypted key metadata bytes.
    """
    encryptor = AesGcmEncryptor(key)
    key_metadata_bytes = key_metadata.buffer()
    encrypted_key_metadata = encryptor.encrypt(key_metadata_bytes, key_id.encode("utf-8"))
    return encrypted_key_metadata
