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
"""Cipher implementations for encryption."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = ["AesGcmEncryptor", "AesGcmDecryptor"]


class AesGcmEncryptor:
    """AES-GCM encryptor for encrypting data."""

    # AES-GCM nonce (IV) size in bytes
    NONCE_SIZE = 12
    # AES-GCM authentication tag size in bytes
    TAG_SIZE = 16

    def __init__(self, key: bytes) -> None:
        """Initialize an AES-GCM encryptor.

        Args:
            key: The encryption key bytes (16, 24, or 32 bytes for AES-128, AES-192, or AES-256).
        """
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Invalid key length: {len(key)}. Must be 16, 24, or 32 bytes.")
        self._cipher = AESGCM(key)

    def encrypt(self, plaintext: bytes, aad: bytes | None = None) -> bytes:
        """Encrypt plaintext using AES-GCM.

        Args:
            plaintext: The data to encrypt.
            aad: Additional authenticated data (optional).

        Returns:
            The encrypted data (nonce + ciphertext + tag).
        """
        # Generate a random nonce
        nonce = os.urandom(self.NONCE_SIZE)

        # Encrypt the plaintext
        ciphertext = self._cipher.encrypt(nonce, plaintext, aad)

        # Return nonce + ciphertext (ciphertext already includes the auth tag)
        return nonce + ciphertext


class AesGcmDecryptor:
    """AES-GCM decryptor for decrypting data."""

    # AES-GCM nonce (IV) size in bytes
    NONCE_SIZE = 12
    # AES-GCM authentication tag size in bytes
    TAG_SIZE = 16

    def __init__(self, key: bytes) -> None:
        """Initialize an AES-GCM decryptor.

        Args:
            key: The encryption key bytes (16, 24, or 32 bytes for AES-128, AES-192, or AES-256).
        """
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Invalid key length: {len(key)}. Must be 16, 24, or 32 bytes.")
        self._cipher = AESGCM(key)

    def decrypt(self, ciphertext: bytes, aad: bytes | None = None) -> bytes:
        """Decrypt ciphertext using AES-GCM.

        Args:
            ciphertext: The encrypted data (nonce + ciphertext + tag).
            aad: Additional authenticated data (optional, must match encryption).

        Returns:
            The decrypted plaintext.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails.
        """
        # Extract nonce and ciphertext
        nonce = ciphertext[: self.NONCE_SIZE]
        encrypted_data = ciphertext[self.NONCE_SIZE :]

        # Decrypt and verify
        plaintext = self._cipher.decrypt(nonce, encrypted_data, aad)

        return plaintext
