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
import os
from types import TracebackType
from typing import cast

import pytest
from cryptography.exceptions import InvalidTag

from pyiceberg.encryption import (
    BaseEncryptedInputFile,
    NativeEncryptionOutputFile,
    StandardEncryptionManager,
    StandardKeyMetadata,
)
from pyiceberg.io import InputFile, InputStream, OutputFile, OutputStream


class InMemoryOutputFile(OutputFile):
    _buffer: bytearray

    def __init__(self, location: str):
        super().__init__(location)
        self._buffer = bytearray()

    def create(self, overwrite: bool = False) -> OutputStream:
        return self._InMemoryOutputStream(self._buffer)

    def to_input_file(self) -> InputFile:
        return InMemoryInputFile(self.location, bytes(self._buffer))

    def exists(self) -> bool:
        return True

    def __len__(self) -> int:
        return len(self._buffer)

    class _InMemoryOutputStream(OutputStream):
        _buffer: bytearray
        _closed: bool

        def __init__(self, buffer: bytearray):
            self._buffer = buffer
            self._closed = False

        def write(self, b: bytes) -> int:
            self._buffer.extend(b)
            return len(b)

        def close(self) -> None:
            self._closed = True

        def __enter__(self) -> OutputStream:
            return self

        def __exit__(
            self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None
        ) -> None:
            self.close()


class InMemoryInputFile(InputFile):
    _content: bytes

    def __init__(self, location: str, content: bytes):
        super().__init__(location)
        self._content = content

    def open(self, seekable: bool = True) -> InputStream:
        return self._InMemoryInputStream(self._content)

    def exists(self) -> bool:
        return True

    def __len__(self) -> int:
        return len(self._content)

    class _InMemoryInputStream(InputStream):
        _content: bytes
        _pos: int

        def __init__(self, content: bytes):
            self._content = content
            self._pos = 0

        def read(self, size: int = -1) -> bytes:
            if size == -1:
                data = self._content[self._pos :]
                self._pos = len(self._content)
                return data
            else:
                data = self._content[self._pos : self._pos + size]
                self._pos += size
                return data

        def seek(self, offset: int, whence: int = 0) -> int:
            if whence == 0:
                self._pos = offset
            elif whence == 1:
                self._pos += offset
            elif whence == 2:
                self._pos = len(self._content) + offset
            return self._pos

        def tell(self) -> int:
            return self._pos

        def close(self) -> None:
            pass

        def __enter__(self) -> InputStream:
            return self

        def __exit__(
            self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None
        ) -> None:
            self.close()


def test_encryption_round_trip() -> None:
    # Setup
    output_file = InMemoryOutputFile("memory://test.enc")
    em = StandardEncryptionManager("key_id", 16)

    # Encrypt
    encrypted_output = em.encrypt(output_file)
    with encrypted_output.create() as out:
        out.write(b"Hello, World!")

    # Verify underlying file has content (nonce + ciphertext)
    # 12 bytes nonce + 13 bytes plaintext + 16 bytes tag = 41 bytes
    assert len(output_file._buffer) == 12 + 13 + 16

    # Decrypt
    # We need to reconstruct the input file with the key metadata
    # In a real scenario, this metadata comes from the manifest list
    # Here we can grab it from the encrypted_output object since we just created it
    encrypted_file = cast(NativeEncryptionOutputFile, encrypted_output)
    key_metadata = encrypted_file._key_metadata

    input_file = output_file.to_input_file()
    encrypted_input = BaseEncryptedInputFile(input_file, key_metadata)

    decrypted_input = em.decrypt(encrypted_input)

    with decrypted_input.open() as inp:
        content = inp.read()
        assert content == b"Hello, World!"


def test_encryption_invalid_key() -> None:
    output_file = InMemoryOutputFile("memory://test.enc")
    em = StandardEncryptionManager("key_id", 16)

    # Encrypt
    encrypted_output = em.encrypt(output_file)
    with encrypted_output.create() as out:
        out.write(b"Secret Data")

    # Try to decrypt with WRONG key
    wrong_key = os.urandom(16)  # AES-128
    encrypted_file = cast(NativeEncryptionOutputFile, encrypted_output)
    wrong_metadata = StandardKeyMetadata(wrong_key, encrypted_file._key_metadata.aad_prefix())

    input_file = output_file.to_input_file()
    encrypted_input = BaseEncryptedInputFile(input_file, wrong_metadata)

    # Decrypting should fail (tag mismatch)
    decrypted_input = em.decrypt(encrypted_input)

    with pytest.raises(InvalidTag):  # Cryptography raises InvalidTag
        with decrypted_input.open() as inp:
            inp.read()
