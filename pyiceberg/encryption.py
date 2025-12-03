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
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from types import TracebackType
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pyiceberg.io import FileIO, InputFile, InputStream, OutputFile, OutputStream

if TYPE_CHECKING:
    from pyiceberg.manifest import ManifestListFile


class EncryptedInputFile(ABC):
    @property
    @abstractmethod
    def encrypted_input_file(self) -> InputFile: ...

    @property
    @abstractmethod
    def key_metadata(self) -> NativeEncryptionKeyMetadata: ...


class BaseEncryptedInputFile(EncryptedInputFile):
    _encrypted_input_file: InputFile
    _key_metadata: NativeEncryptionKeyMetadata

    def __init__(self, encrypted_input_file: InputFile, key_metadata: NativeEncryptionKeyMetadata):
        self._encrypted_input_file = encrypted_input_file
        self._key_metadata = key_metadata

    @property
    def encrypted_input_file(self) -> InputFile:
        return self._encrypted_input_file

    @property
    def key_metadata(self) -> NativeEncryptionKeyMetadata:
        return self._key_metadata


class EncryptionManager(ABC):
    @abstractmethod
    def decrypt(self, file: EncryptedInputFile) -> InputFile: ...

    @abstractmethod
    def encrypt(self, file: OutputFile) -> OutputFile: ...


class PlaintextEncryptionManager(EncryptionManager):
    def decrypt(self, file: EncryptedInputFile) -> InputFile:
        return file.encrypted_input_file

    def encrypt(self, file: OutputFile) -> OutputFile:
        return file


class EncryptionKeyMetadata(ABC):
    @abstractmethod
    def buffer(self) -> bytes: ...

    @abstractmethod
    def copy(self) -> EncryptionKeyMetadata: ...


class NativeEncryptionKeyMetadata(EncryptionKeyMetadata):
    @abstractmethod
    def encryption_key(self) -> bytes: ...

    @abstractmethod
    def aad_prefix(self) -> bytes: ...

    @abstractmethod
    def file_length(self) -> int | None: ...

    @abstractmethod
    def copy_with_length(self, length: int) -> NativeEncryptionKeyMetadata: ...


class NativeEncryptionOutputFile(OutputFile):
    _output_file: OutputFile
    _key_metadata: NativeEncryptionKeyMetadata

    def __init__(self, output_file: OutputFile, key_metadata: NativeEncryptionKeyMetadata):
        self._output_file = output_file
        self._key_metadata = key_metadata
        super().__init__(output_file.location)

    def __len__(self) -> int:
        """Length of the output file."""
        return len(self._output_file)

    def exists(self) -> bool:
        return self._output_file.exists()

    def to_input_file(self) -> InputFile:
        return self._output_file.to_input_file()

    def create(self, overwrite: bool = False) -> OutputStream:
        return self._EncryptionOutputStream(self._output_file.create(overwrite), self._key_metadata)

    class _EncryptionOutputStream:
        _stream: OutputStream
        _key_metadata: NativeEncryptionKeyMetadata
        _buffer: bytearray
        _closed: bool

        def __init__(self, stream: OutputStream, key_metadata: NativeEncryptionKeyMetadata):
            self._stream = stream
            self._key_metadata = key_metadata
            self._buffer = bytearray()
            self._closed = False

        def write(self, b: bytes) -> int:
            self._buffer.extend(b)
            return len(b)

        def close(self) -> None:
            if not self._closed:
                # Encrypt the buffer
                aesgcm = AESGCM(self._key_metadata.encryption_key())
                nonce = os.urandom(12)
                ciphertext = aesgcm.encrypt(nonce, self._buffer, self._key_metadata.aad_prefix())

                # Write nonce + ciphertext (which includes tag)
                self._stream.write(nonce)
                self._stream.write(ciphertext)
                self._stream.close()
                self._closed = True

        def __enter__(self) -> OutputStream:
            return self

        def __exit__(
            self, exctype: type[BaseException] | None, excinst: BaseException | None, exctb: TracebackType | None
        ) -> None:
            self.close()


class DecryptingInputFile(InputFile):
    _input_file: InputFile
    _key_metadata: NativeEncryptionKeyMetadata

    def __init__(self, input_file: InputFile, key_metadata: NativeEncryptionKeyMetadata):
        self._input_file = input_file
        self._key_metadata = key_metadata
        super().__init__(input_file.location)

    def __len__(self) -> int:
        """Length of the input file."""
        return len(self._input_file)

    def exists(self) -> bool:
        return self._input_file.exists()

    def open(self, seekable: bool = True) -> InputStream:
        return self._DecryptingInputStream(self._input_file.open(seekable), self._key_metadata)

    class _DecryptingInputStream:
        _stream: InputStream
        _key_metadata: NativeEncryptionKeyMetadata
        _decrypted_content: bytes | None
        _pos: int

        def __init__(self, stream: InputStream, key_metadata: NativeEncryptionKeyMetadata):
            self._stream = stream
            self._key_metadata = key_metadata
            self._decrypted_content = None
            self._pos = 0

        def _read_and_decrypt(self) -> None:
            if self._decrypted_content is None:
                # Read all content
                content = self._stream.read()
                if len(content) < 12:
                    raise ValueError("File too short to contain nonce")

                nonce = content[:12]
                ciphertext = content[12:]

                aesgcm = AESGCM(self._key_metadata.encryption_key())
                self._decrypted_content = aesgcm.decrypt(nonce, ciphertext, self._key_metadata.aad_prefix())

        def read(self, size: int = 0) -> bytes:
            self._read_and_decrypt()
            assert self._decrypted_content is not None
            if size == 0:
                data = self._decrypted_content[self._pos :]
                self._pos = len(self._decrypted_content)
                return data
            else:
                data = self._decrypted_content[self._pos : self._pos + size]
                self._pos += size
                return data

        def seek(self, offset: int, whence: int = 0) -> int:
            self._read_and_decrypt()
            assert self._decrypted_content is not None
            if whence == 0:
                self._pos = offset
            elif whence == 1:
                self._pos += offset
            elif whence == 2:
                self._pos = len(self._decrypted_content) + offset
            return self._pos

        def tell(self) -> int:
            return self._pos

        def close(self) -> None:
            self._stream.close()

        def __enter__(self) -> InputStream:
            return self

        def __exit__(
            self, exctype: type[BaseException] | None, excinst: BaseException | None, exctb: TracebackType | None
        ) -> None:
            self.close()


class StandardKeyMetadata(NativeEncryptionKeyMetadata):
    _encryption_key: bytes
    _aad_prefix: bytes
    _file_length: int | None

    def __init__(self, encryption_key: bytes, aad_prefix: bytes, file_length: int | None = None):
        self._encryption_key = encryption_key
        self._aad_prefix = aad_prefix
        self._file_length = file_length

    def encryption_key(self) -> bytes:
        return self._encryption_key

    def aad_prefix(self) -> bytes:
        return self._aad_prefix

    def file_length(self) -> int | None:
        return self._file_length

    def buffer(self) -> bytes:
        # TODO: Implement Avro serialization for key metadata if needed
        # For now, just returning key + aad as a placeholder or implementing simple serialization
        # The Java version uses Avro. We might need a proper serializer.
        return self._encryption_key + self._aad_prefix

    def copy(self) -> StandardKeyMetadata:
        return StandardKeyMetadata(self._encryption_key, self._aad_prefix, self._file_length)

    def copy_with_length(self, length: int) -> StandardKeyMetadata:
        return StandardKeyMetadata(self._encryption_key, self._aad_prefix, length)


class StandardEncryptionManager(EncryptionManager):
    def __init__(self, table_key_id: str, data_key_length: int, kms_client: Any | None = None):
        self.table_key_id = table_key_id
        self.data_key_length = data_key_length
        self.kms_client = kms_client
        self._key_encryption_key_id = "KEY_ENCRYPTION_KEY_ID"
        # In a real implementation, we would need to manage keys, cache them, etc.

    def decrypt(self, file: EncryptedInputFile) -> InputFile:
        return DecryptingInputFile(file.encrypted_input_file, file.key_metadata)

    def encrypt(self, file: OutputFile) -> OutputFile:
        # Generate a new FEK
        fek = AESGCM.generate_key(bit_length=self.data_key_length * 8)
        # In a real implementation, we would wrap this FEK with the KEK from KMS
        # For now, we'll just use the FEK as is (simulating a "direct" key or simple wrapping)
        # TODO: Implement actual key wrapping using self.kms_client

        # Create key metadata
        # AAD prefix is usually empty or specific to the file
        aad_prefix = os.urandom(16)  # Random AAD for now

        key_metadata = StandardKeyMetadata(fek, aad_prefix)

        return NativeEncryptionOutputFile(file, key_metadata)

    def add_manifest_list_key_metadata(self, key_metadata: NativeEncryptionKeyMetadata) -> str:
        # Placeholder for adding key metadata and returning a key ID
        # In the Java PR, this encrypts the key metadata and stores it.
        # Here we'll just generate a random ID.
        import base64

        return base64.b64encode(os.urandom(16)).decode("utf-8")


def decrypt_manifest_list_key_metadata(manifest_list: ManifestListFile, em: EncryptionManager) -> bytes:
    if not isinstance(em, StandardEncryptionManager):
        raise ValueError("Snapshot key metadata encryption requires a StandardEncryptionManager")

    # Placeholder: In a real implementation, this would decrypt the key metadata using the EM
    # For now, we assume we can't fully implement it without the KMS and crypto libraries
    return b""  # Return empty bytes or throw


class EncryptingFileIO(FileIO):
    _io: FileIO
    _em: EncryptionManager

    def __init__(self, io: FileIO, em: EncryptionManager):
        self._io = io
        self._em = em
        super().__init__(io.properties)

    def new_input(self, location: str) -> InputFile:
        return self._io.new_input(location)

    def new_output(self, location: str) -> OutputFile:
        return self._em.encrypt(self._io.new_output(location))

    def delete(self, location: str | InputFile | OutputFile) -> None:
        self._io.delete(location)

    def new_input_file(self, file: ManifestListFile) -> InputFile:
        if file.encryption_key_id is not None:
            key_metadata_buffer = file.decrypt_key_metadata(self._em)
            # We need to wrap this buffer into a KeyMetadata object
            # Assuming StandardKeyMetadata for now or generic wrapper
            # The buffer is the decrypted key metadata.
            # In Java: return newDecryptingInputFile(manifestList.location(), keyMetadata);
            # And newDecryptingInputFile wraps it.
            # We need to parse the buffer into NativeEncryptionKeyMetadata?
            # Or just pass it as bytes?
            # EncryptedInputFile expects NativeEncryptionKeyMetadata.
            # We need a way to construct it from bytes.
            # For now, let's create a dummy metadata with the buffer.
            # TODO: Parse the buffer properly
            key_metadata = StandardKeyMetadata(key_metadata_buffer, b"")
            return self._em.decrypt(BaseEncryptedInputFile(self._io.new_input(file.location), key_metadata))
        return self.new_input(file.location)
