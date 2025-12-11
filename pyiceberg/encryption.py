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

import base64
import io
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING, Any

import avro.io
import avro.schema
from cachetools import LRUCache
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
    def aad_prefix(self) -> bytes | None: ...

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

    @property
    def key_metadata(self) -> NativeEncryptionKeyMetadata:
        return self._key_metadata

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
        """
        Length of the decrypted input file.

        The encrypted file length is length of (nonce + ciphertext + tag).
        AES-GCM with a 12-byte nonce and 16-byte tag means the overhead is 28 bytes.
        """
        encrypted_len = len(self._input_file)
        if encrypted_len <= 28:
            return 0
        return encrypted_len - 28

    def exists(self) -> bool:
        return self._input_file.exists()

    def open(self, seekable: bool = True) -> InputStream:
        # The Java implementation uses a streaming decryptor. The `cryptography` library's AESGCM
        # is a one-shot API, so we read the whole file into memory here.
        # This could be inefficient for very large files.
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


STANDARD_KEY_METADATA_AVRO_SCHEMA = avro.schema.parse(
    """
{
  "type": "record",
  "name": "StandardKeyMetadata",
  "namespace": "org.apache.iceberg.encryption",
  "fields": [
    {
      "name": "encryption_key",
      "type": "bytes"
    },
    {
      "name": "aad_prefix",
      "type": ["null", "bytes"],
      "default": null
    },
    {
        "name": "file_length",
        "type": ["null", "long"],
        "default": null
    }
  ]
}
"""
)


class StandardKeyMetadata(NativeEncryptionKeyMetadata):
    _encryption_key: bytes
    _aad_prefix: bytes | None
    _file_length: int | None

    def __init__(self, encryption_key: bytes, aad_prefix: bytes | None = None, file_length: int | None = None):
        self._encryption_key = encryption_key
        self._aad_prefix = aad_prefix
        self._file_length = file_length

    def encryption_key(self) -> bytes:
        return self._encryption_key

    def aad_prefix(self) -> bytes | None:
        return self._aad_prefix

    def file_length(self) -> int | None:
        return self._file_length

    def buffer(self) -> bytes:
        """Serializes the key metadata to Avro binary format."""
        with io.BytesIO() as bio:
            encoder = avro.io.BinaryEncoder(bio)
            writer = avro.io.DatumWriter(STANDARD_KEY_METADATA_AVRO_SCHEMA)
            writer.write(
                {"encryption_key": self._encryption_key, "aad_prefix": self._aad_prefix, "file_length": self._file_length},
                encoder,
            )
            return bio.getvalue()

    @classmethod
    def from_buffer(cls, buffer: bytes) -> StandardKeyMetadata:
        """Deserializes key metadata from Avro binary format."""
        with io.BytesIO(buffer) as bio:
            decoder = avro.io.BinaryDecoder(bio)
            reader = avro.io.DatumReader(STANDARD_KEY_METADATA_AVRO_SCHEMA)
            record = reader.read(decoder)
            return StandardKeyMetadata(
                encryption_key=record["encryption_key"], aad_prefix=record["aad_prefix"], file_length=record["file_length"]
            )

    def copy(self) -> StandardKeyMetadata:
        return StandardKeyMetadata(self._encryption_key, self._aad_prefix, self._file_length)

    def copy_with_length(self, length: int) -> StandardKeyMetadata:
        return StandardKeyMetadata(self._encryption_key, self._aad_prefix, length)


class MockKMSClient:
    """
    A mock KMS client for demonstration and testing.

    This is not a real KMS client and should not be used in production. It simulates
    key wrapping by encrypting a key with a local master key.
    """

    _master_key: bytes

    def __init__(self, master_key: bytes | None = None):
        self._master_key = master_key or os.urandom(32)

    def wrapKey(self, key: bytes, master_key_id: str) -> bytes:  # pylint: disable=invalid-name
        # `master_key_id` is ignored here, we use the single master key.
        aesgcm = AESGCM(self._master_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, key, None)
        return nonce + ciphertext

    def unwrapKey(self, wrapped_key: bytes, master_key_id: str) -> bytes:  # pylint: disable=invalid-name
        # `master_key_id` is ignored here, we use the single master key.
        nonce = wrapped_key[:12]
        ciphertext = wrapped_key[12:]
        aesgcm = AESGCM(self._master_key)
        return aesgcm.decrypt(nonce, ciphertext, None)


@dataclass
class EncryptedKey:
    key_id: str
    encrypted_key_metadata: bytes
    encrypted_by_id: str | None = None
    aad: bytes | None = None


class StandardEncryptionManager(EncryptionManager):
    _table_key_id: str
    _data_key_length: int
    _kms_client: Any  # Should have wrapKey and unwrapKey methods

    _KEY_ENCRYPTION_KEY_ID = "KEY_ENCRYPTION_KEY_ID"

    def __init__(self, table_key_id: str, data_key_length: int, kms_client: Any):
        self._table_key_id = table_key_id
        self._data_key_length = data_key_length
        self._kms_client = kms_client

        self._encryption_keys: dict[str, EncryptedKey] = {}
        self._unwrapped_key_cache: LRUCache = LRUCache(maxsize=128)

    def _get_or_create_kek(self) -> str:
        if self._KEY_ENCRYPTION_KEY_ID not in self._encryption_keys:
            unwrapped = AESGCM.generate_key(bit_length=self._data_key_length * 8)
            wrapped = self._kms_client.wrapKey(unwrapped, self._table_key_id)

            key = EncryptedKey(
                key_id=self._KEY_ENCRYPTION_KEY_ID, encrypted_key_metadata=wrapped, encrypted_by_id=self._table_key_id
            )

            self._unwrapped_key_cache[key.key_id] = unwrapped
            self._encryption_keys[key.key_id] = key

        return self._KEY_ENCRYPTION_KEY_ID

    def encrypted_by_key(self, manifest_list_key_id: str) -> bytes:
        encrypted_key_metadata = self._encryption_keys.get(manifest_list_key_id)
        if not encrypted_key_metadata:
            raise ValueError(f"Cannot find manifest list key metadata with id {manifest_list_key_id}")

        encrypted_by_id = encrypted_key_metadata.encrypted_by_id
        if not encrypted_by_id:
            raise ValueError(f"Key {manifest_list_key_id} is not encrypted by another key")

        if encrypted_by_id in self._unwrapped_key_cache:
            return self._unwrapped_key_cache[encrypted_by_id]

        # unwrap and cache
        kek_metadata = self._encryption_keys.get(encrypted_by_id)
        if not kek_metadata:
            raise ValueError(f"Cannot find key encryption key with id {encrypted_by_id}")

        unwrapped = self._kms_client.unwrapKey(kek_metadata.encrypted_key_metadata, self._table_key_id)
        self._unwrapped_key_cache[encrypted_by_id] = unwrapped
        return unwrapped

    def encrypted_key_metadata(self, manifest_list_key_id: str) -> bytes:
        encrypted_key_metadata = self._encryption_keys.get(manifest_list_key_id)
        if not encrypted_key_metadata:
            raise ValueError(f"Cannot find manifest list key metadata with id {manifest_list_key_id}")
        return encrypted_key_metadata.encrypted_key_metadata

    def add_manifest_list_key_metadata(self, key_metadata: NativeEncryptionKeyMetadata) -> str:
        kek_id = self._get_or_create_kek()
        # The KEK is stored unwrapped in the cache
        kek = self._unwrapped_key_cache[kek_id]

        manifest_list_key_id = base64.b64encode(os.urandom(16)).decode("utf-8")

        encrypted_key_meta = encrypt_manifest_list_key_metadata(key=kek, key_id=manifest_list_key_id, key_metadata=key_metadata)

        key = EncryptedKey(key_id=manifest_list_key_id, encrypted_key_metadata=encrypted_key_meta, encrypted_by_id=kek_id)

        self._encryption_keys[key.key_id] = key
        return manifest_list_key_id

    def decrypt(self, file: EncryptedInputFile) -> InputFile:
        return DecryptingInputFile(file.encrypted_input_file, file.key_metadata)

    def encrypt(self, file: OutputFile) -> OutputFile:
        """Encrypts an output file, returning a NativeEncryptionOutputFile containing the FEK."""
        # Generate a new File Encryption Key (FEK)
        fek = AESGCM.generate_key(bit_length=self.data_key_length * 8)

        # AAD prefix for file content is not defined by the spec for manifest lists,
        # but the Java implementation uses a random one for data files if not supplied.
        # We will let the user/caller decide if AAD is needed. Here, we use None.
        key_metadata = StandardKeyMetadata(fek, aad_prefix=None)

        return NativeEncryptionOutputFile(file, key_metadata)


def encrypt_manifest_list_key_metadata(key: bytes, key_id: str, key_metadata: EncryptionKeyMetadata) -> bytes:
    """Encrypts the key metadata for a manifest list."""
    aesgcm = AESGCM(key)
    key_metadata_bytes = key_metadata.buffer()
    # Use key_id as AAD for the key metadata encryption, as per Iceberg spec
    aad = key_id.encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, key_metadata_bytes, aad)
    return nonce + ciphertext


def decrypt_manifest_list_key_metadata(manifest_list: ManifestListFile, em: EncryptionManager) -> bytes:
    """Decrypt the key metadata for a manifest list."""
    if not isinstance(em, StandardEncryptionManager):
        raise ValueError("Snapshot key metadata encryption requires a StandardEncryptionManager")

    manifest_list_key_id = manifest_list.encryption_key_id
    if not manifest_list_key_id:
        raise ValueError("ManifestListFile has no encryption key ID")

    kek = em.encrypted_by_key(manifest_list_key_id)
    encrypted_key_metadata = em.encrypted_key_metadata(manifest_list_key_id)

    nonce = encrypted_key_metadata[:12]
    ciphertext = encrypted_key_metadata[12:]

    aesgcm = AESGCM(kek)
    aad = manifest_list_key_id.encode("utf-8")

    return aesgcm.decrypt(nonce, ciphertext, aad)


class EncryptingFileIO(FileIO):
    _io: FileIO
    _em: EncryptionManager

    def __init__(self, io: FileIO, em: EncryptionManager):
        self._io = io
        self._em = em
        super().__init__(io.properties)

    @property
    def encryption_manager(self) -> EncryptionManager:
        return self._em

    def new_input(self, location: str) -> InputFile:
        return self._io.new_input(location)

    def new_output(self, location: str) -> OutputFile:
        return self._em.encrypt(self._io.new_output(location))

    def delete(self, location: str | InputFile | OutputFile) -> None:
        self._io.delete(location)

    def new_input_file(self, file: ManifestListFile) -> InputFile:
        if file.encryption_key_id is not None:
            key_metadata_buffer = file.decrypt_key_metadata(self._em)
            # The decrypted buffer is the Avro-serialized StandardKeyMetadata
            # for the manifest list file itself, containing the FEK.
            key_metadata = StandardKeyMetadata.from_buffer(key_metadata_buffer)

            encrypted_input_file = BaseEncryptedInputFile(self._io.new_input(file.location), key_metadata)
            return self._em.decrypt(encrypted_input_file)
        return self.new_input(file.location)
