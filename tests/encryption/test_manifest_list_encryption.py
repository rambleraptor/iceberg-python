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
"""Tests for manifest list encryption."""

import tempfile
from pathlib import Path

import pytest

from pyiceberg.encryption.standard_encryption import StandardEncryptionManager
from pyiceberg.io.pyarrow import PyArrowFileIO
from pyiceberg.manifest import write_manifest_list


def test_manifest_list_encryption_with_standard_encryption_manager() -> None:
    """Test that manifest lists can be encrypted with StandardEncryptionManager."""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        manifest_list_path = tmp_path / "manifest_list.avro"

        # Create a StandardEncryptionManager
        encryption_manager = StandardEncryptionManager(table_key_id="test-table-key", data_key_length=32)

        # Create a FileIO
        file_io = PyArrowFileIO()
        output_file = file_io.new_output(str(manifest_list_path))

        # Write a manifest list with encryption
        with write_manifest_list(
            format_version=2,
            output_file=output_file,
            snapshot_id=1,
            parent_snapshot_id=None,
            sequence_number=0,
            avro_compression="null",
            encryption_manager=encryption_manager,
        ) as writer:
            # Don't add any manifests for this simple test
            pass

        # Get the manifest list file with encryption metadata
        manifest_list_file = writer.to_manifest_list_file()

        # Verify that the encryption key ID is set
        assert manifest_list_file.encryption_key_id is not None
        assert isinstance(manifest_list_file.encryption_key_id, str)

        # Verify that the location is correct
        assert manifest_list_file.location == str(manifest_list_path)

        # Verify that we can decrypt the key metadata
        decrypted_key_metadata = manifest_list_file.decrypt_key_metadata(encryption_manager)
        assert decrypted_key_metadata is not None
        assert isinstance(decrypted_key_metadata, bytes)


def test_manifest_list_without_encryption() -> None:
    """Test that manifest lists can be written without encryption (plaintext)."""
    # Create a temporary directory for the test
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        manifest_list_path = tmp_path / "manifest_list.avro"

        # Create a FileIO
        file_io = PyArrowFileIO()
        output_file = file_io.new_output(str(manifest_list_path))

        # Write a manifest list without encryption (default behavior)
        with write_manifest_list(
            format_version=2,
            output_file=output_file,
            snapshot_id=1,
            parent_snapshot_id=None,
            sequence_number=0,
            avro_compression="null",
        ) as writer:
            # Don't add any manifests for this simple test
            pass

        # Get the manifest list file
        manifest_list_file = writer.to_manifest_list_file()

        # Verify that no encryption key ID is set
        assert manifest_list_file.encryption_key_id is None

        # Verify that the location is correct
        assert manifest_list_file.location == str(manifest_list_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
