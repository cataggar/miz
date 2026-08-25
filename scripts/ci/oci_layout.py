"""Shared helper for building minimal, from-scratch OCI image layouts for
use as `--container`/`MIZ_BOOT_TEST_*_OCI` fixtures in CI, without
depending on network access to a container registry.

Used by `make-minimal-oci-fixture.py` and `make-uki-stub-oci-fixture.py`.
"""

import gzip
import hashlib
import io
import json
import os
import tarfile


def build_single_layer_oci_layout(out_dir: str, files: dict, architecture: str = "amd64") -> None:
    """Builds a from-scratch OCI image layout at `out_dir` containing a
    single tar+gzip layer with the given files.

    `files` maps an archive-relative path (e.g. "hello.txt" or
    "usr/lib/systemd/boot/efi/linuxx64.efi.stub") to its raw byte content.
    File mode defaults to 0o644 for all entries.
    """
    os.makedirs(f"{out_dir}/blobs/sha256", exist_ok=True)

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        for path, content in files.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(content))
    tar_bytes = tar_buf.getvalue()
    diff_id = hashlib.sha256(tar_bytes).hexdigest()

    gz_bytes = gzip.compress(tar_bytes, compresslevel=6)
    layer_digest = hashlib.sha256(gz_bytes).hexdigest()
    with open(f"{out_dir}/blobs/sha256/{layer_digest}", "wb") as f:
        f.write(gz_bytes)

    config = {
        "architecture": architecture,
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{diff_id}"]},
    }
    config_bytes = json.dumps(config).encode()
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    with open(f"{out_dir}/blobs/sha256/{config_digest}", "wb") as f:
        f.write(config_bytes)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": f"sha256:{config_digest}",
            "size": len(config_bytes),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": f"sha256:{layer_digest}",
                "size": len(gz_bytes),
            }
        ],
    }
    manifest_bytes = json.dumps(manifest).encode()
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    with open(f"{out_dir}/blobs/sha256/{manifest_digest}", "wb") as f:
        f.write(manifest_bytes)

    index = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": f"sha256:{manifest_digest}",
                "size": len(manifest_bytes),
            }
        ],
    }
    with open(f"{out_dir}/index.json", "w") as f:
        json.dump(index, f)

    with open(f"{out_dir}/oci-layout", "w") as f:
        json.dump({"imageLayoutVersion": "1.0.0"}, f)
