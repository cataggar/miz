import contextlib
import hashlib
import io
import json
import os
import shutil
import unittest
from pathlib import Path

from scripts import ubuntu2604_image_benchmark as benchmark


ROOT = Path(__file__).resolve().parents[1]


class Ubuntu2604ImageBenchmarkTest(unittest.TestCase):
    def setUp(self):
        self.root = (
            ROOT
            / ".scratch"
            / f"ubuntu2604-image-benchmark-{os.getpid()}-{self._testMethodName}"
        )
        self.root.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def base_arguments(self):
        paths = {}
        for name in (
            "source",
            "sums",
            "signature",
            "manifest",
            "authorized-key",
            "stub",
            "certificate",
            "signing-key",
            "zig",
        ):
            path = self.root / name
            path.write_text(name, encoding="utf-8")
            paths[name] = path
        cache = self.root / "cache"
        locks = self.root / "locks"
        global_cache = self.root / "zig-global"
        cache.mkdir()
        locks.mkdir()
        return [
            "--output-root",
            str(self.root / "output"),
            "--source",
            str(paths["source"]),
            "--sha256sums",
            str(paths["sums"]),
            "--sha256sums-signature",
            str(paths["signature"]),
            "--manifest",
            str(paths["manifest"]),
            "--debz-cache",
            str(cache),
            "--debz-lock-dir",
            str(locks),
            "--authorized-key",
            str(paths["authorized-key"]),
            "--uki-stub",
            str(paths["stub"]),
            "--signing-certificate",
            str(paths["certificate"]),
            "--signing-certificate-sha256",
            "a" * 64,
            "--signing-key",
            str(paths["signing-key"]),
            "--zig",
            str(paths["zig"]),
            "--zig-global-cache",
            str(global_cache),
        ]

    def make_cache(self):
        cache = self.root / "cache-fixture"
        metadata = cache / "metadata-v1" / "objects"
        manifests = cache / "metadata-v1" / "manifests"
        packages = cache / "packages-v1" / "objects"
        metadata.mkdir(parents=True)
        manifests.mkdir(parents=True)
        packages.mkdir(parents=True)
        metadata_bytes = b"metadata"
        metadata_digest = hashlib.sha256(metadata_bytes).hexdigest()
        (metadata / metadata_digest).write_bytes(metadata_bytes)
        package_bytes = b"package"
        package_digest = hashlib.sha256(package_bytes).hexdigest()
        (packages / package_digest).write_bytes(package_bytes)
        (manifests / "fixture.json").write_text("{}", encoding="utf-8")
        return cache, package_digest

    def make_locks(self, package_digest):
        locks = self.root / "lock-fixture"
        locks.mkdir()
        for index, package in enumerate(benchmark.PACKAGE_ROOTS):
            (locks / benchmark.lock_filename(package)).write_text(
                json.dumps(
                    {
                        "schema": "https://debz.dev/schema/exact-closure-lock-v1",
                        "version": 1,
                        "target_architecture": "arm64",
                        "digest_sha256": format(index + 1, "x") * 64,
                        "packages": [
                            {
                                "name": package,
                                "version": "1",
                                "architecture": "arm64",
                                "sha256": package_digest,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
        return locks

    def timing_document(self, raw_outcome="success"):
        phases = []
        elapsed = 1
        for key in benchmark.PHASE_ORDER:
            if key.startswith("debz_transaction:"):
                name, item = key.split(":", 1)
            else:
                name, item = key, None
            phases.append(
                {
                    "name": name,
                    "item": item,
                    "elapsed_ns": elapsed,
                    "outcome": (
                        raw_outcome
                        if name == "raw_image_materialization"
                        else "success"
                    ),
                    "error_name": None,
                }
            )
            elapsed += 1
        return {
            "schema": 1,
            "type": "vmiz-ubuntu2604-image-phase-timing",
            "clock": "monotonic",
            "duration_unit": "nanoseconds",
            "status": "success",
            "failed_phase": None,
            "failed_item": None,
            "error_name": None,
            "phases": phases,
        }

    def test_argument_validation_requires_exact_signing_shape(self):
        arguments = self.base_arguments()
        parsed = benchmark.parse_args(arguments)
        self.assertEqual(parsed.signing_certificate_sha256, "a" * 64)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                benchmark.parse_args(
                    arguments
                    + [
                        "--sign-command-arg",
                        "sign",
                    ]
                )
        invalid = arguments.copy()
        index = invalid.index("a" * 64)
        invalid[index] = "not-a-digest"
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                benchmark.parse_args(invalid)

    def test_benchmark_command_fixes_profile_and_offline_inputs(self):
        args = benchmark.parse_args(self.base_arguments())
        command = benchmark.benchmark_command(
            args,
            work_dir=self.root / "work",
            provenance_dir=self.root / "provenance",
            image=self.root / "artifact" / benchmark.ASSET_NAME,
            timing=self.root / "timing.json",
        )
        self.assertIn("-Doptimize=ReleaseSafe", command)
        self.assertIn("-Dubuntu2604-arch=aarch64", command)
        self.assertIn("-Dubuntu2604-flavor=baremetal", command)
        self.assertIn("--debz-lock-dir", command)
        self.assertIn("--offline", command)
        raw_index = command.index("--raw-output")
        self.assertEqual(
            command[raw_index + 1],
            str(self.root / "artifact" / benchmark.RAW_ASSET_NAME),
        )

    def test_run_directory_must_be_new(self):
        output = self.root / "new-output"
        self.assertEqual(benchmark.prepare_session_dir(output), output)
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.prepare_session_dir(output)

    def test_cleanup_rejects_paths_outside_exact_run_layout(self):
        run = self.root / "run"
        (run / "artifact").mkdir(parents=True)
        (run / "work").mkdir()
        image = run / "artifact" / benchmark.ASSET_NAME
        raw_output = run / "artifact" / benchmark.RAW_ASSET_NAME
        image.write_bytes(b"image")
        raw_output.write_bytes(b"raw")
        outside = self.root / "outside"
        outside.mkdir()
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.cleanup_decisions(
                run, image, raw_output, outside, keep_images=False
            )
        (outside / benchmark.RAW_ASSET_NAME).write_bytes(b"raw")
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.cleanup_decisions(
                run,
                image,
                outside / benchmark.RAW_ASSET_NAME,
                run / "work",
                keep_images=False,
            )

    def test_cleanup_removes_only_validated_large_targets(self):
        run = self.root / "run"
        (run / "artifact").mkdir(parents=True)
        work = run / "work"
        work.mkdir()
        image = run / "artifact" / benchmark.ASSET_NAME
        raw_output = run / "artifact" / benchmark.RAW_ASSET_NAME
        image.write_bytes(b"image")
        raw_output.write_bytes(b"raw")
        removed = benchmark.cleanup_run(
            run, image, raw_output, work, keep_images=False
        )
        self.assertEqual(
            removed,
            [
                f"artifact/{benchmark.ASSET_NAME}",
                f"artifact/{benchmark.RAW_ASSET_NAME}",
                "work",
            ],
        )
        self.assertFalse(image.exists())
        self.assertFalse(raw_output.exists())
        self.assertFalse(work.exists())

    def test_keep_images_still_discards_only_work_directory(self):
        run = self.root / "run"
        (run / "artifact").mkdir(parents=True)
        work = run / "work"
        work.mkdir()
        image = run / "artifact" / benchmark.ASSET_NAME
        raw_output = run / "artifact" / benchmark.RAW_ASSET_NAME
        image.write_bytes(b"image")
        raw_output.write_bytes(b"raw")
        removed = benchmark.cleanup_run(
            run, image, raw_output, work, keep_images=True
        )
        self.assertEqual(removed, ["work"])
        self.assertTrue(image.exists())
        self.assertTrue(raw_output.exists())

    def test_warm_cache_verifies_content_addressed_objects(self):
        cache, package_digest = self.make_cache()
        inventory = benchmark.verify_warm_cache(cache)
        self.assertEqual(inventory["package_objects"], 1)
        self.assertIn(package_digest, inventory["_package_object_names"])
        package = cache / "packages-v1" / "objects" / package_digest
        package.write_bytes(b"corrupt")
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.verify_warm_cache(cache)

    def test_lock_set_fails_closed_on_cache_miss(self):
        cache, package_digest = self.make_cache()
        inventory = benchmark.verify_warm_cache(cache)
        locks = self.make_locks(package_digest)
        verified = benchmark.verify_lock_set(
            locks, inventory["_package_object_names"]
        )
        self.assertEqual(len(verified["locks"]), len(benchmark.PACKAGE_ROOTS))
        missing = json.loads(
            (locks / benchmark.lock_filename(benchmark.PACKAGE_ROOTS[0])).read_text(
                encoding="utf-8"
            )
        )
        missing["packages"][0]["sha256"] = "f" * 64
        (locks / benchmark.lock_filename(benchmark.PACKAGE_ROOTS[0])).write_text(
            json.dumps(missing), encoding="utf-8"
        )
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.verify_lock_set(
                locks, inventory["_package_object_names"]
            )

    def test_timing_schema_ingestion_preserves_phase_values(self):
        path = self.root / "timing.json"
        path.write_text(json.dumps(self.timing_document()), encoding="utf-8")
        timing = benchmark.load_timing(path)
        self.assertEqual(
            set(timing["values"]),
            set(benchmark.PHASE_ORDER),
        )
        document = self.timing_document()
        document["phases"][0]["elapsed_ns"] = -1
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.load_timing(path)

    def test_timing_schema_requires_successful_raw_materialization(self):
        path = self.root / "timing.json"
        path.write_text(
            json.dumps(self.timing_document(raw_outcome="skipped")),
            encoding="utf-8",
        )
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.load_timing(path)

    def test_raw_output_requires_exact_regular_5_gib_file(self):
        raw_output = self.root / benchmark.RAW_ASSET_NAME
        with raw_output.open("wb") as stream:
            stream.truncate(benchmark.VIRTUAL_SIZE)
        info = self.root / "raw-info.json"
        info.write_text(
            json.dumps(
                {
                    "filename": str(raw_output),
                    "format": "raw",
                    "virtual-size": benchmark.VIRTUAL_SIZE,
                    "actual-size": benchmark.VIRTUAL_SIZE,
                    "subformat": None,
                    "backing-filename": None,
                    "format-specific": None,
                }
            ),
            encoding="utf-8",
        )
        metadata = benchmark.validate_raw_output(raw_output, info)
        self.assertEqual(metadata["filename"], benchmark.RAW_ASSET_NAME)
        self.assertEqual(metadata["bytes"], benchmark.VIRTUAL_SIZE)
        self.assertFalse(metadata["byte_hash_recorded"])
        os.truncate(raw_output, benchmark.VIRTUAL_SIZE - 1)
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.validate_raw_output(raw_output, info)
        raw_output.unlink()
        target = self.root / "raw-target"
        with target.open("wb") as stream:
            stream.truncate(benchmark.VIRTUAL_SIZE)
        raw_output.symlink_to(target)
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.validate_raw_output(raw_output, info)

    def test_median_calculation_is_integer_and_stable(self):
        self.assertEqual(benchmark.median_int([9, 1, 5]), 5)
        self.assertEqual(benchmark.median_int([10, 2]), 6)
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.median_int([])

    def test_correctness_comparison_rejects_any_contract_change(self):
        reference = {"closure": "a", "acceptance": {"status": "success"}}
        benchmark.compare_correctness(reference, dict(reference))
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.compare_correctness(
                reference,
                {"closure": "b", "acceptance": {"status": "success"}},
            )

    def test_summary_generation_uses_three_measured_medians(self):
        values = {phase: 10 for phase in benchmark.PHASE_ORDER}
        resources = {
            "wall_ns": 10,
            "user_ns": 8,
            "system_ns": 2,
            "peak_rss_bytes": 100,
            "read_bytes": 200,
            "write_bytes": 300,
            "block_inputs": 4,
            "block_outputs": 5,
        }
        runs = []
        for index, kind in enumerate(("warmup", "measured", "measured", "measured")):
            run_values = dict(values)
            run_values["total_runtime"] = (100, 30, 10, 20)[index]
            run_resources = dict(resources)
            run_resources["wall_ns"] = (100, 30, 10, 20)[index]
            runs.append(
                {
                    "name": f"run-{index}",
                    "kind": kind,
                    "timing_values": run_values,
                    "resources": run_resources,
                    "correctness_sha256": "a" * 64,
                    "image_sha256": str(index) * 64,
                    "image_bytes": 1,
                    "raw_output": {
                        "filename": benchmark.RAW_ASSET_NAME,
                        "format": "raw",
                        "bytes": benchmark.VIRTUAL_SIZE,
                        "virtual_size": benchmark.VIRTUAL_SIZE,
                        "structural_validation": "vmiz-check-and-info",
                        "byte_hash_recorded": False,
                        "byte_reproducibility_compared": False,
                        "retention_policy": "delete-after-validation",
                    },
                    "evidence": f"run-{index}/evidence",
                    "cleanup": [],
                }
            )
        summary = benchmark.build_summary(
            runs,
            source_commit="b" * 40,
            host={"machine": "aarch64"},
            cache_inventory={"inventory_sha256": "c" * 64},
            lock_set={"closure_sha256": "d" * 64, "locks": []},
        )
        self.assertEqual(
            summary["medians"]["phase_elapsed_ns"]["total_runtime"], 20
        )
        self.assertEqual(summary["medians"]["resources"]["wall_ns"], 20)
        self.assertEqual(
            summary["runs"][0]["raw_output"]["virtual_size"],
            benchmark.VIRTUAL_SIZE,
        )
        self.assertFalse(
            summary["runs"][0]["raw_output"]["byte_reproducibility_compared"]
        )
        readable = benchmark.readable_summary(summary)
        self.assertIn("Status: valid", readable)
        self.assertIn("Median total phase time", readable)
        self.assertIn("not compared", readable)


if __name__ == "__main__":
    unittest.main()
