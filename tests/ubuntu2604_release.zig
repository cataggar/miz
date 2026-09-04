//! Behavioral coverage of the Ubuntu 26.04 release tooling.
//!
//! Every test here builds a complete, valid bundle and then changes exactly
//! one thing, because that is the property the release contract actually has:
//! a candidate, an acceptance result, and a staged release are accepted only
//! when every binding still agrees with the bytes on disk. Replaces
//! `tests/ubuntu2604_release_test.py`.

const std = @import("std");

const fixture = @import("ubuntu2604_fixture.zig");
const release = @import("ubuntu2604_release");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Step = fixture.Step;
const Tree = fixture.Tree;
const commands = release.commands;
const contracts = release.contracts;
const documents = release.documents;
const provenance = release.provenance;
const support = release.support;

const allocator = std.testing.allocator;
const io = std.testing.io;
const publication_tag = "Ubuntu-26.04-20260829";
const Attempts = [contracts.release_order.len][]const u8;
const attempt_one: Attempts = @splat("1");

fn tree() !Tree {
    return Tree.create(allocator, io);
}

/// `verify_candidate` against the bundle's own asset.
fn verify(subject: *const Tree, key: []const u8) !documents.Candidate {
    const manifest = try subject.manifestPath(key);
    defer allocator.free(manifest);
    const asset = try subject.assetPath(key);
    defer allocator.free(asset);
    var diagnostic: support.Diagnostic = .{};
    return documents.verifyCandidate(
        allocator,
        io,
        manifest,
        asset,
        key,
        fixture.source_commit,
        &diagnostic,
    );
}

/// `validate_azure_result` against the bundle's own result.
fn validateAzure(subject: *const Tree, key: []const u8) !void {
    var candidate = try verify(subject, key);
    defer candidate.deinit();
    const result_path = try subject.azureResultPath(key);
    defer allocator.free(result_path);
    var diagnostic: support.Diagnostic = .{};
    var result = try documents.validateAzureResult(
        allocator,
        io,
        &candidate,
        result_path,
        &diagnostic,
    );
    result.deinit();
}

fn expectAzureRejected(subject: *const Tree, key: []const u8) !void {
    try std.testing.expectError(error.Failed, validateAzure(subject, key));
}

/// `stage` into the tree's own staging paths.
fn stage(subject: *const Tree, release_tag: []const u8) !void {
    const candidates = try subject.candidates();
    defer allocator.free(candidates);
    const native = try subject.native();
    defer allocator.free(native);
    const azure = try subject.azure();
    defer allocator.free(azure);
    const output = try subject.path("staged", .{});
    defer allocator.free(output);
    const notes = try subject.path("release-notes.md", .{});
    defer allocator.free(notes);
    var diagnostic: support.Diagnostic = .{};
    try commands.stage(allocator, io, .{
        .candidates = candidates,
        .native_results = native,
        .azure_results = azure,
        .source_commit = fixture.source_commit,
        .release_tag = release_tag,
        .candidate_run_id = "100",
        .run_id = "100",
        .run_attempt = "3",
        .output = output,
        .notes = notes,
    }, &diagnostic);
}

fn expectStageRejected(subject: *const Tree) !void {
    try std.testing.expectError(error.Failed, stage(subject, publication_tag));
}

fn makeAll(subject: *const Tree) !void {
    for (contracts.release_order) |key| {
        try fixture.makeBundle(subject, key, .{});
        try fixture.makeNativeResult(subject, key, .{});
    }
}

fn makeReleaseEvidence(subject: *const Tree) !void {
    try makeAll(subject);
}

fn artifactPrefix(kind: release.workflow.ArtifactKind) []const u8 {
    return switch (kind) {
        .candidate => "ubuntu2604-candidate",
        .native => "ubuntu2604-native",
        .azure => "ubuntu2604-azure",
    };
}

fn artifactJobName(
    subject_allocator: Allocator,
    kind: release.workflow.ArtifactKind,
    key: []const u8,
) ![]u8 {
    return switch (kind) {
        .candidate => std.fmt.allocPrint(
            subject_allocator,
            "build/native {s}",
            .{key},
        ),
        .native => std.fmt.allocPrint(
            subject_allocator,
            "same-architecture QEMU ({s}) {s}",
            .{
                if (std.mem.startsWith(u8, key, "x86_64")) "kvm" else "tcg",
                key,
            },
        ),
        .azure => std.fmt.allocPrint(subject_allocator, "Azure {s}", .{key}),
    };
}

fn writeSelection(
    subject: *const Tree,
    kind: release.workflow.ArtifactKind,
    run_id: []const u8,
    attempts: Attempts,
) ![]u8 {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = support.Builder.init(arena.allocator());
    var artifacts = builder.object();
    for (contracts.release_order, 0..) |key, index| {
        const artifact_name = try std.fmt.allocPrint(
            allocator,
            "{s}-{s}-{s}-{s}",
            .{ artifactPrefix(kind), key, fixture.source_commit, attempts[index] },
        );
        defer allocator.free(artifact_name);
        const job_name = try artifactJobName(allocator, kind, key);
        defer allocator.free(job_name);
        var entry = builder.object();
        try builder.putInteger(
            &entry,
            "artifact_id",
            1000 + @as(i64, @intCast(index)),
        );
        try builder.putString(&entry, "artifact_name", artifact_name);
        try builder.putString(
            &entry,
            "artifact_digest",
            "sha256:" ++ "a" ** 64,
        );
        try builder.putInteger(
            &entry,
            "job_id",
            2000 + @as(i64, @intCast(index)),
        );
        try builder.putString(&entry, "job_name", job_name);
        try builder.putString(&entry, "run_attempt", attempts[index]);
        try builder.put(&artifacts, key, .{ .object = entry });
    }
    var document = builder.object();
    try builder.putInteger(&document, "schema", 1);
    try builder.putString(
        &document,
        "type",
        "miz-ubuntu2604-artifact-selection",
    );
    try builder.putString(&document, "kind", @tagName(kind));
    try builder.putString(&document, "run_id", run_id);
    try builder.putString(&document, "source_commit", fixture.source_commit);
    try builder.put(&document, "artifacts", .{ .object = artifacts });
    const path = try subject.path("selection-{s}.json", .{@tagName(kind)});
    errdefer allocator.free(path);
    var diagnostic: support.Diagnostic = .{};
    try support.writeDocument(
        allocator,
        io,
        path,
        .{ .object = document },
        &diagnostic,
    );
    return path;
}

const EvidenceFault = enum {
    none,
    missing,
    duplicate,
    expired,
    empty,
    wrong_source,
    wrong_workflow,
    wrong_key,
    unsuccessful_job,
    missing_job,
    duplicate_job,
};

fn resolveEvidenceWithAttempts(
    subject: *const Tree,
    kind: release.workflow.ArtifactKind,
    fault: EvidenceFault,
    attempts: Attempts,
    max_attempt: i64,
) !void {
    const target_index: usize = 2;
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = support.Builder.init(arena.allocator());
    var jobs = builder.array();
    var artifacts = builder.array();

    for (contracts.release_order, 0..) |key, index| {
        const selected_attempt = try std.fmt.parseInt(i64, attempts[index], 10);
        var attempt: i64 = 1;
        while (attempt <= max_attempt) : (attempt += 1) {
            if (fault == .missing_job and index == target_index and
                attempt == selected_attempt)
            {
                continue;
            }
            const job_name = try artifactJobName(allocator, kind, key);
            defer allocator.free(job_name);
            var job = builder.object();
            try builder.putInteger(
                &job,
                "id",
                attempt * 100 + @as(i64, @intCast(index)) + 1,
            );
            try builder.putString(&job, "name", job_name);
            try builder.putInteger(&job, "run_attempt", attempt);
            try builder.putInteger(&job, "run_id", 100);
            try builder.putString(&job, "head_sha", fixture.source_commit);
            try builder.putString(&job, "status", "completed");
            try builder.putString(
                &job,
                "conclusion",
                if (fault == .unsuccessful_job and index == target_index and
                    attempt == selected_attempt)
                    "failure"
                else
                    "success",
            );
            const job_value: std.json.Value = .{ .object = job };
            try jobs.append(job_value);
            if (fault == .duplicate_job and index == target_index and
                attempt == selected_attempt)
            {
                try jobs.append(job_value);
            }
        }

        if (fault == .missing and index == target_index) continue;
        const artifact_key = if (fault == .wrong_key and index == target_index)
            "riscv64-core"
        else
            key;
        const artifact_source = if (fault == .wrong_source and index == target_index)
            "b" ** 40
        else
            fixture.source_commit;
        const artifact_name = try std.fmt.allocPrint(
            allocator,
            "{s}-{s}-{s}-{s}",
            .{ artifactPrefix(kind), artifact_key, artifact_source, attempts[index] },
        );
        defer allocator.free(artifact_name);
        var workflow_identity = builder.object();
        try builder.putInteger(&workflow_identity, "id", 100);
        try builder.putString(
            &workflow_identity,
            "head_sha",
            if (fault == .wrong_workflow and index == target_index)
                "b" ** 40
            else
                fixture.source_commit,
        );
        var artifact = builder.object();
        try builder.putInteger(
            &artifact,
            "id",
            1000 + @as(i64, @intCast(index)),
        );
        try builder.putString(&artifact, "name", artifact_name);
        try builder.putInteger(
            &artifact,
            "size_in_bytes",
            if (fault == .empty and index == target_index) 0 else 100,
        );
        try builder.put(
            &artifact,
            "expired",
            .{ .bool = fault == .expired and index == target_index },
        );
        try builder.putString(
            &artifact,
            "digest",
            "sha256:" ++ "a" ** 64,
        );
        try builder.put(
            &artifact,
            "workflow_run",
            .{ .object = workflow_identity },
        );
        const artifact_value: std.json.Value = .{ .object = artifact };
        try artifacts.append(artifact_value);
        if (fault == .duplicate and index == target_index) {
            try artifacts.append(artifact_value);
        }
    }

    const jobs_path = try subject.path("jobs-{s}.json", .{@tagName(kind)});
    defer allocator.free(jobs_path);
    const artifacts_path = try subject.path(
        "artifacts-{s}.json",
        .{@tagName(kind)},
    );
    defer allocator.free(artifacts_path);
    const output = try subject.path("resolved-{s}.json", .{@tagName(kind)});
    defer allocator.free(output);
    var diagnostic: support.Diagnostic = .{};
    try support.writeDocument(
        allocator,
        io,
        jobs_path,
        .{ .array = jobs },
        &diagnostic,
    );
    try support.writeDocument(
        allocator,
        io,
        artifacts_path,
        .{ .array = artifacts },
        &diagnostic,
    );
    try release_workflow.resolveArtifacts(allocator, io, .{
        .jobs = jobs_path,
        .artifacts = artifacts_path,
        .kind = kind,
        .run_id = "100",
        .source_commit = fixture.source_commit,
        .max_attempt = max_attempt,
        .output = output,
    }, &diagnostic);
}

fn resolveEvidence(subject: *const Tree, fault: EvidenceFault) !void {
    return resolveEvidenceWithAttempts(
        subject,
        .candidate,
        fault,
        .{ "1", "1", "2", "1" },
        2,
    );
}

fn azureSkuOutput(
    subject: *const Tree,
    document: []const u8,
    architecture: []const u8,
    diagnostic: *support.Diagnostic,
) ![]u8 {
    const path = try subject.path("sku.json", .{});
    defer allocator.free(path);
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = document });
    var buffer: [128]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    try release_workflow.azureSku(
        allocator,
        io,
        &out,
        path,
        "Standard_D2pds_v6",
        architecture,
        diagnostic,
    );
    return allocator.dupe(u8, out.buffered());
}

fn releaseGateWithDiagnostic(
    subject: *const Tree,
    diagnostic: *support.Diagnostic,
) !void {
    const candidates = try subject.candidates();
    defer allocator.free(candidates);
    const native = try subject.native();
    defer allocator.free(native);
    const azure = try subject.azure();
    defer allocator.free(azure);
    const candidate_selection = try writeSelection(
        subject,
        .candidate,
        "100",
        attempt_one,
    );
    defer allocator.free(candidate_selection);
    const native_selection = try writeSelection(
        subject,
        .native,
        "100",
        attempt_one,
    );
    defer allocator.free(native_selection);
    const azure_selection = try writeSelection(
        subject,
        .azure,
        "100",
        attempt_one,
    );
    defer allocator.free(azure_selection);
    try release_workflow.releaseGate(allocator, io, .{
        .candidates = candidates,
        .native_results = native,
        .azure_results = azure,
        .candidate_selection = candidate_selection,
        .native_selection = native_selection,
        .azure_selection = azure_selection,
        .source_commit = fixture.source_commit,
        .candidate_run_id = "100",
        .run_id = "100",
    }, diagnostic);
}

fn releaseGate(subject: *const Tree) !void {
    var diagnostic: support.Diagnostic = .{};
    try releaseGateWithDiagnostic(subject, &diagnostic);
}

fn expectReleaseGateRejected(subject: *const Tree) !void {
    try std.testing.expectError(error.Failed, releaseGate(subject));
}

fn remake(subject: *const Tree, key: []const u8) !void {
    try subject.removeBundle(key);
    try fixture.makeBundle(subject, key, .{});
}

fn addLegacySmokeEvidence(path: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = support.Builder.init(arena.allocator());
    var smoke = builder.object();
    try builder.putString(&smoke, "provenance_sha256", "5" ** 64);
    try builder.putString(&smoke, "runtime_sha256", "6" ** 64);
    try builder.putString(&smoke, "bundle_sha256", "7" ** 64);
    try builder.putString(&smoke, "config_sha256", "8" ** 64);
    try builder.putString(&smoke, "architecture", "aarch64");
    try builder.putString(&smoke, "candidate_key", "aarch64-core");
    try fixture.patch(
        allocator,
        io,
        path,
        &.{.{ .key = "android_" ++ "smoke" }},
        .{ .set = .{ .object = smoke } },
    );
}

test "the release gate requires valid native and Azure results for all four candidates" {
    var subject = try tree();
    defer subject.deinit();
    try makeReleaseEvidence(&subject);
    try releaseGate(&subject);
}

test "artifact selection resolves each candidate from its newest successful attempt" {
    var subject = try tree();
    defer subject.deinit();
    try resolveEvidence(&subject, .none);
    const output = try subject.path("resolved-candidate.json", .{});
    defer allocator.free(output);
    var selection = try fixture.read(allocator, io, output);
    defer selection.deinit();
    const artifacts = selection.value.object.get("artifacts").?.object;
    try std.testing.expectEqualStrings(
        "1",
        artifacts.get("x86_64-full").?.object.get("run_attempt").?.string,
    );
    try std.testing.expectEqualStrings(
        "2",
        artifacts.get("x86_64-core").?.object.get("run_attempt").?.string,
    );
}

test "artifact selection resolves native and Azure result attempts" {
    for ([_]release.workflow.ArtifactKind{ .native, .azure }) |kind| {
        var subject = try tree();
        defer subject.deinit();
        try resolveEvidenceWithAttempts(
            &subject,
            kind,
            .none,
            .{ "2", "1", "2", "1" },
            2,
        );
        const output = try subject.path("resolved-{s}.json", .{@tagName(kind)});
        defer allocator.free(output);
        var selection = try fixture.read(allocator, io, output);
        defer selection.deinit();
        try std.testing.expectEqualStrings(
            @tagName(kind),
            selection.value.object.get("kind").?.string,
        );
        try std.testing.expectEqualStrings(
            "2",
            selection.value.object
                .get("artifacts").?
                .object
                .get("x86_64-full").?
                .object
                .get("run_attempt").?
                .string,
        );
    }
}

test "artifact selection rejects incomplete or untrusted evidence" {
    const faults = [_]EvidenceFault{
        .missing,
        .duplicate,
        .expired,
        .empty,
        .wrong_source,
        .wrong_workflow,
        .wrong_key,
        .unsuccessful_job,
        .missing_job,
        .duplicate_job,
    };
    for (faults) |fault| {
        var subject = try tree();
        defer subject.deinit();
        try std.testing.expectError(error.Failed, resolveEvidence(&subject, fault));
    }
}

test "artifact selection survives downstream-only reruns and prefers later full attempts" {
    {
        var subject = try tree();
        defer subject.deinit();
        try resolveEvidenceWithAttempts(
            &subject,
            .candidate,
            .none,
            .{ "1", "1", "2", "1" },
            3,
        );
        const output = try subject.path("resolved-candidate.json", .{});
        defer allocator.free(output);
        var selection = try fixture.read(allocator, io, output);
        defer selection.deinit();
        const artifacts = selection.value.object.get("artifacts").?.object;
        try std.testing.expectEqualStrings(
            "2",
            artifacts.get("x86_64-core").?.object.get("run_attempt").?.string,
        );
        try std.testing.expectEqualStrings(
            "1",
            artifacts.get("aarch64-core").?.object.get("run_attempt").?.string,
        );
    }
    {
        var subject = try tree();
        defer subject.deinit();
        try resolveEvidenceWithAttempts(
            &subject,
            .candidate,
            .none,
            @splat("3"),
            3,
        );
        const output = try subject.path("resolved-candidate.json", .{});
        defer allocator.free(output);
        var selection = try fixture.read(allocator, io, output);
        defer selection.deinit();
        for (contracts.release_order) |key| {
            try std.testing.expectEqualStrings(
                "3",
                selection.value.object
                    .get("artifacts").?
                    .object
                    .get(key).?
                    .object
                    .get("run_attempt").?
                    .string,
            );
        }
    }
}

test "Azure SKU storage policy distinguishes conventional, NVMe-only, and absent storage" {
    const cases = [_]struct {
        architecture: []const u8,
        capabilities: []const u8,
        expected: []const u8,
    }{
        .{
            .architecture = "x64",
            .capabilities =
            \\{"name":"CpuArchitectureType","value":"x64"},
            \\{"name":"HyperVGenerations","value":"V1,V2"},
            \\{"name":"MaxResourceVolumeMB","value":"76800"}
            ,
            .expected = "true\ntrue\n",
        },
        .{
            .architecture = "Arm64",
            .capabilities =
            \\{"name":"CpuArchitectureType","value":"Arm64"},
            \\{"name":"HyperVGenerations","value":"V2"},
            \\{"name":"MaxResourceVolumeMB","value":"0"},
            \\{"name":"NvmeDiskSizeInMiB","value":"112640"}
            ,
            .expected = "false\ntrue\n",
        },
        .{
            .architecture = "Arm64",
            .capabilities =
            \\{"name":"CpuArchitectureType","value":"Arm64"},
            \\{"name":"HyperVGenerations","value":"V2"},
            \\{"name":"MaxResourceVolumeMB","value":"0"}
            ,
            .expected = "false\nfalse\n",
        },
    };
    for (cases) |case| {
        var subject = try tree();
        defer subject.deinit();
        const document = try std.fmt.allocPrint(
            allocator,
            "[{{\"name\":\"Standard_D2pds_v6\",\"restrictions\":[]," ++
                "\"capabilities\":[{s}]}}]",
            .{case.capabilities},
        );
        defer allocator.free(document);
        var diagnostic: support.Diagnostic = .{};
        const output = try azureSkuOutput(
            &subject,
            document,
            case.architecture,
            &diagnostic,
        );
        defer allocator.free(output);
        try std.testing.expectEqualStrings(case.expected, output);
    }
}

test "Azure SKU storage policy rejects missing x64 storage and malformed ambiguity" {
    const cases = [_]struct {
        architecture: []const u8,
        document: []const u8,
    }{
        .{
            .architecture = "x64",
            .document =
            \\[{"name":"Standard_D2pds_v6","restrictions":[],"capabilities":[
            \\{"name":"CpuArchitectureType","value":"x64"},
            \\{"name":"HyperVGenerations","value":"V2"},
            \\{"name":"MaxResourceVolumeMB","value":"0"},
            \\{"name":"NvmeDiskSizeInMiB","value":"112640"}]}]
            ,
        },
        .{
            .architecture = "Arm64",
            .document =
            \\[{"name":"Standard_D2pds_v6","restrictions":[],"capabilities":[
            \\{"name":"CpuArchitectureType","value":"Arm64"},
            \\{"name":"HyperVGenerations","value":"V2"},
            \\{"name":"NvmeDiskSizeInMiB","value":"invalid"}]}]
            ,
        },
        .{
            .architecture = "Arm64",
            .document =
            \\[{"name":"Standard_D2pds_v6","restrictions":[],"capabilities":[
            \\{"name":"CpuArchitectureType","value":"Arm64"},
            \\{"name":"HyperVGenerations","value":"V2"},
            \\{"name":"NvmeDiskSizeInMiB","value":112640}]}]
            ,
        },
        .{
            .architecture = "Arm64",
            .document =
            \\[{"name":"Standard_D2pds_v6","restrictions":[],"capabilities":[
            \\{"name":"CpuArchitectureType","value":"Arm64"},
            \\{"name":"HyperVGenerations","value":"V2"},
            \\{"name":"NvmeDiskSizeInMiB","value":"1"},
            \\{"name":"NvmeDiskSizeInMiB","value":"2"}]}]
            ,
        },
        .{
            .architecture = "Arm64",
            .document =
            \\[{"name":"Standard_D2pds_v6","restrictions":[],"capabilities":[
            \\{"name":"CpuArchitectureType","value":"Arm64"},
            \\{"name":"HyperVGenerations","value":"V2"}]},
            \\{"name":"Standard_D2pds_v6","restrictions":[],"capabilities":[
            \\{"name":"CpuArchitectureType","value":"Arm64"},
            \\{"name":"HyperVGenerations","value":"V2"}]}]
            ,
        },
        .{
            .architecture = "x64",
            .document =
            \\[{"name":"Standard_D2pds_v6","restrictions":[],"capabilities":[
            \\{"name":"CpuArchitectureType","value":"x64"},
            \\{"name":"HyperVGenerations","value":"V1"},
            \\{"name":"MaxResourceVolumeMB","value":"76800"}]}]
            ,
        },
        .{
            .architecture = "x64",
            .document =
            \\[{"name":"Standard_D2pds_v6","restrictions":[],"capabilities":[
            \\{"name":"CpuArchitectureType","value":"x64"},
            \\{"name":"HyperVGenerations","value":"V2"},
            \\{"name":"TrustedLaunchDisabled","value":"True"},
            \\{"name":"MaxResourceVolumeMB","value":"76800"}]}]
            ,
        },
        .{
            .architecture = "x64",
            .document =
            \\[{"name":"Standard_D2pds_v6","restrictions":[],"capabilities":[
            \\{"name":"CpuArchitectureType","value":"x64"},
            \\{"name":"HyperVGenerations","value":"V2"},
            \\{"name":"TrustedLaunchDisabled","value":"unknown"},
            \\{"name":"MaxResourceVolumeMB","value":"76800"}]}]
            ,
        },
    };
    for (cases) |case| {
        var subject = try tree();
        defer subject.deinit();
        var diagnostic: support.Diagnostic = .{};
        try std.testing.expectError(
            error.Failed,
            azureSkuOutput(
                &subject,
                case.document,
                case.architecture,
                &diagnostic,
            ),
        );
    }
}

test "the release gate accepts per-key candidate and validation attempts" {
    const candidate_attempts: Attempts = .{ "1", "1", "2", "1" };
    const native_attempts: Attempts = .{ "1", "2", "2", "1" };
    const azure_attempts: Attempts = .{ "2", "1", "2", "1" };
    var subject = try tree();
    defer subject.deinit();
    try makeReleaseEvidence(&subject);

    for (contracts.release_order, 0..) |key, index| {
        const manifest = try subject.manifestPath(key);
        defer allocator.free(manifest);
        try fixture.patchString(
            allocator,
            io,
            manifest,
            &.{ .{ .key = "workflow" }, .{ .key = "run_attempt" } },
            candidate_attempts[index],
        );
        const native = try subject.nativeResultPath(key);
        defer allocator.free(native);
        try fixture.patchString(
            allocator,
            io,
            native,
            &.{ .{ .key = "workflow" }, .{ .key = "run_attempt" } },
            native_attempts[index],
        );
        try fixture.patchString(
            allocator,
            io,
            native,
            &.{ .{ .key = "candidate_workflow" }, .{ .key = "run_attempt" } },
            candidate_attempts[index],
        );
        const azure = try subject.azureResultPath(key);
        defer allocator.free(azure);
        try fixture.patchString(
            allocator,
            io,
            azure,
            &.{ .{ .key = "workflow" }, .{ .key = "run_attempt" } },
            azure_attempts[index],
        );
        try fixture.patchString(
            allocator,
            io,
            azure,
            &.{ .{ .key = "candidate_workflow" }, .{ .key = "run_attempt" } },
            candidate_attempts[index],
        );
    }

    const candidates = try subject.candidates();
    defer allocator.free(candidates);
    const native = try subject.native();
    defer allocator.free(native);
    const azure = try subject.azure();
    defer allocator.free(azure);
    const candidate_selection = try writeSelection(
        &subject,
        .candidate,
        "100",
        candidate_attempts,
    );
    defer allocator.free(candidate_selection);
    const native_selection = try writeSelection(
        &subject,
        .native,
        "100",
        native_attempts,
    );
    defer allocator.free(native_selection);
    const azure_selection = try writeSelection(
        &subject,
        .azure,
        "100",
        azure_attempts,
    );
    defer allocator.free(azure_selection);
    var diagnostic: support.Diagnostic = .{};
    try release_workflow.releaseGate(allocator, io, .{
        .candidates = candidates,
        .native_results = native,
        .azure_results = azure,
        .candidate_selection = candidate_selection,
        .native_selection = native_selection,
        .azure_selection = azure_selection,
        .source_commit = fixture.source_commit,
        .candidate_run_id = "100",
        .run_id = "100",
    }, &diagnostic);
}

test "the release gate rejects missing, duplicate, extra, and unexpected native results" {
    {
        var subject = try tree();
        defer subject.deinit();
        try makeReleaseEvidence(&subject);
        const missing = try subject.nativeResultPath("aarch64-full");
        defer allocator.free(missing);
        try Dir.cwd().deleteFile(io, missing);
        try expectReleaseGateRejected(&subject);
    }
    {
        var subject = try tree();
        defer subject.deinit();
        try makeReleaseEvidence(&subject);
        const duplicate = try subject.nativeResultPath("aarch64-full");
        defer allocator.free(duplicate);
        try fixture.patchString(
            allocator,
            io,
            duplicate,
            &.{.{ .key = "key" }},
            "x86_64-full",
        );
        try expectReleaseGateRejected(&subject);
    }
    {
        var subject = try tree();
        defer subject.deinit();
        try makeReleaseEvidence(&subject);
        const unexpected = try subject.nativeResultPath("aarch64-full");
        defer allocator.free(unexpected);
        try fixture.patchString(
            allocator,
            io,
            unexpected,
            &.{.{ .key = "key" }},
            "riscv64-core",
        );
        try expectReleaseGateRejected(&subject);
    }
    {
        var subject = try tree();
        defer subject.deinit();
        try makeReleaseEvidence(&subject);
        const source_result = try subject.nativeResultPath("x86_64-core");
        defer allocator.free(source_result);
        const extra_dir = try subject.path("native/extra", .{});
        defer allocator.free(extra_dir);
        try Dir.cwd().createDirPath(io, extra_dir);
        const extra_result = try subject.path("native/extra/native-result.json", .{});
        defer allocator.free(extra_result);
        try Dir.cwd().copyFile(source_result, Dir.cwd(), extra_result, io, .{});
        try expectReleaseGateRejected(&subject);
    }
    {
        var subject = try tree();
        defer subject.deinit();
        try makeReleaseEvidence(&subject);
        const x86 = try subject.nativeResultPath("x86_64-full");
        defer allocator.free(x86);
        var x86_result = try fixture.read(allocator, io, x86);
        defer x86_result.deinit();
        const duplicate_digest = x86_result.value.object.get("candidate_sha256").?.string;
        const arm = try subject.nativeResultPath("aarch64-full");
        defer allocator.free(arm);
        try fixture.patchString(
            allocator,
            io,
            arm,
            &.{.{ .key = "candidate_sha256" }},
            duplicate_digest,
        );
        try expectReleaseGateRejected(&subject);
    }
}

test "the release gate rejects duplicate digests in two non-first native results" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});
    try fixture.makeBundle(&subject, "aarch64-full", .{});
    const shared_core_bytes = "shared core candidate bytes\n";
    try fixture.makeBundle(
        &subject,
        "x86_64-core",
        .{ .asset_bytes = shared_core_bytes },
    );
    try fixture.makeBundle(
        &subject,
        "aarch64-core",
        .{ .asset_bytes = shared_core_bytes },
    );
    for (contracts.release_order) |key| {
        try fixture.makeNativeResult(&subject, key, .{});
    }

    const first_asset = try subject.assetPath("x86_64-full");
    defer allocator.free(first_asset);
    const first_digest = try support.hashArtifact(io, first_asset);
    const x86_core_asset = try subject.assetPath("x86_64-core");
    defer allocator.free(x86_core_asset);
    const x86_core_digest = try support.hashArtifact(io, x86_core_asset);
    const arm_core_asset = try subject.assetPath("aarch64-core");
    defer allocator.free(arm_core_asset);
    const arm_core_digest = try support.hashArtifact(io, arm_core_asset);

    try std.testing.expect(!std.mem.eql(
        u8,
        &first_digest.hex,
        &x86_core_digest.hex,
    ));
    try std.testing.expectEqualStrings(&x86_core_digest.hex, &arm_core_digest.hex);

    var diagnostic: support.Diagnostic = .{};
    try std.testing.expectError(
        error.Failed,
        releaseGateWithDiagnostic(&subject, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "duplicate native acceptance digest",
        diagnostic.message(),
    );
}

test "the release gate rejects missing, duplicate, and extra candidate or Azure evidence" {
    var subject = try tree();
    defer subject.deinit();
    try makeReleaseEvidence(&subject);

    const candidate_key = "aarch64-core";
    const candidate = try subject.manifestPath(candidate_key);
    defer allocator.free(candidate);
    try Dir.cwd().deleteFile(io, candidate);
    try expectReleaseGateRejected(&subject);
    try remake(&subject, candidate_key);

    try fixture.patchString(
        allocator,
        io,
        candidate,
        &.{.{ .key = "key" }},
        "x86_64-core",
    );
    try expectReleaseGateRejected(&subject);
    try remake(&subject, candidate_key);

    const extra_candidate_dir = try subject.path("candidates/extra", .{});
    defer allocator.free(extra_candidate_dir);
    try Dir.cwd().createDirPath(io, extra_candidate_dir);
    const extra_candidate = try subject.path("candidates/extra/candidate.json", .{});
    defer allocator.free(extra_candidate);
    try Dir.cwd().copyFile(candidate, Dir.cwd(), extra_candidate, io, .{});
    try expectReleaseGateRejected(&subject);
    try Dir.cwd().deleteTree(io, extra_candidate_dir);

    const azure = try subject.azureResultPath(candidate_key);
    defer allocator.free(azure);
    try Dir.cwd().deleteFile(io, azure);
    try expectReleaseGateRejected(&subject);
    try remake(&subject, candidate_key);

    try fixture.patchString(
        allocator,
        io,
        azure,
        &.{.{ .key = "key" }},
        "x86_64-core",
    );
    try expectReleaseGateRejected(&subject);
    try remake(&subject, candidate_key);

    const extra_azure_dir = try subject.path("azure/extra", .{});
    defer allocator.free(extra_azure_dir);
    try Dir.cwd().createDirPath(io, extra_azure_dir);
    const extra_azure = try subject.path("azure/extra/azure-result.json", .{});
    defer allocator.free(extra_azure);
    try Dir.cwd().copyFile(azure, Dir.cwd(), extra_azure, io, .{});
    try expectReleaseGateRejected(&subject);
}

test "the release gate rejects stale or invalid native evidence" {
    var subject = try tree();
    defer subject.deinit();
    try makeReleaseEvidence(&subject);
    const key = "x86_64-full";
    const native = try subject.nativeResultPath(key);
    defer allocator.free(native);

    const mutations = [_]struct {
        steps: []const Step,
        change: fixture.Change,
    }{
        .{
            .steps = &.{.{ .key = "source_commit" }},
            .change = .{ .set = .{ .string = "b" ** 40 } },
        },
        .{
            .steps = &.{ .{ .key = "workflow" }, .{ .key = "run_attempt" } },
            .change = .{ .set = .{ .string = "2" } },
        },
        .{
            .steps = &.{.{ .key = "architecture" }},
            .change = .{ .set = .{ .string = "aarch64" } },
        },
        .{
            .steps = &.{.{ .key = "candidate_sha256" }},
            .change = .{ .set = .{ .string = "0" ** 64 } },
        },
        .{ .steps = &.{.{ .key = "schema" }}, .change = .{ .set = .{ .integer = 1 } } },
        .{ .steps = &.{.{ .key = "contracts" }}, .change = .pop },
        .{
            .steps = &.{.{ .key = "certificate_sha256" }},
            .change = .{ .set = .{ .string = "0" ** 64 } },
        },
        .{
            .steps = &.{.{ .key = "fallback_uki_sha256" }},
            .change = .{ .set = .{ .string = "0" ** 64 } },
        },
        .{
            .steps = &.{.{ .key = "status" }},
            .change = .{ .set = .{ .string = "failure" } },
        },
    };
    for (mutations) |mutation| {
        try fixture.patch(allocator, io, native, mutation.steps, mutation.change);
        try expectReleaseGateRejected(&subject);
        try fixture.makeNativeResult(&subject, key, .{});
    }

    try Dir.cwd().writeFile(io, .{ .sub_path = native, .data = "{" });
    try expectReleaseGateRejected(&subject);
}

test "the release gate rejects wrong QEMU accelerator and runner architecture" {
    var subject = try tree();
    defer subject.deinit();
    try makeReleaseEvidence(&subject);

    const cases = [_]struct {
        key: []const u8,
        field: []const u8,
        value: []const u8,
    }{
        .{ .key = "x86_64-full", .field = "accelerator", .value = "tcg" },
        .{ .key = "aarch64-full", .field = "accelerator", .value = "kvm" },
        .{ .key = "aarch64-core", .field = "accelerator", .value = "auto" },
        .{ .key = "aarch64-core", .field = "accelerator", .value = "unknown" },
        .{
            .key = "aarch64-core",
            .field = "runner_architecture",
            .value = "x86_64",
        },
    };
    for (cases) |case| {
        const result = try subject.nativeResultPath(case.key);
        defer allocator.free(result);
        try fixture.patchString(
            allocator,
            io,
            result,
            &.{ .{ .key = "execution" }, .{ .key = case.field } },
            case.value,
        );
        var diagnostic: support.Diagnostic = .{};
        try std.testing.expectError(
            error.Failed,
            releaseGateWithDiagnostic(&subject, &diagnostic),
        );
        const expected = try std.fmt.allocPrint(
            allocator,
            "{s}: QEMU execution identity is invalid",
            .{case.key},
        );
        defer allocator.free(expected);
        try std.testing.expectEqualStrings(expected, diagnostic.message());
        try fixture.makeNativeResult(&subject, case.key, .{});
    }
}

test "the release gate retains candidate and Azure fail-closed validation" {
    {
        var subject = try tree();
        defer subject.deinit();
        try makeReleaseEvidence(&subject);
        const azure = try subject.azureResultPath("aarch64-full");
        defer allocator.free(azure);
        try fixture.patchString(
            allocator,
            io,
            azure,
            &.{.{ .key = "status" }},
            "failure",
        );
        try expectReleaseGateRejected(&subject);
    }
    {
        var subject = try tree();
        defer subject.deinit();
        try makeReleaseEvidence(&subject);
        const azure = try subject.azureResultPath("x86_64-core");
        defer allocator.free(azure);
        try fixture.patchString(
            allocator,
            io,
            azure,
            &.{ .{ .key = "workflow" }, .{ .key = "run_id" } },
            "999",
        );
        try expectReleaseGateRejected(&subject);
    }
    {
        var subject = try tree();
        defer subject.deinit();
        try makeReleaseEvidence(&subject);
        const manifest = try subject.manifestPath("aarch64-core");
        defer allocator.free(manifest);
        try fixture.patchString(
            allocator,
            io,
            manifest,
            &.{ .{ .key = "workflow" }, .{ .key = "run_attempt" } },
            "2",
        );
        try expectReleaseGateRejected(&subject);
    }
    {
        var subject = try tree();
        defer subject.deinit();
        try makeReleaseEvidence(&subject);
        const asset = try subject.assetPath("x86_64-full");
        defer allocator.free(asset);
        try Dir.cwd().writeFile(io, .{ .sub_path = asset, .data = "tampered" });
        try expectReleaseGateRejected(&subject);
    }
}

test "the release gate rejects stale removed smoke evidence" {
    var subject = try tree();
    defer subject.deinit();
    try makeReleaseEvidence(&subject);
    const native = try subject.nativeResultPath("aarch64-core");
    defer allocator.free(native);
    try addLegacySmokeEvidence(native);
    try expectReleaseGateRejected(&subject);

    try fixture.makeNativeResult(&subject, "aarch64-core", .{});
    const azure = try subject.azureResultPath("aarch64-core");
    defer allocator.free(azure);
    try addLegacySmokeEvidence(azure);
    try expectReleaseGateRejected(&subject);
}

test "the core gate records only current candidate and acceptance digests" {
    var subject = try tree();
    defer subject.deinit();
    for ([_][]const u8{ "x86_64-core", "aarch64-core" }) |key| {
        try fixture.makeBundle(&subject, key, .{});
        try fixture.makeNativeResult(&subject, key, .{});
    }

    const candidates = try subject.candidates();
    defer allocator.free(candidates);
    const native = try subject.native();
    defer allocator.free(native);
    const azure = try subject.azure();
    defer allocator.free(azure);
    const output = try subject.path("validation.json", .{});
    defer allocator.free(output);
    var diagnostic: support.Diagnostic = .{};
    try release_workflow.coreGate(allocator, io, .{
        .candidates = candidates,
        .native_results = native,
        .azure_results = azure,
        .output = output,
        .source_commit = fixture.source_commit,
        .candidate_run_id = "100",
        .candidate_run_attempt = "1",
        .run_id = "100",
        .run_attempt = "1",
    }, &diagnostic);

    var document = try fixture.read(allocator, io, output);
    defer document.deinit();
    try std.testing.expectEqual(
        @as(i64, 3),
        document.value.object.get("schema").?.integer,
    );
    const records = document.value.object.get("candidates").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), records.len);
    for (records) |record| {
        try std.testing.expect(record.object.get("android_" ++ "smoke") == null);
        try std.testing.expect(support.isSha256(
            record.object.get("native_result_sha256").?.string,
        ));
        try std.testing.expect(support.isSha256(
            record.object.get("azure_result_sha256").?.string,
        ));
    }
}

test "a successful stage publishes exactly four full and core assets" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    try stage(&subject, publication_tag);

    const manifest_path = try subject.path("staged/publish-manifest.json", .{});
    defer allocator.free(manifest_path);
    var manifest = try fixture.read(allocator, io, manifest_path);
    defer manifest.deinit();
    const document = manifest.value.object;

    try std.testing.expectEqual(@as(i64, 2), document.get("schema").?.integer);
    try std.testing.expectEqualStrings(
        "miz-ubuntu2604-release",
        document.get("type").?.string,
    );
    try std.testing.expectEqualStrings(
        fixture.source_commit,
        document.get("source_commit").?.string,
    );
    try std.testing.expectEqualStrings(
        &fixture.certificateSha256(),
        document.get("certificate_sha256").?.string,
    );
    try std.testing.expectEqualStrings(
        fixture.signing_certificate_sha256,
        document.get("signing_certificate_sha256").?.string,
    );
    try std.testing.expect(documents.hasWorkflowIdentity(
        document.get("publication_workflow"),
    ));
    try std.testing.expectEqualStrings(
        "3",
        document.get("publication_workflow").?.object.get("run_attempt").?.string,
    );

    const assets = document.get("assets").?.array.items;
    try std.testing.expectEqual(contracts.release_order.len, assets.len);
    for (assets, contracts.release_order) |asset, key| {
        try std.testing.expectEqualStrings(
            contracts.lookup(key).?.asset_name,
            asset.object.get("asset_name").?.string,
        );
        try std.testing.expect(documents.hasWorkflowIdentity(
            asset.object.get("candidate_workflow"),
        ));
        try std.testing.expect(documents.hasWorkflowIdentity(
            asset.object.get("native_workflow"),
        ));
        try std.testing.expect(documents.hasWorkflowIdentity(
            asset.object.get("azure_workflow"),
        ));
        const staged = try subject.path(
            "staged/{s}",
            .{contracts.lookup(key).?.asset_name},
        );
        defer allocator.free(staged);
        try std.testing.expect(support.isRegularFile(io, staged));
    }

    const notes_path = try subject.path("release-notes.md", .{});
    defer allocator.free(notes_path);
    const notes = try Dir.cwd().readFileAlloc(
        io,
        notes_path,
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(notes);
    const required_notes = [_][]const u8{
        "Ubuntu 26.04 full/server and core/appliance",
        "systemd, cloud-init, WALinuxAgent",
        "mizinit, azagent, supervised OpenSSH",
        "exact 5 GiB",
        "3584 MiB (3.5 GiB), 30% smaller",
        "same-architecture QEMU acceptance (x86_64 KVM; AArch64 TCG)",
        "explicit multi-threaded TCG",
        "no accelerator probing or fallback",
        "Azure Trusted Launch",
        "signed in-tree Binder with BinderFS and DMA-heap probes",
        "standalone zstd QCOW2 files with no backing images",
        "finalized release is immutable",
        "separate digest-pinned handoff",
        "candidate run `100` attempt `1`",
        "native acceptance run `100` attempt `1`",
        "Azure acceptance run `100` attempt `1`",
    };
    for (required_notes) |text| {
        try std.testing.expect(std.mem.indexOf(u8, notes, text) != null);
    }
    try std.testing.expect(std.mem.indexOf(
        u8,
        notes,
        "No checksum sidecar assets are published",
    ) != null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(notes, "android container") == null);
}

test "staged publication records each candidate attempt exactly" {
    const attempts: Attempts = .{ "1", "1", "2", "1" };
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    for (contracts.release_order, 0..) |key, index| {
        const manifest = try subject.manifestPath(key);
        defer allocator.free(manifest);
        try fixture.patchString(
            allocator,
            io,
            manifest,
            &.{ .{ .key = "workflow" }, .{ .key = "run_attempt" } },
            attempts[index],
        );
        for ([_][]const u8{
            try subject.nativeResultPath(key),
            try subject.azureResultPath(key),
        }) |path| {
            defer allocator.free(path);
            try fixture.patchString(
                allocator,
                io,
                path,
                &.{ .{ .key = "candidate_workflow" }, .{ .key = "run_attempt" } },
                attempts[index],
            );
        }
    }
    try stage(&subject, publication_tag);

    const manifest_path = try subject.path("staged/publish-manifest.json", .{});
    defer allocator.free(manifest_path);
    var manifest = try fixture.read(allocator, io, manifest_path);
    defer manifest.deinit();
    for (manifest.value.object.get("assets").?.array.items, 0..) |asset, index| {
        try std.testing.expectEqualStrings(
            attempts[index],
            asset.object
                .get("candidate_workflow").?
                .object
                .get("run_attempt").?
                .string,
        );
    }
}

test "stage rejects candidate and acceptance evidence from the wrong run" {
    const cases = [_]struct {
        path_kind: enum { candidate, native, azure },
        field: []const u8,
    }{
        .{ .path_kind = .candidate, .field = "workflow" },
        .{ .path_kind = .native, .field = "workflow" },
        .{ .path_kind = .azure, .field = "workflow" },
    };
    for (cases) |case| {
        var subject = try tree();
        defer subject.deinit();
        try makeAll(&subject);
        const path = switch (case.path_kind) {
            .candidate => try subject.manifestPath("x86_64-full"),
            .native => try subject.nativeResultPath("x86_64-full"),
            .azure => try subject.azureResultPath("x86_64-full"),
        };
        defer allocator.free(path);
        try fixture.patchString(
            allocator,
            io,
            path,
            &.{ .{ .key = case.field }, .{ .key = "run_id" } },
            "101",
        );
        try expectStageRejected(&subject);
    }
}

test "stage rejects acceptance evidence from a future publication attempt" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const native = try subject.nativeResultPath("x86_64-full");
    defer allocator.free(native);
    try fixture.patchString(
        allocator,
        io,
        native,
        &.{ .{ .key = "workflow" }, .{ .key = "run_attempt" } },
        "4",
    );
    try expectStageRejected(&subject);
}

test "stage rejects stale removed smoke evidence" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const azure = try subject.azureResultPath("aarch64-core");
    defer allocator.free(azure);
    try addLegacySmokeEvidence(azure);
    try expectStageRejected(&subject);
}

test "image-info validation requires standalone zstd QCOW2 bytes" {
    var subject = try tree();
    defer subject.deinit();
    const info = try subject.path("image-info.json", .{});
    defer allocator.free(info);
    var diagnostic: support.Diagnostic = .{};

    try Dir.cwd().writeFile(io, .{
        .sub_path = info,
        .data =
        \\{"format":"qcow2","virtual-size":2097152,
        \\"backing-filename":"","full-backing-filename":null,
        \\"format-specific":{"data":{"compression-type":"zstd"}}}
        ,
    });
    try release.workflow.verifyImageInfo(
        allocator,
        io,
        info,
        fixture.virtual_size,
        "fixture size",
        &diagnostic,
    );

    try fixture.patchString(
        allocator,
        io,
        info,
        &.{.{ .key = "backing-filename" }},
        "base.qcow2",
    );
    try std.testing.expectError(error.Failed, release.workflow.verifyImageInfo(
        allocator,
        io,
        info,
        fixture.virtual_size,
        "fixture size",
        &diagnostic,
    ));
}

test "the candidate and Azure result schemas bind the published bytes" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});

    const manifest_path = try subject.manifestPath("x86_64-full");
    defer allocator.free(manifest_path);
    var candidate = try fixture.read(allocator, io, manifest_path);
    defer candidate.deinit();
    const result_path = try subject.azureResultPath("x86_64-full");
    defer allocator.free(result_path);
    var azure = try fixture.read(allocator, io, result_path);
    defer azure.deinit();

    const candidate_object = candidate.value.object;
    const azure_object = azure.value.object;
    try std.testing.expectEqualStrings(
        "ubuntu2604-candidate",
        candidate_object.get("type").?.string,
    );
    try std.testing.expectEqualStrings(
        "ubuntu2604-azure-acceptance",
        azure_object.get("type").?.string,
    );
    const digest = candidate_object.get("sha256").?.string;
    try std.testing.expectEqualStrings(
        digest,
        azure_object.get("qcow_sha256").?.string,
    );
    try std.testing.expectEqualStrings(
        digest,
        azure_object.get("azure_accepted_sha256").?.string,
    );
    const conversion = azure_object.get("conversion").?.object;
    try std.testing.expectEqualStrings(
        digest,
        conversion.get("source").?.object.get("sha256_before").?.string,
    );
    try std.testing.expectEqual(
        candidate_object.get("virtual_size").?.integer,
        conversion.get("parameters").?.object.get("expected_virtual_size").?.integer,
    );
    try std.testing.expect(support.isExactOrderedStrings(
        azure_object.get("contracts"),
        &contracts.full_azure_contracts,
    ));
    try std.testing.expect(support.isExactOrderedStrings(
        candidate_object.get("azure_contracts"),
        &contracts.full_azure_contracts,
    ));
}

test "the core candidate and result bind flavor metadata and contracts" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-core";
    try fixture.makeBundle(&subject, key, .{});
    try validateAzure(&subject, key);

    const manifest_path = try subject.manifestPath(key);
    defer allocator.free(manifest_path);
    var candidate = try fixture.read(allocator, io, manifest_path);
    defer candidate.deinit();
    const result_path = try subject.azureResultPath(key);
    defer allocator.free(result_path);
    var azure = try fixture.read(allocator, io, result_path);
    defer azure.deinit();

    const candidate_object = candidate.value.object;
    const azure_object = azure.value.object;
    try std.testing.expectEqualStrings("core", candidate_object.get("flavor").?.string);
    try std.testing.expectEqualStrings(
        "Ubuntu-26.04-x86_64.core.qcow2",
        candidate_object.get("asset_name").?.string,
    );
    try std.testing.expect(support.isExactOrderedStrings(
        candidate_object.get("azure_contracts"),
        &contracts.core_azure_contracts,
    ));
    for ([_][]const u8{
        "source_commit",
        "architecture",
        "flavor",
        "asset_name",
    }) |field| {
        try std.testing.expectEqualStrings(
            candidate_object.get(field).?.string,
            azure_object.get(field).?.string,
        );
    }
    const signing = candidate_object.get("uki_signing").?.object;
    try std.testing.expectEqualStrings(
        candidate_object.get("sha256").?.string,
        azure_object.get("qcow_sha256").?.string,
    );
    for ([_][]const u8{
        "certificate_sha256",
        "signing_certificate_sha256",
        "fallback_uki_sha256",
    }) |field| {
        try std.testing.expectEqualStrings(
            signing.get(field).?.string,
            azure_object.get(field).?.string,
        );
    }
    try std.testing.expect(support.jsonEqual(
        azure_object.get("contracts").?,
        candidate_object.get("azure_contracts").?,
    ));
}

fn writeNativeResult(subject: *const Tree, key: []const u8) ![]u8 {
    try fixture.makeNativeResult(subject, key, .{});
    return subject.nativeResultPath(key);
}

fn validateNative(subject: *const Tree, key: []const u8, path: []const u8) !void {
    var candidate = try verify(subject, key);
    defer candidate.deinit();
    var diagnostic: support.Diagnostic = .{};
    var result = try documents.validateNativeResult(
        allocator,
        io,
        &candidate,
        path,
        &diagnostic,
    );
    result.deinit();
}

test "the full native result binds complete candidate and workflow identity" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const native_path = try writeNativeResult(&subject, key);
    defer allocator.free(native_path);
    try validateNative(&subject, key, native_path);

    var result = try fixture.read(allocator, io, native_path);
    defer result.deinit();
    const object = result.value.object;
    try std.testing.expectEqual(@as(i64, 4), object.get("schema").?.integer);
    try std.testing.expectEqualStrings(key, object.get("key").?.string);
    try std.testing.expectEqualStrings(
        "x86_64",
        object.get("architecture").?.string,
    );
    try std.testing.expectEqualStrings(
        "Ubuntu-26.04-x86_64.qcow2",
        object.get("asset_name").?.string,
    );
    try std.testing.expectEqualStrings(
        fixture.source_commit,
        object.get("source_commit").?.string,
    );
    try std.testing.expectEqualStrings("success", object.get("status").?.string);
    const candidate_workflow = object.get("candidate_workflow").?.object;
    try std.testing.expectEqualStrings(
        "100",
        candidate_workflow.get("run_id").?.string,
    );
    try std.testing.expectEqualStrings(
        "1",
        candidate_workflow.get("run_attempt").?.string,
    );
    try std.testing.expect(documents.hasWorkflowIdentity(object.get("workflow")));
    try std.testing.expect(support.hasExactContracts(
        object.get("contracts"),
        &contracts.full_native_contracts,
    ));
    const qemu = object.get("execution").?.object;
    try std.testing.expectEqualStrings("kvm", qemu.get("accelerator").?.string);
    try std.testing.expectEqualStrings("host", qemu.get("cpu").?.string);
    try std.testing.expectEqualStrings(
        "/usr/bin/qemu-system-x86_64",
        qemu.get("emulator").?.string,
    );
    try std.testing.expectEqualStrings(
        "x86_64",
        qemu.get("guest_architecture").?.string,
    );
    try std.testing.expectEqualStrings("q35", qemu.get("machine").?.string);
    try std.testing.expectEqualStrings(
        "x86_64",
        qemu.get("runner_architecture").?.string,
    );

    const virtual_size = object.get("virtual_size").?.integer;
    const mutations = [_]struct {
        steps: []const Step,
        change: fixture.Change,
    }{
        .{ .steps = &.{.{ .key = "schema" }}, .change = .{ .set = .{ .integer = 2 } } },
        .{
            .steps = &.{.{ .key = "key" }},
            .change = .{ .set = .{ .string = "aarch64-full" } },
        },
        .{
            .steps = &.{.{ .key = "architecture" }},
            .change = .{ .set = .{ .string = "aarch64" } },
        },
        .{
            .steps = &.{.{ .key = "asset_name" }},
            .change = .{ .set = .{ .string = "Ubuntu-26.04-aarch64.qcow2" } },
        },
        .{
            .steps = &.{.{ .key = "source_commit" }},
            .change = .{ .set = .{ .string = "b" ** 40 } },
        },
        .{
            .steps = &.{.{ .key = "virtual_size" }},
            .change = .{ .set = .{ .integer = virtual_size + 1 } },
        },
        .{
            .steps = &.{.{ .key = "candidate_sha256" }},
            .change = .{ .set = .{ .string = "0" ** 64 } },
        },
        .{
            .steps = &.{.{ .key = "certificate_sha256" }},
            .change = .{ .set = .{ .string = "0" ** 64 } },
        },
        .{
            .steps = &.{.{ .key = "fallback_uki_sha256" }},
            .change = .{ .set = .{ .string = "0" ** 64 } },
        },
        .{ .steps = &.{.{ .key = "contracts" }}, .change = .pop },
        .{
            .steps = &.{.{ .key = "status" }},
            .change = .{ .set = .{ .string = "failure" } },
        },
        .{
            .steps = &.{ .{ .key = "execution" }, .{ .key = "accelerator" } },
            .change = .{ .set = .{ .string = "auto" } },
        },
        .{
            .steps = &.{ .{ .key = "execution" }, .{ .key = "runner_architecture" } },
            .change = .{ .set = .{ .string = "aarch64" } },
        },
        .{
            .steps = &.{ .{ .key = "execution" }, .{ .key = "emulator" } },
            .change = .{ .set = .{ .string = "/usr/bin/qemu-system-aarch64" } },
        },
        .{
            .steps = &.{ .{ .key = "execution" }, .{ .key = "guest_architecture" } },
            .change = .{ .set = .{ .string = "aarch64" } },
        },
        .{
            .steps = &.{ .{ .key = "execution" }, .{ .key = "machine" } },
            .change = .{ .set = .{ .string = "virt" } },
        },
        .{
            .steps = &.{ .{ .key = "execution" }, .{ .key = "cpu" } },
            .change = .{ .set = .{ .string = "max" } },
        },
        .{
            .steps = &.{ .{ .key = "execution" }, .{ .key = "mode" } },
            .change = .{ .set = .{ .string = "auto" } },
        },
        .{
            .steps = &.{ .{ .key = "execution" }, .{ .key = "accelerator" } },
            .change = .remove,
        },
        .{
            .steps = &.{ .{ .key = "workflow" }, .{ .key = "run_id" } },
            .change = .{ .set = .{ .string = "" } },
        },
    };
    for (mutations) |mutation| {
        try fixture.patch(allocator, io, native_path, mutation.steps, mutation.change);
        try std.testing.expectError(
            error.Failed,
            validateNative(&subject, key, native_path),
        );
        try fixture.makeNativeResult(&subject, key, .{});
    }
}

test "acceptance evidence rejects a mismatched candidate workflow attempt" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    try fixture.makeNativeResult(&subject, key, .{});

    const native = try subject.nativeResultPath(key);
    defer allocator.free(native);
    try fixture.patchString(
        allocator,
        io,
        native,
        &.{ .{ .key = "candidate_workflow" }, .{ .key = "run_attempt" } },
        "2",
    );
    try std.testing.expectError(
        error.Failed,
        validateNative(&subject, key, native),
    );

    const azure = try subject.azureResultPath(key);
    defer allocator.free(azure);
    try fixture.patchString(
        allocator,
        io,
        azure,
        &.{ .{ .key = "candidate_workflow" }, .{ .key = "run_attempt" } },
        "2",
    );
    try expectAzureRejected(&subject, key);
}

test "the core native result binds the candidate identity and contracts" {
    var subject = try tree();
    defer subject.deinit();
    const key = "aarch64-core";
    try fixture.makeBundle(&subject, key, .{});

    const manifest_path = try subject.manifestPath(key);
    defer allocator.free(manifest_path);
    var candidate = try fixture.read(allocator, io, manifest_path);
    defer candidate.deinit();
    const native_path = try writeNativeResult(&subject, key);
    defer allocator.free(native_path);
    try validateNative(&subject, key, native_path);

    var result = try fixture.read(allocator, io, native_path);
    defer result.deinit();
    try std.testing.expectEqualStrings(
        "aarch64",
        result.value.object.get("architecture").?.string,
    );
    try std.testing.expectEqualStrings(
        "core",
        result.value.object.get("flavor").?.string,
    );
    try std.testing.expectEqual(
        @as(i64, 9),
        result.value.object.get("schema").?.integer,
    );
    try std.testing.expect(support.hasExactContracts(
        result.value.object.get("contracts"),
        &contracts.core_native_contracts,
    ));
    const qemu = result.value.object.get("execution").?.object;
    try std.testing.expectEqualStrings("tcg", qemu.get("accelerator").?.string);
    try std.testing.expectEqualStrings("max", qemu.get("cpu").?.string);
    try std.testing.expectEqualStrings(
        "/usr/bin/qemu-system-aarch64",
        qemu.get("emulator").?.string,
    );
    try std.testing.expectEqualStrings(
        "aarch64",
        qemu.get("guest_architecture").?.string,
    );
    try std.testing.expectEqualStrings("virt", qemu.get("machine").?.string);
    try std.testing.expectEqualStrings(
        "aarch64",
        qemu.get("runner_architecture").?.string,
    );

    const virtual_size = candidate.value.object.get("virtual_size").?.integer;
    const mutations = [_]struct {
        steps: []const Step,
        change: fixture.Change,
    }{
        .{ .steps = &.{.{ .key = "schema" }}, .change = .{ .set = .{ .integer = 7 } } },
        .{
            .steps = &.{.{ .key = "key" }},
            .change = .{ .set = .{ .string = "x86_64-core" } },
        },
        .{
            .steps = &.{.{ .key = "architecture" }},
            .change = .{ .set = .{ .string = "x86_64" } },
        },
        .{
            .steps = &.{.{ .key = "source_commit" }},
            .change = .{ .set = .{ .string = "b" ** 40 } },
        },
        .{
            .steps = &.{.{ .key = "virtual_size" }},
            .change = .{ .set = .{ .integer = virtual_size + 1 } },
        },
        .{
            .steps = &.{.{ .key = "candidate_sha256" }},
            .change = .{ .set = .{ .string = "0" ** 64 } },
        },
        .{ .steps = &.{.{ .key = "contracts" }}, .change = .pop },
        .{
            .steps = &.{.{ .key = "status" }},
            .change = .{ .set = .{ .string = "failure" } },
        },
        .{
            .steps = &.{ .{ .key = "workflow" }, .{ .key = "run_attempt" } },
            .change = .{ .set = .{ .string = "" } },
        },
        .{
            .steps = &.{ .{ .key = "execution" }, .{ .key = "accelerator" } },
            .change = .{ .set = .{ .string = "kvm" } },
        },
        .{
            .steps = &.{ .{ .key = "execution" }, .{ .key = "runner_architecture" } },
            .change = .{ .set = .{ .string = "x86_64" } },
        },
    };
    for (mutations) |mutation| {
        try fixture.patch(allocator, io, native_path, mutation.steps, mutation.change);
        try std.testing.expectError(
            error.Failed,
            validateNative(&subject, key, native_path),
        );
        allocator.free(try writeNativeResult(&subject, key));
    }

    try addLegacySmokeEvidence(native_path);
    try std.testing.expectError(
        error.Failed,
        validateNative(&subject, key, native_path),
    );
}

test "the contract sets cover the acceptance each flavor actually performs" {
    // Full Azure acceptance: Trusted Launch, the enrolled signer, and the
    // cloud-init/WALinuxAgent server contract.
    try std.testing.expectEqualDeep(
        &[_][]const u8{
            "agent-ready",
            "cloud-init-provisioning",
            "kernel-lockdown",
            "key-only-ssh",
            "managed-data-disk",
            "matching-architecture-gen2",
            "module-signatures",
            "reboot-reconnect",
            "root-growth",
            "runtime-release-identity",
            "secure-boot",
            "signed-uki",
            "trusted-launch",
            "uefi-db-signer",
            "vtpm",
        },
        &contracts.full_azure_contracts,
    );
    // Core Azure acceptance: the appliance contract plus signed in-tree
    // Binder, BinderFS, and dynamic-device usability.
    try std.testing.expectEqualDeep(
        &[_][]const u8{
            "agent-ready",
            "azagent-provisioning",
            "binder-devices-usable",
            "binder-module-signed",
            "binderfs-mounted",
            "dma-heap-device",
            "identity-persistence",
            "kernel-lockdown",
            "key-only-ssh",
            "managed-data-disk-mount-only",
            "matching-architecture-gen2",
            "mizinit-pid1",
            "module-signatures",
            "no-anbox-evidence",
            "no-cloud-init",
            "no-dkms-binder-module",
            "no-systemd-service-manager",
            "no-walinuxagent",
            "pid1-supervised-sshd",
            "reboot-reconnect",
            "resource-disk",
            "root-growth",
            "runtime-contract",
            "runtime-release-identity",
            "secure-boot",
            "signed-uki",
            "sshd-restart-reconnect",
            "trusted-launch",
            "uefi-db-signer",
            "vtpm",
        },
        &contracts.core_azure_contracts,
    );
    try std.testing.expectEqualDeep(
        &[_][]const u8{
            "clean-service-health",
            "cloud-init-provisioning",
            "generalized-identity",
            "gpt-layout",
            "kernel-lockdown",
            "key-only-ssh",
            "module-signatures",
            "netplan-networkd",
            "reboot-reconnect",
            "root-growth",
            "same-architecture-qemu",
            "secure-boot",
            "signed-uki",
            "standalone-zstd-qcow2",
            "tampered-uki-rejected",
            "uefi-db-signer",
            "vtpm",
            "walinuxagent",
        },
        &contracts.full_native_contracts,
    );
    try std.testing.expectEqualDeep(
        &[_][]const u8{
            "azagent-provisioning",
            "binder-boot-required",
            "binder-device-usability",
            "binderfs-dynamic-devices",
            "clean-service-health",
            "dma-heap-device",
            "generalized-identity",
            "gpt-layout",
            "kernel-lockdown",
            "key-only-ssh",
            "local-ovf-azagent-skip-ready",
            "mizinit-pid1",
            "mizinit-sshd-supervision",
            "module-signatures",
            "no-cloud-init",
            "no-walinuxagent",
            "persistent-provisioned-state",
            "reboot-reconnect",
            "root-growth",
            "runtime-contract",
            "same-architecture-qemu",
            "secure-boot",
            "signed-binder-module",
            "signed-uki",
            "sshd-restart",
            "standalone-zstd-qcow2",
            "tampered-uki-rejected",
            "uefi-db-signer",
            "vtpm",
        },
        &contracts.core_native_contracts,
    );
}

test "Azure root growth is measured from the original root geometry" {
    var script = try @import("ubuntu2604_source.zig").Source.open(
        allocator,
        "scripts/ubuntu2604_azure_acceptance.sh",
    );
    defer script.deinit();
    try script.expectContains("x86_64) root_first_lba=2324480");
    try script.expectContains("aarch64) root_first_lba=2099200");
    try script.expectContains(
        "original_root_size=$(((last_usable_lba - root_first_lba + 1) * gpt_sector_size))",
    );
    try script.expectContains(
        "minimum_grown_root_size=$((original_root_size + 1073741824))",
    );
    try script.expectContains("test \"$root_size\" -gt \"$minimum_grown_root_size\"");
    try script.expectOmits("test \"$root_size\" -gt $((original_size + 1073741824))");

    // The growth threshold has to be reachable from the enlarged disk and
    // unreachable from the source disk, for both architectures.
    const source_disk_size: u64 = 5 * 1024 * 1024 * 1024;
    const expanded_disk_size: u64 = 7 * 1024 * 1024 * 1024;
    const gibibyte: u64 = 1024 * 1024 * 1024;
    for ([_]u64{ 2324480, 2099200 }) |first_lba| {
        const original = rootSize(source_disk_size, first_lba);
        const maximum = rootSize(expanded_disk_size, first_lba);
        try std.testing.expect(maximum < source_disk_size + gibibyte);
        try std.testing.expect(maximum > original + gibibyte);
    }
}

fn rootSize(disk_size: u64, first_lba: u64) u64 {
    const sector_size: u64 = 512;
    const partition_array_sectors: u64 = 32;
    const last_usable_lba = disk_size / sector_size - 2 - partition_array_sectors;
    return (last_usable_lba - first_lba + 1) * sector_size;
}

test "the full Azure service contract matches Ubuntu 26.04" {
    var script = try @import("ubuntu2604_source.zig").Source.open(
        allocator,
        "scripts/ubuntu2604_azure_acceptance.sh",
    );
    defer script.deinit();
    try script.expectContains("cloud-init-network.service");
    try script.expectOmits("cloud-init.service");
    try script.expectContains(
        "check network-online systemctl is-active --quiet network-online.target",
    );
    try script.expectOmits("networkctl is-online");
    try script.expectContains("FAIL %s (exit %s)");
    try script.expectContains("networkd-dispatcher.service");
    try script.expectContains("check udisks2-installed package_installed udisks2");
    try script.expectContains("Name=org.freedesktop.UDisks2");
    try script.expectContains("SystemdService=udisks2.service");
    try script.expectContains("udisks2-graphical-eager-start-absent");
    try script.expectContains(
        "mount -t efivarfs efivarfs /sys/firmware/efi/efivars",
    );
    try script.expectContains("failed_units=$(systemctl --failed --no-legend --plain)");
    try script.expectContains("check no-failed-units test -z");
    try script.expectContains(
        "systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,TimeoutStartUSec",
    );
    try script.expectContains(
        "sudo -n journalctl --no-pager --boot=0 --unit \"$unit\" --priority=info..emerg --lines=120",
    );
    try script.expectContains("head -c 49152");
    try script.expectContains("head -n 8");
    try script.expectContains("diagnose_failed_units\n  exit 1");
    const cloud_init_wait = std.mem.indexOf(
        u8,
        script.text,
        "check cloud-init-wait cloud-init status --wait",
    ).?;
    const service_checks = std.mem.indexOf(
        u8,
        script.text,
        "for unit in cloud-init-local.service",
    ).?;
    try std.testing.expect(cloud_init_wait < service_checks);
    try script.expectOmits(
        "test \"$(systemctl --failed --no-legend --plain | wc -l)\" -eq 0",
    );
    try script.expectOmits("--property=Environment");
    try script.expectContains(
        "check conventional-resource-disk-policy validate_conventional_resource_disk",
    );
    try script.expectOmits(
        "check conventional-resource-disk-not-mounted not_mountpoint /mnt",
    );
    try script.expectContains("instanceView.bootDiagnostics.serialConsoleLogBlobUri");
}

test "Azure Secure Boot loads required modules and accepts only in-tree Binder" {
    var script = try @import("ubuntu2604_source.zig").Source.open(
        allocator,
        "scripts/ubuntu2604_azure_acceptance.sh",
    );
    defer script.deinit();
    try script.expectContains(
        "if ! test -d \"/sys/module/$module\"; then\n    sudo -n /usr/sbin/modprobe \"$module\"",
    );
    try script.expectOmits(
        "if ! test -d \"/sys/module/$module\" && [[ \"$flavor\" == full ]]",
    );
    try script.expectContains(
        "/lib/modules/*/kernel/*|/usr/lib/modules/*/kernel/*",
    );
    try script.expectContains("test -n \"$module_signer\"");
    try script.expectContains("test \"$module_sig_id\" = \"PKCS#7\"");
}

test "Azure Binder probe transfer has exactly one SSH stdin source" {
    var script = try @import("ubuntu2604_source.zig").Source.open(
        allocator,
        "scripts/ubuntu2604_azure_acceptance.sh",
    );
    defer script.deinit();
    try script.expectContains(
        "base64 -w0 \"$BINDER_PROBE\" | ssh \"${ssh_options[@]}\" \"$ssh_target\"",
    );
    try script.expectContains(
        "base64 -d >'$binder_probe_remote'; chmod 0700 '$binder_probe_remote'",
    );
    try script.expectOmits(
        "\"/usr/bin/bash -s -- '$binder_probe_remote'\" <<'GUEST'\nset -euo pipefail\nremote=$1",
    );
    try script.expectContains(
        "test \"$binder_probe_remote_sha256\" = \"$binder_probe_sha256\"",
    );
}

test "an Azure result whose contracts are not the candidate's is rejected" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-core";
    try fixture.makeBundle(&subject, key, .{});
    const result_path = try subject.azureResultPath(key);
    defer allocator.free(result_path);

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = support.Builder.init(arena.allocator());
    try fixture.patch(
        allocator,
        io,
        result_path,
        &.{.{ .key = "contracts" }},
        .{ .set = try builder.strings(&contracts.full_azure_contracts) },
    );
    try expectAzureRejected(&subject, key);
}

test "the core Azure result rejects every candidate binding change" {
    const key = "x86_64-core";
    const mutations = [_]struct { field: []const u8, replacement: []const u8 }{
        .{ .field = "source_commit", .replacement = "b" ** 40 },
        .{ .field = "architecture", .replacement = "aarch64" },
        .{
            .field = "asset_name",
            .replacement = "Ubuntu-26.04-aarch64.core.qcow2",
        },
        .{ .field = "qcow_sha256", .replacement = "0" ** 64 },
        .{ .field = "certificate_sha256", .replacement = "1" ** 64 },
        .{ .field = "signing_certificate_sha256", .replacement = "2" ** 64 },
        .{ .field = "fallback_uki_sha256", .replacement = "9" ** 64 },
    };
    for (mutations) |mutation| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, key, .{});
        const result_path = try subject.azureResultPath(key);
        defer allocator.free(result_path);
        try fixture.patchString(
            allocator,
            io,
            result_path,
            &.{.{ .key = mutation.field }},
            mutation.replacement,
        );
        try expectAzureRejected(&subject, key);
    }
}

test "Azure result schemas reject stale removed smoke evidence" {
    const cases = [_]struct {
        key: []const u8,
        schema: i64,
        stale_schema: i64,
    }{
        .{ .key = "x86_64-full", .schema = 2, .stale_schema = 1 },
        .{ .key = "aarch64-core", .schema = 4, .stale_schema = 3 },
    };
    for (cases) |case| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, case.key, .{});
        const result_path = try subject.azureResultPath(case.key);
        defer allocator.free(result_path);

        var result = try fixture.read(allocator, io, result_path);
        try std.testing.expectEqual(
            case.schema,
            result.value.object.get("schema").?.integer,
        );
        try std.testing.expect(result.value.object.get("android_" ++ "smoke") == null);
        result.deinit();
        try validateAzure(&subject, case.key);

        try fixture.patchInteger(
            allocator,
            io,
            result_path,
            &.{.{ .key = "schema" }},
            case.stale_schema,
        );
        try expectAzureRejected(&subject, case.key);
        try fixture.patchInteger(
            allocator,
            io,
            result_path,
            &.{.{ .key = "schema" }},
            case.schema,
        );
        try addLegacySmokeEvidence(result_path);
        try expectAzureRejected(&subject, case.key);
    }
}

/// Re-runs `azure-result` with one option changed, which is how the command's
/// own argument contract is probed.
fn rerunAzureResult(
    subject: *const Tree,
    key: []const u8,
    mutate: *const fn (*commands.AzureResultOptions) void,
) !void {
    const entry = contracts.lookup(key).?;
    const flavor = contracts.parseFlavor(entry.flavor).?;
    const manifest = try subject.manifestPath(key);
    defer allocator.free(manifest);
    const asset = try subject.assetPath(key);
    defer allocator.free(asset);
    const vhd = try subject.path("azure/{s}/temporary.vhd", .{key});
    defer allocator.free(vhd);
    const vhd_info = try subject.path("azure/{s}/vhd-info.json", .{key});
    defer allocator.free(vhd_info);
    const conversion = try subject.path(
        "azure/{s}/conversion-attestation.json",
        .{key},
    );
    defer allocator.free(conversion);
    const request = try subject.path("azure/{s}/request.json", .{key});
    defer allocator.free(request);
    const response = try subject.path("azure/{s}/response.json", .{key});
    defer allocator.free(response);
    const output = try subject.path("azure/{s}/rerun.json", .{key});
    defer allocator.free(output);
    const resource_group = try std.fmt.allocPrint(allocator, "ubuntu-{s}", .{key});
    defer allocator.free(resource_group);
    const image_version_id = try std.fmt.allocPrint(
        allocator,
        "/subscriptions/test/gallery/ubuntu/{s}/versions/1.0.0",
        .{key},
    );
    defer allocator.free(image_version_id);
    const contract_list = try fixture.joinContracts(
        allocator,
        contracts.azureContracts(flavor),
    );
    defer allocator.free(contract_list);

    var options = fixture.azureResultOptions(.{
        .manifest = manifest,
        .asset = asset,
        .vhd = vhd,
        .vhd_info = vhd_info,
        .conversion = conversion,
        .key = key,
        .request = request,
        .response = response,
        .contracts = contract_list,
        .resource_group = resource_group,
        .image_version_id = image_version_id,
        .output = output,
    });
    mutate(&options);
    var diagnostic: support.Diagnostic = .{};
    return commands.azureResult(allocator, io, options, &diagnostic);
}

fn useFullContracts(options: *commands.AzureResultOptions) void {
    options.contracts = "agent-ready,cloud-init-provisioning,kernel-lockdown," ++
        "key-only-ssh,managed-data-disk,matching-architecture-gen2," ++
        "module-signatures,reboot-reconnect,root-growth," ++
        "runtime-release-identity,secure-boot,signed-uki,trusted-launch," ++
        "uefi-db-signer,vtpm";
}

test "azure-result rejects a non-canonical contract argument" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-core", .{});
    try std.testing.expectError(
        error.Failed,
        rerunAzureResult(&subject, "x86_64-core", useFullContracts),
    );
}

test "an unknown flavor has no Azure contract set" {
    try std.testing.expect(contracts.parseFlavor("minimal") == null);
    try std.testing.expect(contracts.parseFlavor("") == null);
}

test "candidate rejects a build-validation digest that is not the asset's" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const entry = contracts.lookup(key).?;
    const asset = try subject.assetPath(key);
    defer allocator.free(asset);
    const provenance_dir = try subject.provenanceDir(key);
    defer allocator.free(provenance_dir);
    const output = try subject.path("candidates/{s}/rejected.json", .{key});
    defer allocator.free(output);

    var diagnostic: support.Diagnostic = .{};
    try std.testing.expectError(error.Failed, commands.candidate(allocator, io, .{
        .key = key,
        .architecture = entry.architecture,
        .flavor = entry.flavor,
        .asset = asset,
        .validated_sha256 = "0" ** 64,
        .virtual_size = fixture.virtual_size,
        .source_commit = fixture.source_commit,
        .provenance_dir = provenance_dir,
        .runner = "runner",
        .run_id = "1",
        .run_attempt = "1",
        .output = output,
    }, &diagnostic));
    try std.testing.expectEqualStrings(
        "x86_64-full: build validation digest does not match candidate bytes",
        diagnostic.message(),
    );
}

test "verify rejects tampered candidate bytes" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const asset = try subject.assetPath(key);
    defer allocator.free(asset);
    try Dir.cwd().writeFile(io, .{ .sub_path = asset, .data = "tampered" });

    const manifest = try subject.manifestPath(key);
    defer allocator.free(manifest);
    var diagnostic: support.Diagnostic = .{};
    try std.testing.expectError(error.Failed, documents.verifyCandidate(
        allocator,
        io,
        manifest,
        asset,
        null,
        null,
        &diagnostic,
    ));
}

test "stage rejects a missing or duplicated candidate document" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);

    const manifest = try subject.manifestPath("aarch64-full");
    defer allocator.free(manifest);
    try Dir.cwd().deleteFile(io, manifest);
    try expectStageRejected(&subject);

    try remake(&subject, "aarch64-full");
    const extra = try subject.path("candidates/unexpected", .{});
    defer allocator.free(extra);
    try Dir.cwd().createDirPath(io, extra);
    const source_manifest = try subject.manifestPath("x86_64-full");
    defer allocator.free(source_manifest);
    const extra_manifest = try subject.path(
        "candidates/unexpected/candidate.json",
        .{},
    );
    defer allocator.free(extra_manifest);
    try Dir.cwd().copyFile(source_manifest, Dir.cwd(), extra_manifest, io, .{});
    try expectStageRejected(&subject);
}

test "stage requires exactly four Azure results" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const result_path = try subject.azureResultPath("aarch64-full");
    defer allocator.free(result_path);
    try Dir.cwd().deleteFile(io, result_path);
    try expectStageRejected(&subject);
}

test "stage requires exactly four native results" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const result_path = try subject.nativeResultPath("aarch64-full");
    defer allocator.free(result_path);
    try Dir.cwd().deleteFile(io, result_path);
    try expectStageRejected(&subject);
}

test "stage release ordering contains the exact full and core asset matrix" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    try stage(&subject, publication_tag);
    try std.testing.expectEqual(@as(usize, 4), contracts.release_order.len);
    const expected = [_]struct {
        key: []const u8,
        flavor: []const u8,
        asset_name: []const u8,
    }{
        .{
            .key = "x86_64-full",
            .flavor = "full",
            .asset_name = "Ubuntu-26.04-x86_64.qcow2",
        },
        .{
            .key = "aarch64-full",
            .flavor = "full",
            .asset_name = "Ubuntu-26.04-aarch64.qcow2",
        },
        .{
            .key = "x86_64-core",
            .flavor = "core",
            .asset_name = "Ubuntu-26.04-x86_64.core.qcow2",
        },
        .{
            .key = "aarch64-core",
            .flavor = "core",
            .asset_name = "Ubuntu-26.04-aarch64.core.qcow2",
        },
    };
    for (contracts.release_order, expected) |key, item| {
        try std.testing.expectEqualStrings(item.key, key);
        try std.testing.expectEqualStrings(item.flavor, contracts.lookup(key).?.flavor);
        try std.testing.expectEqualStrings(
            item.asset_name,
            contracts.lookup(key).?.asset_name,
        );
    }
}

test "stage rejects an extra QCOW2 and a checksum sidecar" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);

    const extra = try subject.path("candidates/extra.qcow2", .{});
    defer allocator.free(extra);
    try Dir.cwd().writeFile(io, .{ .sub_path = extra, .data = "extra" });
    try expectStageRejected(&subject);
    try Dir.cwd().deleteFile(io, extra);

    const sidecar = try subject.path("azure/forbidden.sha256", .{});
    defer allocator.free(sidecar);
    try Dir.cwd().writeFile(io, .{ .sub_path = sidecar, .data = "0" ** 64 });
    try expectStageRejected(&subject);
}

test "stage rejects source commit and identity changes" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const manifest = try subject.manifestPath("x86_64-full");
    defer allocator.free(manifest);

    try fixture.patchString(
        allocator,
        io,
        manifest,
        &.{.{ .key = "source_commit" }},
        "b" ** 40,
    );
    try expectStageRejected(&subject);

    try fixture.patchString(
        allocator,
        io,
        manifest,
        &.{.{ .key = "source_commit" }},
        fixture.source_commit,
    );
    try fixture.patchString(
        allocator,
        io,
        manifest,
        &.{.{ .key = "asset_name" }},
        "other.qcow2",
    );
    try expectStageRejected(&subject);
}

test "stage rejects tampered or unbound provenance" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);

    const manifest_file = try subject.path(
        "candidates/x86_64-full/internal-provenance/ubuntu-26.04-server-cloudimg-amd64.manifest",
        .{},
    );
    defer allocator.free(manifest_file);
    try Dir.cwd().writeFile(io, .{ .sub_path = manifest_file, .data = "tampered" });
    try expectStageRejected(&subject);

    try remake(&subject, "x86_64-full");
    const unbound = try subject.path(
        "candidates/x86_64-full/internal-provenance/unbound.log",
        .{},
    );
    defer allocator.free(unbound);
    try Dir.cwd().writeFile(io, .{ .sub_path = unbound, .data = "new" });
    try expectStageRejected(&subject);
}

fn validateUbuntu(
    subject: *const Tree,
    key: []const u8,
    architecture: []const u8,
    flavor: contracts.Flavor,
    virtual_size: ?i64,
) !void {
    const root = try subject.provenanceDir(key);
    defer allocator.free(root);
    var diagnostic: support.Diagnostic = .{};
    var document = try provenance.validateUbuntu(
        allocator,
        io,
        root,
        architecture,
        flavor,
        virtual_size,
        &diagnostic,
    );
    document.deinit();
}

fn expectUbuntuRejected(
    subject: *const Tree,
    key: []const u8,
    architecture: []const u8,
    flavor: contracts.Flavor,
    virtual_size: ?i64,
) !void {
    try std.testing.expectError(
        error.Failed,
        validateUbuntu(subject, key, architecture, flavor, virtual_size),
    );
}

test "Ubuntu provenance requires immutable, signed snapshot inputs" {
    const mutations = [_]struct { steps: []const Step, change: fixture.Change }{
        .{
            .steps = &.{ .{ .key = "snapshot" }, .{ .key = "base_url" } },
            .change = .{
                .set = .{
                    .string = "https://cloud-images.ubuntu.com/releases/26.04/current/",
                },
            },
        },
        .{
            .steps = &.{.{ .key = "canonical_key_fingerprint" }},
            .change = .{ .set = .{ .string = "not-a-fingerprint" } },
        },
        .{
            .steps = &.{.{ .key = "sha256sums_signature_verified" }},
            .change = .{ .set = .{ .bool = false } },
        },
        .{
            .steps = &.{ .{ .key = "artifacts" }, .{ .key = "source_image" } },
            .change = .remove,
        },
    };
    for (mutations) |mutation| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, "x86_64-full", .{});
        const path = try subject.path(
            "candidates/x86_64-full/internal-provenance/{s}",
            .{contracts.ubuntu_provenance_filename},
        );
        defer allocator.free(path);
        try fixture.patch(allocator, io, path, mutation.steps, mutation.change);
        try expectUbuntuRejected(&subject, "x86_64-full", "x86_64", .full, null);
    }
}

test "Ubuntu provenance requires the exact architecture disk layout" {
    for ([_][2][]const u8{
        .{ "x86_64-full", "x86_64" },
        .{ "aarch64-full", "aarch64" },
    }) |entry| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, entry[0], .{});
        try validateUbuntu(&subject, entry[0], entry[1], .full, null);
    }
}

test "Ubuntu provenance rejects disk layout changes" {
    const mutations = [_]struct { steps: []const Step, change: fixture.Change }{
        .{
            .steps = &.{ .{ .key = "disk_layout" }, .{ .key = "transform" } },
            .change = .{ .set = .{ .string = "preserved" } },
        },
        .{
            .steps = &.{
                .{ .key = "disk_layout" },
                .{ .key = "esp" },
                .{ .key = "last_lba" },
            },
            .change = .{ .set = .{ .integer = 1_050_622 } },
        },
        .{
            .steps = &.{
                .{ .key = "disk_layout" },
                .{ .key = "esp" },
                .{ .key = "table_index" },
            },
            .change = .{ .set = .{ .bool = true } },
        },
        .{
            .steps = &.{
                .{ .key = "disk_layout" },
                .{ .key = "retired_xbootldr" },
                .{ .key = "cleared" },
            },
            .change = .{ .set = .{ .bool = false } },
        },
        .{
            .steps = &.{ .{ .key = "disk_layout" }, .{ .key = "unexpected" } },
            .change = .{ .set = .{ .string = "value" } },
        },
    };
    for (mutations) |mutation| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, "aarch64-full", .{});
        const path = try subject.path(
            "candidates/aarch64-full/internal-provenance/{s}",
            .{contracts.ubuntu_provenance_filename},
        );
        defer allocator.free(path);
        try fixture.patch(allocator, io, path, mutation.steps, mutation.change);
        try expectUbuntuRejected(&subject, "aarch64-full", "aarch64", .full, null);
    }
}

/// The size-inventory document the fixture bound into a candidate's
/// provenance.
fn sizeInventoryPath(subject: *const Tree, key: []const u8) ![]u8 {
    const entry = contracts.lookup(key).?;
    return subject.path(
        "candidates/{s}/internal-provenance/ubuntu2604-size-inventory-{s}-{s}.json",
        .{ key, entry.flavor, entry.architecture },
    );
}

test "Ubuntu provenance binds a complete size inventory" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-core", .{});
    try validateUbuntu(&subject, "x86_64-core", "x86_64", .core, fixture.virtual_size);

    const inventory = try sizeInventoryPath(&subject, "x86_64-core");
    defer allocator.free(inventory);
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var diagnostic: support.Diagnostic = .{};
    try release.workflow.sizeInventoryVerify(
        allocator,
        io,
        &writer,
        inventory,
        "x86_64",
        "core",
        "root_build,image_build,publication",
        null,
        &diagnostic,
    );
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "packages=1") != null);

    // A phase the candidate has not reached is refused rather than assumed.
    try std.testing.expectError(error.Failed, release.workflow.sizeInventoryVerify(
        allocator,
        io,
        &writer,
        inventory,
        "x86_64",
        "core",
        "first_boot",
        null,
        &diagnostic,
    ));

    // Issue #677 step 3: the fresh-root bound the core workflows pass. The
    // fixture root deliberately carries a kernel no package claims, so the
    // bound the core workflows use refuses it by name rather than reporting it.
    try std.testing.expectError(error.Failed, release.workflow.sizeInventoryVerify(
        allocator,
        io,
        &writer,
        inventory,
        "x86_64",
        "core",
        "root_build,image_build,publication",
        "0",
        &diagnostic,
    ));
    try std.testing.expect(std.mem.indexOf(
        u8,
        diagnostic.message(),
        "outside the explicit allowlist",
    ) != null);
    writer.end = 0;
    try release.workflow.sizeInventoryVerify(
        allocator,
        io,
        &writer,
        inventory,
        "x86_64",
        "core",
        "root_build,image_build,publication",
        "1024",
        &diagnostic,
    );
    // A malformed bound is refused rather than silently ignored.
    try std.testing.expectError(error.Failed, release.workflow.sizeInventoryVerify(
        allocator,
        io,
        &writer,
        inventory,
        "x86_64",
        "core",
        "root_build,image_build,publication",
        "many",
        &diagnostic,
    ));

    // The inventory is bound by digest, so editing it invalidates the whole
    // provenance tree rather than only the file.
    try fixture.patch(
        allocator,
        io,
        inventory,
        &.{ .{ .key = "root_build" }, .{ .key = "installed_bytes" } },
        .{ .set = .{ .integer = 1 } },
    );
    try expectUbuntuRejected(
        &subject,
        "x86_64-core",
        "x86_64",
        .core,
        fixture.virtual_size,
    );
}

/// The runtime-contract document the fixture bound into a core candidate's
/// provenance.
fn runtimeContractPath(subject: *const Tree, key: []const u8) ![]u8 {
    const entry = contracts.lookup(key).?;
    return subject.path(
        "candidates/{s}/internal-provenance/ubuntu2604-runtime-contract-{s}-{s}.json",
        .{ key, entry.flavor, entry.architecture },
    );
}

/// The build provenance the fixture wrote for a candidate.
fn buildProvenancePath(subject: *const Tree, key: []const u8) ![]u8 {
    return subject.path(
        "candidates/{s}/internal-provenance/{s}",
        .{ key, contracts.ubuntu_provenance_filename },
    );
}

test "build-only packages cannot enter a published core guest" {
    // Issue #677 step 4 is only true if a candidate that broke it is refused.
    // Every mutation below is a way the separation could quietly fail: the
    // kernel metapackage installed after all, the generator promoted to a guest
    // root, the staging build removed entirely, or an initramfs staged for a
    // different kernel than the one the guest boots.
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "aarch64-core", .{});
    try validateUbuntu(&subject, "aarch64-core", "aarch64", .core, fixture.virtual_size);

    const provenance_path = try buildProvenancePath(&subject, "aarch64-core");
    defer allocator.free(provenance_path);
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var diagnostic: support.Diagnostic = .{};
    try release.workflow.buildRuntimeSplitVerify(
        allocator,
        io,
        &writer,
        provenance_path,
        &diagnostic,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        writer.buffered(),
        "kernel=" ++ fixture.fixture_kernel_release,
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "build_roots=1") != null);

    const mutations = [_]struct {
        steps: []const Step,
        change: fixture.Change,
        expect: []const u8,
    }{
        // The metapackage installed rather than merely resolved.
        .{
            .steps = &.{ .{ .key = "debz" }, .{ .key = "package_roots" }, .{ .index = 0 } },
            .change = .{ .set = .{ .string = "linux-azure" } },
            .expect = "package roots",
        },
        // The generator promoted into the guest.
        .{
            .steps = &.{ .{ .key = "debz" }, .{ .key = "package_roots" }, .{ .index = 2 } },
            .change = .{ .set = .{ .string = "initramfs-tools" } },
            .expect = "package roots",
        },
        // No staging build at all, which means the guest generated its own.
        .{
            .steps = &.{ .{ .key = "debz" }, .{ .key = "build_stage" } },
            .change = .remove,
            .expect = "build stage",
        },
        // A staging root whose roots are not the contract's build tooling.
        .{
            .steps = &.{
                .{ .key = "debz" },
                .{ .key = "build_stage" },
                .{ .key = "package_roots" },
                .{ .index = 0 },
            },
            .change = .{ .set = .{ .string = "sudo" } },
            .expect = "build tooling",
        },
        // An initramfs staged for a kernel the guest does not boot.
        .{
            .steps = &.{
                .{ .key = "debz" },
                .{ .key = "build_stage" },
                .{ .key = "initramfs" },
                .{ .key = "kernel_release" },
            },
            .change = .{ .set = .{ .string = "7.0.0-1004-azure" } },
            .expect = "selected kernel",
        },
    };
    for (mutations) |mutation| {
        var mutated = try tree();
        defer mutated.deinit();
        try fixture.makeBundle(&mutated, "aarch64-core", .{});
        const path = try buildProvenancePath(&mutated, "aarch64-core");
        defer allocator.free(path);
        try fixture.patch(allocator, io, path, mutation.steps, mutation.change);
        writer.end = 0;
        diagnostic = .{};
        try std.testing.expectError(error.Failed, release.workflow.buildRuntimeSplitVerify(
            allocator,
            io,
            &writer,
            path,
            &diagnostic,
        ));
        try std.testing.expect(
            std.mem.indexOf(u8, diagnostic.message(), mutation.expect) != null,
        );
        // The same mutation also fails the whole provenance tree, so the gate
        // is a second reading of the contract rather than the only one.
        try expectUbuntuRejected(
            &mutated,
            "aarch64-core",
            "aarch64",
            .core,
            fixture.virtual_size,
        );
    }
}

test "both core architectures publish the same build/runtime split" {
    // #677 requires both architectures to keep every contract, and the split is
    // now one of them: each architecture selects its own kernel and binds its
    // own architecture-qualified selector lock, so a gate that only ever saw
    // one of them would not be a gate.
    for ([_][]const u8{ "x86_64-core", "aarch64-core" }) |key| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, key, .{});
        const entry = contracts.lookup(key).?;
        try validateUbuntu(
            &subject,
            key,
            entry.architecture,
            .core,
            fixture.virtual_size,
        );
        const provenance_path = try buildProvenancePath(&subject, key);
        defer allocator.free(provenance_path);
        var buffer: [4096]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        var diagnostic: support.Diagnostic = .{};
        try release.workflow.buildRuntimeSplitVerify(
            allocator,
            io,
            &writer,
            provenance_path,
            &diagnostic,
        );
        try std.testing.expect(std.mem.indexOf(
            u8,
            writer.buffered(),
            "image=" ++ fixture.fixture_kernel_image,
        ) != null);

        // The selector lock is published per architecture and is a real file in
        // the candidate's provenance tree, so the selection is reviewable.
        const source_architecture = contracts.sourceArchitecture(entry.architecture).?;
        const selector_lock = try subject.path(
            "candidates/{s}/internal-provenance/debz-exact-lock-linux-azure-{s}.json",
            .{ key, source_architecture },
        );
        defer allocator.free(selector_lock);
        const bytes = try Dir.cwd().readFileAlloc(
            io,
            selector_lock,
            allocator,
            .limited(1024 * 1024),
        );
        defer allocator.free(bytes);
        try std.testing.expect(bytes.len != 0);
    }
}

test "core provenance binds the explicit runtime contract" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "aarch64-core", .{});
    try validateUbuntu(&subject, "aarch64-core", "aarch64", .core, fixture.virtual_size);

    const contract_path = try runtimeContractPath(&subject, "aarch64-core");
    defer allocator.free(contract_path);
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var diagnostic: support.Diagnostic = .{};
    try release.workflow.runtimeContractVerify(
        allocator,
        io,
        &writer,
        contract_path,
        "aarch64",
        "core",
        &diagnostic,
    );
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "aarch64 core") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "guest_runtime=") != null);

    // The wrong architecture is refused rather than accepted as "a contract".
    writer.end = 0;
    try std.testing.expectError(error.Failed, release.workflow.runtimeContractVerify(
        allocator,
        io,
        &writer,
        contract_path,
        "x86_64",
        "core",
        &diagnostic,
    ));

    // The contract is bound by digest, so editing it invalidates the whole
    // provenance tree rather than only the file.
    try fixture.patch(
        allocator,
        io,
        contract_path,
        &.{.{ .key = "flavor" }},
        .{ .set = .{ .string = "full" } },
    );
    try expectUbuntuRejected(
        &subject,
        "aarch64-core",
        "aarch64",
        .core,
        fixture.virtual_size,
    );
}

test "a core candidate without a runtime contract is refused" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-core", .{});
    const path = try subject.path(
        "candidates/x86_64-core/internal-provenance/{s}",
        .{contracts.ubuntu_provenance_filename},
    );
    defer allocator.free(path);
    try fixture.patch(
        allocator,
        io,
        path,
        &.{ .{ .key = "runtime_contract" }, .{ .key = "filename" } },
        .{ .set = .{ .string = "ubuntu2604-runtime-contract-core-aarch64.json" } },
    );
    try expectUbuntuRejected(&subject, "x86_64-core", "x86_64", .core, fixture.virtual_size);
}

test "a guest runtime-contract probe report is judged by the release tool" {
    var subject = try tree();
    defer subject.deinit();

    var complete: std.ArrayList(u8) = .empty;
    defer complete.deinit(allocator);
    var broken: std.ArrayList(u8) = .empty;
    defer broken.deinit(allocator);
    for (release.runtime_contract.requirements()) |requirement| {
        if (!requirement.kind.probeable()) continue;
        try complete.print(allocator, "runtime-contract id={s} status=ok\n", .{requirement.id});
        const status = if (std.mem.eql(u8, requirement.id, "sshd")) "missing" else "ok";
        try broken.print(
            allocator,
            "runtime-contract id={s} status={s}\n",
            .{ requirement.id, status },
        );
    }

    const good_path = try subject.path("probe-report-ok.txt", .{});
    defer allocator.free(good_path);
    try Dir.cwd().writeFile(io, .{ .sub_path = good_path, .data = complete.items });
    const bad_path = try subject.path("probe-report-broken.txt", .{});
    defer allocator.free(bad_path);
    try Dir.cwd().writeFile(io, .{ .sub_path = bad_path, .data = broken.items });

    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var diagnostic: support.Diagnostic = .{};
    try release.workflow.runtimeContractProbeVerify(
        allocator,
        io,
        &writer,
        good_path,
        &diagnostic,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, writer.buffered(), "runtime-contract satisfied") != null,
    );

    writer.end = 0;
    try std.testing.expectError(error.Failed, release.workflow.runtimeContractProbeVerify(
        allocator,
        io,
        &writer,
        bad_path,
        &diagnostic,
    ));
    try std.testing.expect(std.mem.indexOf(u8, diagnostic.message(), "sshd") != null);

    // A report that was never produced is a failure, not an empty pass.
    const absent = try subject.path("probe-report-absent.txt", .{});
    defer allocator.free(absent);
    writer.end = 0;
    try std.testing.expectError(error.Failed, release.workflow.runtimeContractProbeVerify(
        allocator,
        io,
        &writer,
        absent,
        &diagnostic,
    ));
}

test "size inventories are compared before a closure changes" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-core", .{});
    try fixture.makeBundle(&subject, "aarch64-core", .{});

    const baseline = try sizeInventoryPath(&subject, "x86_64-core");
    defer allocator.free(baseline);
    const other_architecture = try sizeInventoryPath(&subject, "aarch64-core");
    defer allocator.free(other_architecture);
    const candidate = try subject.path("candidate-inventory.json", .{});
    defer allocator.free(candidate);
    const original = try Dir.cwd().readFileAlloc(
        io,
        baseline,
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(original);
    try Dir.cwd().writeFile(io, .{ .sub_path = candidate, .data = original });
    try fixture.patch(
        allocator,
        io,
        candidate,
        &.{ .{ .key = "publication" }, .{ .key = "compressed_artifact_bytes" } },
        .{ .set = .{ .integer = fixture.virtual_size - 4096 } },
    );

    const comparison = try subject.path("size-comparison.json", .{});
    defer allocator.free(comparison);
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var diagnostic: support.Diagnostic = .{};
    try release.workflow.sizeInventoryCompare(
        allocator,
        io,
        &writer,
        baseline,
        candidate,
        comparison,
        null,
        &diagnostic,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, writer.buffered(), "closure_changed=false") != null,
    );
    const document = try Dir.cwd().readFileAlloc(
        io,
        comparison,
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(document);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, document, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(
        @as(i64, -4096),
        parsed.value.object.get("publication").?
            .object.get("compressed_artifact_bytes_delta").?.integer,
    );

    // Two architectures do not describe the same image, so their inventories
    // are not comparable.
    try std.testing.expectError(error.Failed, release.workflow.sizeInventoryCompare(
        allocator,
        io,
        &writer,
        baseline,
        other_architecture,
        null,
        null,
        &diagnostic,
    ));
}

test "Ubuntu provenance binds the source image and manifest checksums" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});
    const root = try subject.provenanceDir("x86_64-full");
    defer allocator.free(root);
    const checksum_path = try std.fs.path.join(allocator, &.{ root, "SHA256SUMS" });
    defer allocator.free(checksum_path);

    const original = try Dir.cwd().readFileAlloc(
        io,
        checksum_path,
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(original);
    // Drop the last binding, then re-bind the truncated file so only the
    // SHA256SUMS content itself is different.
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, original, "\n"), '\n');
    var truncated: std.ArrayList(u8) = .empty;
    defer truncated.deinit(allocator);
    var kept: usize = 0;
    const total = std.mem.count(u8, std.mem.trimEnd(u8, original, "\n"), "\n") + 1;
    while (lines.next()) |line| : (kept += 1) {
        if (kept + 1 == total) break;
        try truncated.appendSlice(allocator, line);
        try truncated.append(allocator, '\n');
    }
    try Dir.cwd().writeFile(io, .{
        .sub_path = checksum_path,
        .data = truncated.items,
    });

    const path = try subject.path(
        "candidates/x86_64-full/internal-provenance/{s}",
        .{contracts.ubuntu_provenance_filename},
    );
    defer allocator.free(path);
    const digest = support.digest.hexBytes(truncated.items);
    try fixture.patchString(
        allocator,
        io,
        path,
        &.{
            .{ .key = "artifacts" },
            .{ .key = "sha256sums" },
            .{ .key = "sha256" },
        },
        &digest,
    );
    try expectUbuntuRejected(&subject, "x86_64-full", "x86_64", .full, null);
}

test "Ubuntu provenance binds the debz lock and transaction together" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});
    const path = try subject.path(
        "candidates/x86_64-full/internal-provenance/{s}",
        .{contracts.ubuntu_provenance_filename},
    );
    defer allocator.free(path);
    try fixture.patchString(allocator, io, path, &.{
        .{ .key = "debz" },
        .{ .key = "transactions" },
        .{ .index = 0 },
        .{ .key = "transaction_provenance" },
        .{ .key = "lock_sha256" },
    }, "0" ** 64);
    try expectUbuntuRejected(&subject, "x86_64-full", "x86_64", .full, null);
}

test "Ubuntu provenance requires a locked baseline for both architectures" {
    for ([_][2][]const u8{
        .{ "x86_64-full", "x86_64" },
        .{ "aarch64-full", "aarch64" },
    }) |entry| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, entry[0], .{});
        const root = try subject.provenanceDir(entry[0]);
        defer allocator.free(root);
        const metadata = try std.fs.path.join(
            allocator,
            &.{ root, contracts.ubuntu_provenance_filename },
        );
        defer allocator.free(metadata);

        var document = try fixture.read(allocator, io, metadata);
        defer document.deinit();
        const transaction = document.value.object
            .get("debz").?.object
            .get("transactions").?.array.items[0].object;
        const lock_name = transaction
            .get("exact_lock").?.object
            .get("filename").?.string;
        const lock_path = try std.fs.path.join(allocator, &.{ root, lock_name });
        defer allocator.free(lock_path);

        // Removing every retained package leaves a lock that proves no closure.
        try fixture.patch(
            allocator,
            io,
            lock_path,
            &.{ .{ .key = "packages" }, .{ .index = 0 } },
            .remove,
        );
        const lock_bytes = try Dir.cwd().readFileAlloc(
            io,
            lock_path,
            allocator,
            .limited(64 * 1024),
        );
        defer allocator.free(lock_bytes);
        const digest = support.digest.hexBytes(lock_bytes);
        try fixture.patchString(allocator, io, metadata, &.{
            .{ .key = "debz" },
            .{ .key = "transactions" },
            .{ .index = 0 },
            .{ .key = "exact_lock" },
            .{ .key = "sha256" },
        }, &digest);
        try expectUbuntuRejected(&subject, entry[0], entry[1], .full, null);
    }
}

test "Ubuntu provenance requires the explicit baseline contract" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});
    const path = try subject.path(
        "candidates/x86_64-full/internal-provenance/{s}",
        .{contracts.ubuntu_provenance_filename},
    );
    defer allocator.free(path);
    try fixture.patchString(
        allocator,
        io,
        path,
        &.{ .{ .key = "debz" }, .{ .key = "baseline" }, .{ .key = "enforcement" } },
        "transaction-actions-only",
    );
    try expectUbuntuRejected(&subject, "x86_64-full", "x86_64", .full, null);
}

test "Ubuntu provenance requires stably ordered debz transactions" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});
    const path = try subject.path(
        "candidates/x86_64-full/internal-provenance/{s}",
        .{contracts.ubuntu_provenance_filename},
    );
    defer allocator.free(path);
    try fixture.patch(
        allocator,
        io,
        path,
        &.{ .{ .key = "debz" }, .{ .key = "transactions" } },
        .reverse,
    );
    try expectUbuntuRejected(&subject, "x86_64-full", "x86_64", .full, null);
}

test "core Ubuntu provenance matches the builder contract" {
    var subject = try tree();
    defer subject.deinit();
    const key = "aarch64-core";
    try fixture.makeBundle(&subject, key, .{});
    try validateUbuntu(&subject, key, "aarch64", .core, fixture.virtual_size);

    const path = try subject.path(
        "candidates/{s}/internal-provenance/{s}",
        .{ key, contracts.ubuntu_provenance_filename },
    );
    defer allocator.free(path);
    var document = try fixture.read(allocator, io, path);
    defer document.deinit();
    try std.testing.expectEqualStrings(
        "core",
        document.value.object.get("flavor").?.string,
    );
    try std.testing.expectEqualStrings(
        "signed-gpt-esp-substrate",
        document.value.object
            .get("artifacts").?.object
            .get("source_image").?.object
            .get("role").?.string,
    );
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const expected_roots = try fixture.coreDebzPackages(arena.allocator());
    try std.testing.expect(support.isExactOrderedStrings(
        document.value.object.get("debz").?.object.get("package_roots"),
        expected_roots,
    ));
    const transactions = document.value.object
        .get("debz").?.object
        .get("transactions").?.array.items;
    try std.testing.expectEqual(expected_roots.len, transactions.len);
    for (transactions, expected_roots) |item, package| {
        try std.testing.expectEqualStrings(
            package,
            item.object.get("package").?.string,
        );
    }

    // Issue #677 step 4: the kernel is selected from a metapackage that is not
    // installed, and the initramfs is produced by a staging root whose own
    // roots, transactions, and output are bound here rather than assumed.
    const debz = document.value.object.get("debz").?.object;
    const selection = debz.get("kernel_selection").?.object;
    try std.testing.expectEqualStrings(
        "linux-azure",
        selection.get("selector").?.string,
    );
    try std.testing.expectEqualStrings(
        fixture.fixture_kernel_release,
        selection.get("kernel_release").?.string,
    );
    try std.testing.expectEqualStrings(
        fixture.fixture_kernel_image,
        selection.get("image_package").?.string,
    );
    const build_stage = debz.get("build_stage").?.object;
    try std.testing.expectEqualStrings(
        "initramfs-generation",
        build_stage.get("purpose").?.string,
    );
    try std.testing.expect(support.isExactOrderedStrings(
        build_stage.get("package_roots"),
        &contracts.core_build_package_roots,
    ));
    try std.testing.expectEqualStrings(
        "/boot/initrd.img-" ++ fixture.fixture_kernel_release,
        build_stage.get("initramfs").?.object.get("path").?.string,
    );
    // The generator is a build root, so it must not also be a guest root.
    for (expected_roots) |root| {
        for (contracts.core_build_package_roots) |build_root| {
            try std.testing.expect(!std.mem.eql(u8, root, build_root));
        }
    }
}

test "core Ubuntu provenance rejects contract changes" {
    const mutations = [_]struct { steps: []const Step, change: fixture.Change }{
        .{
            .steps = &.{.{ .key = "flavor" }},
            .change = .{ .set = .{ .string = "full" } },
        },
        .{
            .steps = &.{
                .{ .key = "artifacts" },
                .{ .key = "source_image" },
                .{ .key = "role" },
            },
            .change = .{ .set = .{ .string = "root-filesystem" } },
        },
        .{
            .steps = &.{ .{ .key = "debz" }, .{ .key = "package_roots" } },
            .change = .reverse,
        },
        .{
            .steps = &.{
                .{ .key = "debz" },
                .{ .key = "baseline" },
                .{ .key = "source" },
            },
            .change = .{ .set = .{ .string = "canonical-image-dpkg-status" } },
        },
        .{
            .steps = &.{.{ .key = "validated_root_free_bytes" }},
            .change = .{ .set = .{ .integer = 0 } },
        },
        .{
            .steps = &.{.{ .key = "virtual_size" }},
            .change = .{ .set = .{ .integer = 3 * 1024 * 1024 } },
        },
    };
    for (mutations) |mutation| {
        var subject = try tree();
        defer subject.deinit();
        const key = "x86_64-core";
        try fixture.makeBundle(&subject, key, .{});
        const path = try subject.path(
            "candidates/{s}/internal-provenance/{s}",
            .{ key, contracts.ubuntu_provenance_filename },
        );
        defer allocator.free(path);
        try fixture.patch(allocator, io, path, mutation.steps, mutation.change);
        try expectUbuntuRejected(&subject, key, "x86_64", .core, fixture.virtual_size);
    }
}

test "stage refuses PEM, DER, and embedded private key material" {
    const payloads = [_][]const u8{
        "-----BEGIN PRIVATE KEY-----\nsecret\n",
        "-----BEGIN DSA PRIVATE KEY-----\nsecret\n",
        &[_]u8{ 0x30, 0x82, 0x00, 0x08, 0x02, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00 },
        "prefix\n" ++ &[_]u8{
            0x30, 0x0c, 0x30, 0x07, 0x06, 0x03, 0x2a, 0x03,
            0x04, 0x05, 0x00, 0x04, 0x01, 0x00,
        },
        "binary-prefix\x00openssh-key-v1\x00binary-private-key",
    };
    for (payloads) |payload| {
        var subject = try tree();
        defer subject.deinit();
        try makeAll(&subject);
        const path = try subject.path(
            "candidates/x86_64-full/internal-provenance/ubuntu-26.04-server-cloudimg-amd64.manifest",
            .{},
        );
        defer allocator.free(path);
        try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = payload });
        try expectStageRejected(&subject);
    }
}

test "stage rejects acceptance digest and contract changes" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const path = try subject.azureResultPath("x86_64-full");
    defer allocator.free(path);

    try fixture.patchString(
        allocator,
        io,
        path,
        &.{.{ .key = "azure_accepted_sha256" }},
        "0" ** 64,
    );
    try expectStageRejected(&subject);

    try remake(&subject, "x86_64-full");
    try fixture.patch(allocator, io, path, &.{.{ .key = "contracts" }}, .pop);
    try expectStageRejected(&subject);
}

test "stage rejects acceptance status and derived VHD evidence changes" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const path = try subject.azureResultPath("x86_64-full");
    defer allocator.free(path);

    try fixture.patchString(allocator, io, path, &.{.{ .key = "status" }}, "failure");
    try expectStageRejected(&subject);

    try remake(&subject, "x86_64-full");
    try fixture.patchInteger(allocator, io, path, &.{
        .{ .key = "conversion" },
        .{ .key = "result" },
        .{ .key = "current_size" },
    }, fixture.virtual_size + 1024 * 1024);
    try expectStageRejected(&subject);
}

test "azure-result rejects a malformed derived VHD structure" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const vhd = try subject.path("azure/{s}/temporary.vhd", .{key});
    defer allocator.free(vhd);

    const file = try Dir.cwd().openFile(io, vhd, .{ .mode = .read_write });
    defer file.close(io);
    const size = (try file.stat(io)).size;
    const zeros = [_]u8{0} ** 512;
    try file.writePositionalAll(io, &zeros, size - zeros.len);
    try std.testing.expectError(
        error.Failed,
        rerunAzureResult(&subject, key, keepOptions),
    );
}

fn keepOptions(_: *commands.AzureResultOptions) void {}

test "azure-result rejects a malformed qemu VHD info document" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const info = try subject.path("azure/{s}/vhd-info.json", .{key});
    defer allocator.free(info);
    try Dir.cwd().writeFile(io, .{
        .sub_path = info,
        .data = "{\"format\": \"raw\", \"virtual-size\": 2097152}",
    });
    try std.testing.expectError(
        error.Failed,
        rerunAzureResult(&subject, key, keepOptions),
    );
}

test "azure-result rejects an unrelated but structurally valid VHD" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const vhd = try subject.path("azure/{s}/temporary.vhd", .{key});
    defer allocator.free(vhd);

    const file = try Dir.cwd().openFile(io, vhd, .{ .mode = .read_write });
    defer file.close(io);
    try file.writePositionalAll(io, "unrelated", 0);
    try std.testing.expectError(
        error.Failed,
        rerunAzureResult(&subject, key, keepOptions),
    );
}

test "azure-result rejects a conversion parameter mismatch" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const attestation = try subject.path(
        "azure/{s}/conversion-attestation.json",
        .{key},
    );
    defer allocator.free(attestation);
    try fixture.patchString(
        allocator,
        io,
        attestation,
        &.{ .{ .key = "parameters" }, .{ .key = "input_sha256" } },
        "0" ** 64,
    );
    try std.testing.expectError(
        error.Failed,
        rerunAzureResult(&subject, key, keepOptions),
    );
}

test "stage rejects mixed UKI and Artifact Signing identities" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});
    try fixture.makeBundle(&subject, "aarch64-full", .{
        .certificate = "different certificate",
    });
    try expectStageRejected(&subject);

    try subject.removeBundle("aarch64-full");
    try fixture.makeBundle(&subject, "aarch64-full", .{
        .signing_certificate_sha256 = "5" ** 64,
    });
    try expectStageRejected(&subject);
}

test "stage rejects a changed Azure signing binding" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const path = try subject.azureResultPath("aarch64-full");
    defer allocator.free(path);
    try fixture.patchString(
        allocator,
        io,
        path,
        &.{.{ .key = "certificate_sha256" }},
        "0" ** 64,
    );
    try expectStageRejected(&subject);
}

test "stage rejects a release tag that is not a date" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    try std.testing.expectError(
        error.Failed,
        stage(&subject, "Ubuntu-26.04-latest"),
    );
}

test "a failed stage leaves the destination and notes untouched" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);

    const output = try subject.path("staged", .{});
    defer allocator.free(output);
    try Dir.cwd().createDirPath(io, output);
    const notes = try subject.path("release-notes.md", .{});
    defer allocator.free(notes);
    try Dir.cwd().writeFile(io, .{ .sub_path = notes, .data = "existing notes\n" });

    const result_path = try subject.azureResultPath("x86_64-full");
    defer allocator.free(result_path);
    try fixture.patch(allocator, io, result_path, &.{.{ .key = "contracts" }}, .pop);
    try expectStageRejected(&subject);

    var directory = try Dir.cwd().openDir(io, output, .{ .iterate = true });
    defer directory.close(io);
    var iterator = directory.iterate();
    try std.testing.expect(try iterator.next(io) == null);

    const remaining = try Dir.cwd().readFileAlloc(
        io,
        notes,
        allocator,
        .limited(1024),
    );
    defer allocator.free(remaining);
    try std.testing.expectEqualStrings("existing notes\n", remaining);

    // No transactional staging path survives the failure.
    var root_directory = try Dir.cwd().openDir(io, subject.root, .{ .iterate = true });
    defer root_directory.close(io);
    var root_iterator = root_directory.iterate();
    while (try root_iterator.next(io)) |item| {
        try std.testing.expect(
            !std.mem.startsWith(u8, item.name, ".staged.tmp-"),
        );
        try std.testing.expect(
            !std.mem.startsWith(u8, item.name, ".release-notes.md.tmp-"),
        );
    }
}

test "stage refuses a non-empty destination" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const output = try subject.path("staged", .{});
    defer allocator.free(output);
    try Dir.cwd().createDirPath(io, output);
    const sentinel = try subject.path("staged/do-not-replace", .{});
    defer allocator.free(sentinel);
    try Dir.cwd().writeFile(io, .{ .sub_path = sentinel, .data = "sentinel" });

    try expectStageRejected(&subject);
    try std.testing.expect(support.isRegularFile(io, sentinel));
}

test "the production builder is native, qemu-free, and GnuPG-free" {
    const Source = @import("ubuntu2604_source.zig").Source;
    var builder = try Source.open(
        allocator,
        "scripts/build_generalized_ubuntu2604.zig",
    );
    defer builder.deinit();
    const production = try builder.section("", "test \"profiles pin");

    const source = @import("ubuntu2604_source.zig");
    if (source.findForbiddenProductionTool(production)) |match| {
        std.debug.print("builder uses {s}\n", .{match});
        return error.ForbiddenText;
    }
    // Issue #476: Ubuntu finalization emits the compressed release image
    // natively, so qemu tooling no longer appears in the builder at all.
    try source.expectOmitsIn(production, "\"qemu-img\"", "builder");
    try source.expectOmitsIn(production, "\"qemu-utils\"", "builder");
    try source.expectContainsIn(
        production,
        "miz.qcow2.writeStandaloneCompressed",
        "builder",
    );

    // The package root is imported and exported through the native mountless
    // ext4 path, never through an external image tool.
    const native = [_][]const u8{
        "miz.ext4_mountless.FileSystem.open",
        "exportHostTree",
        "importHostTree",
        "native_root.finish()",
        "cloudimg-rootfs",
        "materializeTrustedKeyring(allocator, io, trusted_keyring, external_keyring)",
        "const absolute_keyring = trusted.path",
        "realPathFileAlloc(io, destination",
        "assertTrustedKeyringUnchanged",
        // Arm64 UKIs are assembled from a normalized EFI kernel payload.
        "uki_kernel_payload.normalize(",
        ".linux = kernel_payload.bytes",
        // Canonical's signature is verified natively.
        "@embedFile(\"fixtures/canonical-ubuntu-cloud-image-key.asc\")",
        "verifyOpenPgpDetachedSignature",
        "PKCS1v1_5Signature.concatVerify",
        "NativeHttpsDownloader.init",
        "artifact_pipeline.acquireVerified",
    };
    for (native) |needle| try source.expectContainsIn(production, needle, "builder");
    const forbidden = [_][]const u8{
        "/dev/sda4",
        "/dev/sda3",
        "virt-tar-out",
        "virt-tar-in",
        "\"guestfish\"",
        "\"tar\"",
        "\"cp\"",
        "realPathFileAlloc(io, trusted_keyring",
        ".linux = kernel_bytes",
        "\"gpg\"",
        "\"curl\"",
    };
    for (forbidden) |needle| try source.expectOmitsIn(production, needle, "builder");

    var root_tree = try Source.open(allocator, "packages/miz/src/root_tree.zig");
    defer root_tree.deinit();
    try root_tree.expectContains("path_index: std.StringHashMap(usize)");
    try root_tree.expectContains("append_only_import = true");
    var ext4 = try Source.open(allocator, "packages/miz/src/ext4_mountless.zig");
    defer ext4.deinit();
    try ext4.expectContains("readFileAllocAt");

    var workflow = try Source.open(
        allocator,
        ".github/workflows/ubuntu2604-release.yml",
    );
    defer workflow.deinit();
    try workflow.expectOmits("gnupg");
    try workflow.expectOmits("curl");
    try workflow.expectOmits("ukify");
    try workflow.expectContains("test -f \"$uki_stub\"");
}

test "the publisher is draft-first, allowlisted, and fail-safe" {
    const Source = @import("ubuntu2604_source.zig").Source;
    const source = @import("ubuntu2604_source.zig");
    var script = try Source.open(allocator, "scripts/ubuntu2604_publish.sh");
    defer script.deinit();

    try script.expectContains("test \"$(wc -l <\"$expected_file\")\" -eq 4");
    // The published allowlist is derived by the release tooling from the
    // staged manifest, and the shell only consumes the result.
    try script.expectContains("\"$RELEASE_TOOL\" publish-expected");
    try script.expectContains("--assets-dir \"$assets_dir\"");
    try script.expectContains("--native-results \"$NATIVE_RESULTS_DIR\"");
    try script.expectContains("--candidate-run-id \"$CANDIDATE_RUN_ID\"");
    try script.expectContains("--run-id \"$GITHUB_RUN_ID\"");
    try script.expectContains("--run-attempt \"$GITHUB_RUN_ATTEMPT\"");
    try script.expectContains("--draft");
    try script.expectContains("stale-asset-ids");
    try script.expectContains("retaining $RELEASE_TAG as a draft");
    try script.expectContains("--json isDraft");
    try script.expectContains("date -u +%Y%m%d");
    try script.expectContains("Final release $RELEASE_TAG is immutable after its tag date");
    try script.expectContains("gh release download \"$RELEASE_TAG\"");
    try script.expectContains("\"$RELEASE_TOOL\" github-release-downloaded");
    try source.expectOrder(
        script.text,
        "gh release create \"$RELEASE_TAG\"",
        "gh release upload \"$RELEASE_TAG\"",
        "publish",
    );
    const download_index = try script.indexOf("\"$RELEASE_TOOL\" github-release-downloaded");
    const remainder = script.text[download_index..];
    try source.expectContainsIn(
        remainder,
        "gh release edit \"$RELEASE_TAG\"",
        "publish",
    );
    // Publication depends on no interpreter.
    try script.expectOmits(source.interpreter);
}

// ---- github-release-assets ----

const release_workflow = release.workflow;

/// Runs `github-release-assets` against a remote release document and the
/// staged allowlist. `true` means accepted; on `false` the rejection text is
/// in `diagnostic`.
///
/// The caller owns the `Diagnostic` because its message lives in the struct's
/// own inline buffer: returning `diagnostic.message()` from here would hand
/// back a slice into a frame that has already been popped, which compares
/// correctly only for as long as nothing reuses the stack.
fn checkReleaseAssets(
    subject: *const Tree,
    remote: []const u8,
    expected_lines: []const u8,
    stage_name: []const u8,
    diagnostic: *support.Diagnostic,
) !bool {
    const remote_path = try subject.path("release.json", .{});
    defer allocator.free(remote_path);
    try Dir.cwd().writeFile(io, .{ .sub_path = remote_path, .data = remote });
    const expected_path = try subject.path("expected.tsv", .{});
    defer allocator.free(expected_path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = expected_path,
        .data = expected_lines,
    });

    release_workflow.releaseAssets(
        allocator,
        io,
        remote_path,
        expected_path,
        stage_name,
        diagnostic,
    ) catch |err| switch (err) {
        error.Failed => return false,
        else => return err,
    };
    return true;
}

/// Overwrites the stack the callee just released. A helper that hands back a
/// slice into its own frame still compares equal by luck; it does not survive
/// a comparison taken after this.
///
/// `noinline` because the guard is the write, not the call: inlined into the
/// caller this would get its own live storage rather than reusing the frame
/// the callee gave back, and the regression it exists to catch would pass.
noinline fn clobberStack() void {
    var scratch: [8192]u8 = undefined;
    for (&scratch, 0..) |*byte, index| byte.* = @truncate(index +% 0x5a);
    std.mem.doNotOptimizeAway(&scratch);
}

const publication_allowlist =
    "Ubuntu-26.04-x86_64.qcow2\t" ++ "a" ** 64 ++ "\t2048\n" ++
    "Ubuntu-26.04-aarch64.qcow2\t" ++ "b" ** 64 ++ "\t4096\n" ++
    "Ubuntu-26.04-x86_64.core.qcow2\t" ++ "c" ** 64 ++ "\t6144\n" ++
    "Ubuntu-26.04-aarch64.core.qcow2\t" ++ "d" ** 64 ++ "\t8192\n";

fn expectAssetsAccepted(
    subject: *const Tree,
    remote: []const u8,
    stage_name: []const u8,
) !void {
    var diagnostic: support.Diagnostic = .{};
    if (try checkReleaseAssets(
        subject,
        remote,
        publication_allowlist,
        stage_name,
        &diagnostic,
    )) return;
    std.debug.print("unexpected rejection: {s}\n", .{diagnostic.message()});
    return error.UnexpectedRejection;
}

fn expectAssetsRejected(
    subject: *const Tree,
    remote: []const u8,
    stage_name: []const u8,
    expected_message: []const u8,
) !void {
    var diagnostic: support.Diagnostic = .{};
    if (try checkReleaseAssets(
        subject,
        remote,
        publication_allowlist,
        stage_name,
        &diagnostic,
    )) return error.ExpectedRejection;
    // The message is read after the callee's frame has been reused, so this
    // asserts the text is owned here rather than borrowed from that frame.
    clobberStack();
    try std.testing.expectEqualStrings(expected_message, diagnostic.message());
}

const draft_mismatch = "remote release asset allowlist/size mismatch: 4 assets";
const final_mismatch = "published release did not retain the exact final allowlist";

test "github-release-assets binds each remote asset to one allowlist entry" {
    var subject = try tree();
    defer subject.deinit();

    const exact =
        \\{"draft": true, "assets": [
        \\  {"name": "Ubuntu-26.04-x86_64.qcow2", "size": 2048},
        \\  {"name": "Ubuntu-26.04-aarch64.qcow2", "size": 4096},
        \\  {"name": "Ubuntu-26.04-x86_64.core.qcow2", "size": 6144},
        \\  {"name": "Ubuntu-26.04-aarch64.core.qcow2", "size": 8192}
        \\]}
    ;
    try expectAssetsAccepted(&subject, exact, "draft");

    // Order is not part of the contract; the binding is.
    const reordered =
        \\{"draft": true, "assets": [
        \\  {"name": "Ubuntu-26.04-aarch64.core.qcow2", "size": 8192},
        \\  {"name": "Ubuntu-26.04-x86_64.core.qcow2", "size": 6144},
        \\  {"name": "Ubuntu-26.04-aarch64.qcow2", "size": 4096},
        \\  {"name": "Ubuntu-26.04-x86_64.qcow2", "size": 2048}
        \\]}
    ;
    try expectAssetsAccepted(&subject, reordered, "draft");

    // The count matches and every name is allowlisted, but one expected asset
    // is absent: without a one-to-one binding this reads as a clean release.
    const duplicated =
        \\{"draft": true, "assets": [
        \\  {"name": "Ubuntu-26.04-x86_64.qcow2", "size": 2048},
        \\  {"name": "Ubuntu-26.04-aarch64.qcow2", "size": 4096},
        \\  {"name": "Ubuntu-26.04-x86_64.core.qcow2", "size": 6144},
        \\  {"name": "Ubuntu-26.04-x86_64.core.qcow2", "size": 6144}
        \\]}
    ;
    try expectAssetsRejected(&subject, duplicated, "draft", draft_mismatch);

    const wrong_size =
        \\{"draft": true, "assets": [
        \\  {"name": "Ubuntu-26.04-x86_64.qcow2", "size": 2048},
        \\  {"name": "Ubuntu-26.04-aarch64.qcow2", "size": 4096},
        \\  {"name": "Ubuntu-26.04-x86_64.core.qcow2", "size": 6145},
        \\  {"name": "Ubuntu-26.04-aarch64.core.qcow2", "size": 8192}
        \\]}
    ;
    try expectAssetsRejected(&subject, wrong_size, "draft", draft_mismatch);

    const unknown_name =
        \\{"draft": true, "assets": [
        \\  {"name": "Ubuntu-26.04-x86_64.qcow2", "size": 2048},
        \\  {"name": "Ubuntu-26.04-aarch64.qcow2", "size": 4096},
        \\  {"name": "Ubuntu-26.04-x86_64.core.qcow2", "size": 6144},
        \\  {"name": "SHA256SUMS", "size": 8192}
        \\]}
    ;
    try expectAssetsRejected(&subject, unknown_name, "draft", draft_mismatch);

    const extra =
        \\{"draft": true, "assets": [
        \\  {"name": "Ubuntu-26.04-x86_64.qcow2", "size": 2048},
        \\  {"name": "Ubuntu-26.04-aarch64.qcow2", "size": 4096},
        \\  {"name": "Ubuntu-26.04-x86_64.core.qcow2", "size": 6144},
        \\  {"name": "Ubuntu-26.04-aarch64.core.qcow2", "size": 8192},
        \\  {"name": "SHA256SUMS", "size": 1}
        \\]}
    ;
    try expectAssetsRejected(
        &subject,
        extra,
        "draft",
        "remote release asset allowlist/size mismatch: 5 assets",
    );

    // A release that stopped being a draft is refused before it is downloaded.
    const published =
        \\{"draft": false, "assets": [
        \\  {"name": "Ubuntu-26.04-x86_64.qcow2", "size": 2048},
        \\  {"name": "Ubuntu-26.04-aarch64.qcow2", "size": 4096},
        \\  {"name": "Ubuntu-26.04-x86_64.core.qcow2", "size": 6144},
        \\  {"name": "Ubuntu-26.04-aarch64.core.qcow2", "size": 8192}
        \\]}
    ;
    try expectAssetsRejected(
        &subject,
        published,
        "draft",
        "release stopped being a draft before verification",
    );
}

test "github-release-assets holds the final stage to the same one-to-one set" {
    var subject = try tree();
    defer subject.deinit();

    const exact =
        \\{"draft": false, "assets": [
        \\  {"name": "Ubuntu-26.04-x86_64.qcow2", "size": 2048},
        \\  {"name": "Ubuntu-26.04-aarch64.qcow2", "size": 4096},
        \\  {"name": "Ubuntu-26.04-x86_64.core.qcow2", "size": 6144},
        \\  {"name": "Ubuntu-26.04-aarch64.core.qcow2", "size": 8192}
        \\]}
    ;
    try expectAssetsAccepted(&subject, exact, "final");

    const duplicated =
        \\{"draft": false, "assets": [
        \\  {"name": "Ubuntu-26.04-x86_64.qcow2", "size": 2048},
        \\  {"name": "Ubuntu-26.04-aarch64.qcow2", "size": 4096},
        \\  {"name": "Ubuntu-26.04-aarch64.core.qcow2", "size": 8192},
        \\  {"name": "Ubuntu-26.04-aarch64.core.qcow2", "size": 8192}
        \\]}
    ;
    try expectAssetsRejected(&subject, duplicated, "final", final_mismatch);

    // The published bytes are the validated bytes, so a size that changed
    // between the draft check and publication is a rejection, not a detail
    // the final stage may ignore.
    const resized =
        \\{"draft": false, "assets": [
        \\  {"name": "Ubuntu-26.04-x86_64.qcow2", "size": 2049},
        \\  {"name": "Ubuntu-26.04-aarch64.qcow2", "size": 4096},
        \\  {"name": "Ubuntu-26.04-x86_64.core.qcow2", "size": 6144},
        \\  {"name": "Ubuntu-26.04-aarch64.core.qcow2", "size": 8192}
        \\]}
    ;
    try expectAssetsRejected(&subject, resized, "final", final_mismatch);

    const still_draft =
        \\{"draft": true, "assets": [
        \\  {"name": "Ubuntu-26.04-x86_64.qcow2", "size": 2048},
        \\  {"name": "Ubuntu-26.04-aarch64.qcow2", "size": 4096},
        \\  {"name": "Ubuntu-26.04-x86_64.core.qcow2", "size": 6144},
        \\  {"name": "Ubuntu-26.04-aarch64.core.qcow2", "size": 8192}
        \\]}
    ;
    try expectAssetsRejected(&subject, still_draft, "final", final_mismatch);

    const missing =
        \\{"draft": false, "assets": [
        \\  {"name": "Ubuntu-26.04-x86_64.qcow2", "size": 2048},
        \\  {"name": "Ubuntu-26.04-aarch64.qcow2", "size": 4096},
        \\  {"name": "Ubuntu-26.04-x86_64.core.qcow2", "size": 6144}
        \\]}
    ;
    try expectAssetsRejected(
        &subject,
        missing,
        "final",
        final_mismatch,
    );
}

test "the publication allowlist refuses a repeated asset name" {
    var subject = try tree();
    defer subject.deinit();

    const remote =
        \\{"draft": true, "assets": [
        \\  {"name": "ubuntu-26.04-x86_64.qcow2", "size": 2048},
        \\  {"name": "ubuntu-26.04-x86_64.qcow2", "size": 2048}
        \\]}
    ;
    const repeated =
        "ubuntu-26.04-x86_64.qcow2\t" ++ "a" ** 64 ++ "\t2048\n" ++
        "ubuntu-26.04-x86_64.qcow2\t" ++ "a" ** 64 ++ "\t2048\n";
    var diagnostic: support.Diagnostic = .{};
    if (try checkReleaseAssets(
        &subject,
        remote,
        repeated,
        "draft",
        &diagnostic,
    )) return error.ExpectedRejection;
    clobberStack();
    try std.testing.expectEqualStrings(
        "publication allowlist line is malformed",
        diagnostic.message(),
    );
}

// ---- staged and downloaded allowlists ----

/// Runs `publish-expected` over a real staged directory, returning the
/// allowlist it printed. The caller owns `diagnostic` for the same reason
/// `checkReleaseAssets`'s does.
fn publishExpected(
    subject: *const Tree,
    out: *std.Io.Writer,
    diagnostic: *support.Diagnostic,
) !bool {
    const manifest_path = try subject.path("staged/publish-manifest.json", .{});
    defer allocator.free(manifest_path);
    const staged = try subject.path("staged", .{});
    defer allocator.free(staged);
    release_workflow.publishExpected(
        allocator,
        io,
        out,
        manifest_path,
        staged,
        publication_tag,
        fixture.source_commit,
        diagnostic,
    ) catch |err| switch (err) {
        error.Failed => return false,
        else => return err,
    };
    return true;
}

/// A staged tree whose `publish-expected` allowlist has already been accepted,
/// so any later rejection is caused by what the test changed.
fn stagedSubject() !Tree {
    var subject = try tree();
    errdefer subject.deinit();
    try makeAll(&subject);
    try stage(&subject, publication_tag);
    return subject;
}

fn expectStagedAccepted(subject: *const Tree) ![]u8 {
    var buffer: [4096]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    var diagnostic: support.Diagnostic = .{};
    if (!try publishExpected(subject, &out, &diagnostic)) {
        std.debug.print("unexpected rejection: {s}\n", .{diagnostic.message()});
        return error.UnexpectedRejection;
    }
    return allocator.dupe(u8, out.buffered());
}

fn expectStagedRejected(subject: *const Tree, expected_message: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    var diagnostic: support.Diagnostic = .{};
    if (try publishExpected(subject, &out, &diagnostic)) {
        return error.ExpectedRejection;
    }
    clobberStack();
    try std.testing.expectEqualStrings(expected_message, diagnostic.message());
}

test "publish-expected rejects the pre-provenance manifest schema" {
    var subject = try stagedSubject();
    defer subject.deinit();
    const manifest = try subject.path("staged/publish-manifest.json", .{});
    defer allocator.free(manifest);
    try fixture.patchInteger(
        allocator,
        io,
        manifest,
        &.{.{ .key = "schema" }},
        1,
    );
    try expectStagedRejected(
        &subject,
        "unexpected Ubuntu publish manifest schema",
    );
}

test "publish-expected counts a symlinked staged asset as a staged file" {
    var subject = try stagedSubject();
    defer subject.deinit();

    const allowlist = try expectStagedAccepted(&subject);
    defer allocator.free(allowlist);
    try std.testing.expectEqual(
        contracts.release_order.len,
        std.mem.count(u8, allowlist, "\n"),
    );

    // An extra entry that `readdir` reports as a symlink is a file to
    // `is_file()`, so it is an unallowlisted staged asset and not something
    // the scan may skip on the strength of its dirent kind.
    const staged = try subject.path("staged", .{});
    defer allocator.free(staged);
    var directory = try Dir.cwd().openDir(io, staged, .{ .iterate = true });
    defer directory.close(io);
    try directory.symLink(
        io,
        contracts.lookup(contracts.release_order[0]).?.asset_name,
        "SHA256SUMS",
        .{},
    );
    try expectStagedRejected(
        &subject,
        "staged release allowlist mismatch: SHA256SUMS",
    );
}

test "publish-expected ignores staged entries that are not regular files" {
    var subject = try stagedSubject();
    defer subject.deinit();

    const staged = try subject.path("staged", .{});
    defer allocator.free(staged);
    var directory = try Dir.cwd().openDir(io, staged, .{ .iterate = true });
    defer directory.close(io);
    // A directory, a symlink to one, and a broken symlink are all "not a
    // file" to `is_file()`, whatever their dirent kinds say.
    try directory.createDirPath(io, "scratch");
    try directory.symLink(io, "scratch", "linked-scratch", .{});
    try directory.symLink(io, "removed.qcow2", "dangling", .{});

    const allowlist = try expectStagedAccepted(&subject);
    defer allocator.free(allowlist);
    try std.testing.expectEqual(
        contracts.release_order.len,
        std.mem.count(u8, allowlist, "\n"),
    );
}

test "publish-expected still refuses a staged file the manifest never named" {
    var subject = try stagedSubject();
    defer subject.deinit();

    const extra = try subject.path("staged/SHA256SUMS", .{});
    defer allocator.free(extra);
    try Dir.cwd().writeFile(io, .{ .sub_path = extra, .data = "digest\n" });
    try expectStagedRejected(
        &subject,
        "staged release allowlist mismatch: SHA256SUMS",
    );
}

fn checkDownloaded(
    subject: *const Tree,
    expected_lines: []const u8,
    diagnostic: *support.Diagnostic,
) !bool {
    const expected_path = try subject.path("downloaded-expected.tsv", .{});
    defer allocator.free(expected_path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = expected_path,
        .data = expected_lines,
    });
    const root = try subject.path("downloaded", .{});
    defer allocator.free(root);
    release_workflow.releaseDownloaded(
        allocator,
        io,
        root,
        expected_path,
        diagnostic,
    ) catch |err| switch (err) {
        error.Failed => return false,
        else => return err,
    };
    return true;
}

const downloaded_payload = "downloaded release asset\n";

/// A download directory holding exactly the allowlisted assets, plus the
/// allowlist that describes them.
fn downloadedSubject(subject: *const Tree) ![]u8 {
    const root = try subject.path("downloaded", .{});
    defer allocator.free(root);
    try Dir.cwd().createDirPath(io, root);

    var expected: std.ArrayList(u8) = .empty;
    errdefer expected.deinit(allocator);
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(downloaded_payload, &digest, .{});
    for (contracts.release_order) |key| {
        const name = contracts.lookup(key).?.asset_name;
        const path = try subject.path("downloaded/{s}", .{name});
        defer allocator.free(path);
        try Dir.cwd().writeFile(io, .{
            .sub_path = path,
            .data = downloaded_payload,
        });
        try expected.print(allocator, "{s}\t{s}\t{d}\n", .{
            name,
            &std.fmt.bytesToHex(digest, .lower),
            downloaded_payload.len,
        });
    }
    return expected.toOwnedSlice(allocator);
}

test "github-release-downloaded counts a symlinked download as a file" {
    var subject = try tree();
    defer subject.deinit();
    const expected = try downloadedSubject(&subject);
    defer allocator.free(expected);

    var accepted: support.Diagnostic = .{};
    try std.testing.expect(try checkDownloaded(&subject, expected, &accepted));

    const root = try subject.path("downloaded", .{});
    defer allocator.free(root);
    var directory = try Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer directory.close(io);
    try directory.symLink(
        io,
        contracts.lookup(contracts.release_order[0]).?.asset_name,
        "SHA256SUMS",
        .{},
    );

    var diagnostic: support.Diagnostic = .{};
    try std.testing.expect(!try checkDownloaded(&subject, expected, &diagnostic));
    clobberStack();
    try std.testing.expectEqualStrings(
        "downloaded release allowlist mismatch: SHA256SUMS",
        diagnostic.message(),
    );
}

test "github-release-downloaded ignores entries that are not regular files" {
    var subject = try tree();
    defer subject.deinit();
    const expected = try downloadedSubject(&subject);
    defer allocator.free(expected);

    const root = try subject.path("downloaded", .{});
    defer allocator.free(root);
    var directory = try Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer directory.close(io);
    try directory.createDirPath(io, "scratch");
    try directory.symLink(io, "scratch", "linked-scratch", .{});
    try directory.symLink(io, "removed.qcow2", "dangling", .{});

    var diagnostic: support.Diagnostic = .{};
    try std.testing.expect(try checkDownloaded(&subject, expected, &diagnostic));
}

test "github-release-downloaded refuses a missing asset and a wrong one" {
    var subject = try tree();
    defer subject.deinit();
    const expected = try downloadedSubject(&subject);
    defer allocator.free(expected);

    const first = contracts.lookup(contracts.release_order[0]).?.asset_name;
    const path = try subject.path("downloaded/{s}", .{first});
    defer allocator.free(path);
    try Dir.cwd().deleteFile(io, path);

    var missing: support.Diagnostic = .{};
    try std.testing.expect(!try checkDownloaded(&subject, expected, &missing));
    clobberStack();
    try std.testing.expectEqualStrings(
        "downloaded release allowlist mismatch: 3 files",
        missing.message(),
    );

    // Restoring it with different bytes keeps the name set exact and moves the
    // rejection to the digest, so the count check has not swallowed it.
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "tampered\n" });
    var tampered: support.Diagnostic = .{};
    try std.testing.expect(!try checkDownloaded(&subject, expected, &tampered));
    clobberStack();
    const message = tampered.message();
    try std.testing.expect(std.mem.endsWith(u8, message, ": downloaded size mismatch"));
    try std.testing.expect(std.mem.startsWith(u8, message, first));
}
