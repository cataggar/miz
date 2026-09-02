//! Guards for `scripts/ubuntu2604_azure_acceptance.sh` and its library.
//!
//! Two kinds of assertion live here, and both come from the Python suite this
//! replaces.
//!
//! The first is structural: the harness's guest contracts, its Binder
//! sections, its diagnostics, and its refusal to persist boot
//! diagnostic SAS URIs are all expressed as shell text, so they are checked as
//! shell text.
//!
//! The second actually runs the harness. `cleanup` is the one path that
//! deletes Azure resources, so its identity validation and its ownership-tag
//! check are exercised end to end against a stub `az`, including the
//! regression that a non-exact tag set must abort the delete.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const source = @import("ubuntu2604_source.zig");

const Source = source.Source;
const script_path = "scripts/ubuntu2604_azure_acceptance.sh";
const library_path = "scripts/ubuntu2604_azure_acceptance_lib.sh";

fn open() !Source {
    return Source.open(std.testing.allocator, script_path);
}

test "the cleanup identity check accepts every candidate key and rejects the rest" {
    var harness = try Harness.create();
    defer harness.deinit();

    const keys = [_][]const u8{
        "x86_64-full",
        "aarch64-full",
        "x86_64-core",
        "aarch64-core",
    };
    for (keys) |key| {
        const result = try harness.runCleanup(key, &.{});
        defer result.deinit(std.testing.allocator);
        if (!result.succeeded()) {
            std.debug.print("{s}: cleanup rejected a valid key: {s}\n", .{
                key,
                result.stderr,
            });
            return error.UnexpectedCleanupFailure;
        }
    }

    const rejected = try harness.runCleanup("riscv64-core", &.{});
    defer rejected.deinit(std.testing.allocator);
    try std.testing.expect(!rejected.succeeded());
}

test "extra command arguments are a usage error" {
    var harness = try Harness.create();
    defer harness.deinit();
    const result = try harness.run(
        &.{ "cleanup", "unexpected" },
        "x86_64-full",
        &.{},
    );
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(?u8, 2), result.exitCode());
    try source.expectContainsIn(result.stderr, "usage:", "cleanup usage");
}

test "the candidate identity helper requires the exact flavor/asset tuple" {
    var harness = try Harness.create();
    defer harness.deinit();

    const valid = [_][2][]const u8{
        .{ "x86_64-full", "Ubuntu-26.04-x86_64.qcow2" },
        .{ "aarch64-full", "Ubuntu-26.04-aarch64.qcow2" },
        .{ "x86_64-core", "Ubuntu-26.04-x86_64.core.qcow2" },
        .{ "aarch64-core", "Ubuntu-26.04-aarch64.core.qcow2" },
    };
    for (valid) |entry| {
        const key = entry[0];
        const asset = entry[1];
        const separator = std.mem.indexOfScalar(u8, key, '-').?;
        const architecture = key[0..separator];
        const flavor = key[separator + 1 ..];

        var command_buffer: [256]u8 = undefined;
        const command = try std.fmt.bufPrint(
            &command_buffer,
            "ubuntu2604_validate_candidate_identity {s} {s} {s} {s}",
            .{ key, architecture, flavor, asset },
        );
        const result = try harness.runLibrary(command);
        defer result.deinit(std.testing.allocator);
        if (!result.succeeded()) {
            std.debug.print("{s}: rejected a valid tuple: {s}\n", .{ key, result.stderr });
            return error.UnexpectedIdentityFailure;
        }

        var asset_buffer: [128]u8 = undefined;
        const asset_command = try std.fmt.bufPrint(
            &asset_buffer,
            "ubuntu2604_expected_asset {s} {s}",
            .{ architecture, flavor },
        );
        const asset_result = try harness.runLibrary(asset_command);
        defer asset_result.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings(
            asset,
            std.mem.trim(u8, asset_result.stdout, " \n"),
        );
    }

    const rejected = [_][]const u8{
        "ubuntu2604_validate_candidate_identity x86_64-core x86_64 full Ubuntu-26.04-x86_64.core.qcow2",
        "ubuntu2604_validate_candidate_identity x86_64-core x86_64 core Ubuntu-26.04-x86_64.qcow2",
        "ubuntu2604_validate_candidate_identity riscv64-core riscv64 core Ubuntu-26.04-riscv64.core.qcow2",
    };
    for (rejected) |command| {
        const result = try harness.runLibrary(command);
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(!result.succeeded());
    }
}

test "the curl auth header is a private bearer header written with mode 0600" {
    var harness = try Harness.create();
    defer harness.deinit();

    var header_buffer: [512]u8 = undefined;
    const header = try harness.path(&header_buffer, "auth-header");
    const token = "regression-token-not-a-secret";
    var command_buffer: [1024]u8 = undefined;
    const command = try std.fmt.bufPrint(
        &command_buffer,
        "write_bearer_header '{s}' '{s}'",
        .{ token, header },
    );
    const result = try harness.runLibrary(command);
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.succeeded());
    try source.expectOmitsIn(result.stdout, token, "write_bearer_header stdout");
    try source.expectOmitsIn(result.stderr, token, "write_bearer_header stderr");

    const written = try Dir.cwd().readFileAlloc(
        std.testing.io,
        header,
        std.testing.allocator,
        .limited(1024),
    );
    defer std.testing.allocator.free(written);
    var expected_buffer: [256]u8 = undefined;
    const expected = try std.fmt.bufPrint(
        &expected_buffer,
        "Authorization: Bearer {s}\n",
        .{token},
    );
    try std.testing.expectEqualStrings(expected, written);
    const stat = try Dir.cwd().statFile(std.testing.io, header, .{});
    try std.testing.expectEqual(
        @as(std.posix.mode_t, 0o600),
        stat.permissions.toMode() & 0o777,
    );

    var script = try open();
    defer script.deinit();
    try script.expectContains("write_bearer_header \"$token\" \"$auth_header\"\n  token=");
    try script.expectContains("--header \"@$auth_header\"");
}

test "cleanup deletes only a resource group whose ownership tags are exact" {
    var harness = try Harness.create();
    defer harness.deinit();
    try harness.writeStubAz();

    var state_buffer: [512]u8 = undefined;
    const state = try harness.path(&state_buffer, "state");
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = state,
        .data = "miz-u2604-123-4-x86-64-full\n",
    });
    var marker_buffer: [512]u8 = undefined;
    const marker = try harness.path(&marker_buffer, "deleted");

    const exact =
        \\{"miz-owner": "ubuntu2604-release", "miz-run-id": "123",
        \\ "miz-run-attempt": "4", "miz-candidate": "x86_64-full"}
    ;
    var tags_buffer: [512]u8 = undefined;
    var marker_variable_buffer: [512]u8 = undefined;
    const tags_variable = try std.fmt.bufPrint(
        &tags_buffer,
        "MOCK_TAGS={s}",
        .{exact},
    );
    const marker_variable = try std.fmt.bufPrint(
        &marker_variable_buffer,
        "DELETE_MARKER={s}",
        .{marker},
    );

    const accepted = try harness.run(
        &.{"cleanup"},
        "x86_64-full",
        &.{ tags_variable, marker_variable },
    );
    defer accepted.deinit(std.testing.allocator);
    if (!accepted.succeeded()) {
        std.debug.print("cleanup refused exact tags: {s}\n", .{accepted.stderr});
        return error.UnexpectedCleanupFailure;
    }
    try std.testing.expect(
        Dir.cwd().statFile(std.testing.io, marker, .{}) catch null != null,
    );

    try Dir.cwd().deleteFile(std.testing.io, marker);
    const foreign =
        \\{"miz-owner": "someone-else", "miz-run-id": "123",
        \\ "miz-run-attempt": "4", "miz-candidate": "x86_64-full"}
    ;
    var foreign_buffer: [512]u8 = undefined;
    const foreign_variable = try std.fmt.bufPrint(
        &foreign_buffer,
        "MOCK_TAGS={s}",
        .{foreign},
    );
    const refused = try harness.run(
        &.{"cleanup"},
        "x86_64-full",
        &.{ foreign_variable, marker_variable },
    );
    defer refused.deinit(std.testing.allocator);
    try std.testing.expect(!refused.succeeded());
    try std.testing.expectError(
        error.FileNotFound,
        Dir.cwd().statFile(std.testing.io, marker, .{}),
    );
}

test "the conversion attestation binds the qemu info digest" {
    var script = try open();
    defer script.deinit();
    // The attestation is derived from the qemu-img document itself, and its
    // digest is recorded in the attestation the acceptance result binds.
    try script.expectContains("\"$RELEASE_TOOL\" azure-conversion-attestation");
    try script.expectContains("--info \"$RESULT_DIR/vhd-info.json\"");
    try script.expectContains("--vhd-current-size \"$vhd_current_size\"");
    // The acceptance result re-derives every size from the attestation and the
    // VHD, so it never accepts a size as an argument.
    const azure_result = try script.section(
        "\"$RELEASE_TOOL\" azure-result \\",
        "\n\"$RELEASE_TOOL\" verify-azure-result",
    );
    try source.expectContainsIn(
        azure_result,
        "--vhd-info \"$RESULT_DIR/vhd-info.json\"",
        "azure-result",
    );
    try source.expectContainsIn(
        azure_result,
        "--conversion-attestation \"$conversion_attestation\"",
        "azure-result",
    );
    try source.expectOmitsIn(azure_result, "--vhd-current-size", "azure-result");
    try source.expectOmitsIn(azure_result, "--vhd-bytes", "azure-result");
}

test "core contract checks are explicit and the full checks are preserved" {
    var script = try open();
    defer script.deinit();
    try script.expectContains("--run-id \"$CANDIDATE_RUN_ID\"");
    try script.expectContains("--run-attempt \"$CANDIDATE_RUN_ATTEMPT\"");
    try script.expectContains("readarray -t sku_storage");
    try script.expectContains("has_conventional_resource_disk=${sku_storage[0]}");
    try script.expectContains("has_local_temp_storage=${sku_storage[1]}");
    const core = try script.section(
        "if [[ \"$FLAVOR\" == core ]]; then\n  readarray -t core_identity",
        "\nelse\n  ssh \"${ssh_options[@]}\" \"$ssh_target\" \\\n" ++
            "    \"/usr/bin/bash -s -- '$has_conventional_resource_disk'\" <<'GUEST'",
    );
    const required = [_][]const u8{
        "/proc/1/exe -ef /sbin/mizinit",
        "test -x /usr/sbin/azagent",
        "test -s /var/lib/azagent/provisioned",
        "ResourceDisk.Format",
        "DataDisk.Mount",
        "/var/lib/cloud",
        "/var/lib/waagent",
        "/var/log/azure",
        "test ! -d /run/systemd/system",
        "initial_machine_id",
        "initial_host_key_fingerprint",
        "initial_authorized_keys_sha256",
        "initial_sentinel_sha256",
        "test \"$has_local_temp_storage\" = true",
        "mount_source=$(findmnt -n -o SOURCE --target /d)",
        "test -b \"$mount_source\"",
        "\"$resource_disk\" != \"$root_disk\"",
        "DATALOSS_WARNING_README.txt",
        "grep -Fq \"temporary resource disk\"",
        "test \"$swap_disk\" != \"$resource_disk\"",
    };
    for (required) |needle| try source.expectContainsIn(core, needle, "core contracts");
    try source.expectOmitsIn(core, "systemctl is-active", "core contracts");

    try script.expectContains("/usr/sbin/sshd -D -e");
    try script.expectContains("read_core_sshd_pid");
    try script.expectContains("/usr/bin/kill -KILL");
    try script.expectContains("az vm extension list");
    try script.expectContains("test -z \"${first_sector//0/}\"");
    try script.expectContains("\"$RELEASE_TOOL\" verify-azure-result");
    try script.expectContains("--contracts \"$azure_contract_list\"");

    const full = try script.section(
        "\nelse\n  ssh \"${ssh_options[@]}\" \"$ssh_target\" \\\n" ++
            "    \"/usr/bin/bash -s -- '$has_conventional_resource_disk'\" <<'GUEST'",
        "\nfi\n",
    );
    try source.expectContainsIn(full, "/proc/1/exe -ef /usr/lib/systemd/systemd", "full");
    try source.expectContainsIn(full, "cloud-init status --wait", "full");
    try source.expectContainsIn(full, "walinuxagent.service", "full");
    try source.expectContainsIn(full, "networkd-dispatcher.service", "full");
    try source.expectContainsIn(
        full,
        "check udisks2-installed package_installed udisks2",
        "full",
    );
    try source.expectContainsIn(full, "Name=org.freedesktop.UDisks2", "full");
    try source.expectContainsIn(full, "SystemdService=udisks2.service", "full");
    try source.expectContainsIn(
        full,
        "udisks2-graphical-eager-start-absent",
        "full",
    );
    try source.expectContainsIn(
        full,
        "failed_units=$(systemctl --failed --no-legend --plain)",
        "full",
    );
    try source.expectContainsIn(full, "test -z \"$failed_units\"", "full");
    try source.expectContainsIn(
        full,
        "systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,TimeoutStartUSec",
        "full",
    );
    try source.expectContainsIn(
        full,
        "sudo -n journalctl --no-pager --boot=0 --unit \"$unit\" --priority=info..emerg --lines=120",
        "full",
    );
    try source.expectContainsIn(full, "head -c 49152", "full");
    try source.expectContainsIn(full, "head -n 8", "full");
    try source.expectOmitsIn(full, "--property=Environment", "full");
    try source.expectContainsIn(full, "validate_conventional_resource_disk", "full");
    try source.expectContainsIn(full, "mountpoint -q /mnt || return 1", "full");
    try source.expectContainsIn(full, "\"$resource_disk\" != \"$root_disk\"", "full");
    try source.expectContainsIn(full, "/mnt/*) return 1", "full");
    try source.expectOmitsIn(
        full,
        "conventional-resource-disk-not-mounted not_mountpoint /mnt",
        "full",
    );
    try script.expectOmits(
        "test \"$(systemctl --failed --no-legend --plain | wc -l)\" -eq 0",
    );
}

test "failure diagnostics never persist boot diagnostic SAS URIs" {
    var script = try open();
    defer script.deinit();
    const diagnostics = try script.section(
        "collect_failure_diagnostics() {",
        "\n}\n\ncleanup_on_exit()",
    );
    try source.expectContainsIn(
        diagnostics,
        "instanceView.bootDiagnostics.serialConsoleLogBlobUri",
        "diagnostics",
    );
    try source.expectContainsIn(
        diagnostics,
        "instanceView.bootDiagnostics.consoleScreenshotBlobUri",
        "diagnostics",
    );
    try source.expectContainsIn(diagnostics, "serial_console_uri=\n", "diagnostics");
    try source.expectContainsIn(diagnostics, "console_screenshot_uri=\n", "diagnostics");
    // Only the retrieval status reaches the recorded document, never the SAS
    // URI it was fetched from.
    const document = try script.section(
        "\"$RELEASE_TOOL\" azure-failure-diagnostics \\",
        "\n}",
    );
    try source.expectContainsIn(document, "--output \"$failure_diagnostics\"", "document");
    try source.expectContainsIn(document, "--instance-view \"$instance_view_status\"", "document");
    try source.expectContainsIn(
        document,
        "--serial-console-log \"$boot_log_status\"",
        "document",
    );
    try source.expectContainsIn(
        document,
        "--console-screenshot \"$boot_screenshot_status\"",
        "document",
    );
    try source.expectOmitsIn(document, "serial_console_uri", "document");
    try source.expectOmitsIn(document, "console_screenshot_uri", "document");
}

test "the Binder probe is required only for the core flavor" {
    var script = try open();
    defer script.deinit();
    try script.expectContains(
        "if [[ \"$FLAVOR\" == core ]]; then\n" ++
            "  if [[ -z ${BINDER_PROBE:-} ]]; then\n" ++
            "    echo \"::error::Core Azure acceptance requires a Binder device probe binary\"",
    );
    try script.expectContains("[[ -x \"$BINDER_PROBE\" ]]");
    try script.expectContains("base64");
}

test "external secret-bound smoke inputs are absent while Binder remains mandatory" {
    var script = try open();
    defer script.deinit();
    try script.expectOmits("MIZ_UBUNTU2604_" ++ "ANDROID");
    try script.expectOmits("android-" ++ "smoke");
    try script.expectOmits("android_" ++ "container");
    try script.expectOmits("guest-config.json");
    try script.expectContains("Core Azure acceptance requires a Binder device probe binary");
    try script.expectContains("binder_probe_sha256=$(sha256sum");
}

test "core Binder module trust rejects DKMS and Anbox evidence" {
    var script = try open();
    defer script.deinit();
    const module_block = try script.section(
        "if [[ \"$flavor\" == core ]]; then\n  module_info=",
        "\nfi\nGUEST",
    );
    const needles = [_][]const u8{
        "/usr/sbin/modinfo binder_linux",
        "/lib/modules/*/kernel/*",
        "*/updates/dkms/*",
        "test -n \"$module_signer\"",
        "test \"$module_sig_id\" = \"PKCS#7\"",
        "grep -iq anbox",
        "dkms status",
        "/sys/module/binder_linux/taint",
        "test -z \"$module_taint\"",
        "binder_linux:.*(verification failed|taint)",
    };
    for (needles) |needle| try source.expectContainsIn(module_block, needle, "module trust");
}

test "core BinderFS, Binder devices, and DMA heap are probed" {
    var script = try open();
    defer script.deinit();
    const binder = try script.section(
        "if [[ \"$FLAVOR\" == core ]]; then\n  binder_probe_remote=",
        "\nfi\n\nif",
    );
    const needles = [_][]const u8{
        "binder_probe_sha256=$(sha256sum",
        "base64 -w0 \"$BINDER_PROBE\"",
        "binder_probe_remote_sha256",
        "test \"$binder_probe_remote_sha256\" = \"$binder_probe_sha256\"",
        "binderfs_mount=/dev/binderfs",
        "test \"$(findmnt -n -o FSTYPE \"$binderfs_mount\")\" = binder",
        "test -c \"$binderfs_mount/binder-control\"",
        "binder",
        "hwbinder",
        "vndbinder",
        "sudo -n \"$probe\" version",
        "sudo -n \"$probe\" alloc \"$binderfs_mount/binder-control\"",
        "miz-acceptance-probe",
        "dma_heap=/dev/dma_heap/system",
        "test -d /dev/dma_heap",
        "sudo -n test -c \"$dma_heap\"",
        "sudo -n test -r \"$dma_heap\"",
        "sudo -n test -w \"$dma_heap\"",
    };
    for (needles) |needle| try source.expectContainsIn(binder, needle, "binder probe");
}

test "the Binder probe binary targets the public UAPI constants" {
    var probe = try Source.open(std.testing.allocator, "tests/binder_probe.zig");
    defer probe.deinit();
    try probe.expectContains("const BINDER_VERSION: u32 = 0xc0046209;");
    try probe.expectContains("const BINDER_CTL_ADD: u32 = 0xc1086201;");
    try probe.expectContains("protocol_version");
    // The probe speaks only the upstream Binder UAPI.
    try probe.expectOmits("anbox");
    try probe.expectOmits("Anbox");
    try probe.expectOmits("ANBOX");
}

test "cloud-init status is decided host-side and fails closed" {
    var script = try open();
    defer script.deinit();
    // The guest emits the document; the host parses it and compares.
    try script.expectContains("cloud-init status --format json\" |");
    try script.expectContains("\"$RELEASE_TOOL\" cloud-init-status");
    try script.expectContains("test \"$cloud_init_status\" = done");

    const done = try runWithStdin(
        std.testing.allocator,
        "cloud-init-status",
        "{\"status\": \"done\", \"boot_status_code\": \"enabled-by-generator\"}",
    );
    defer done.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(
        "done",
        std.mem.trimEnd(u8, done.stdout, "\n"),
    );

    // A failed cloud-init query is an error rather than a success-shaped
    // default.
    for ([_][]const u8{ "", "not json", "{}" }) |input| {
        const result = try runWithStdin(
            std.testing.allocator,
            "cloud-init-status",
            input,
        );
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(!result.succeeded());
    }
}

test "the harness runs no Python and the library is syntactically valid" {
    var script = try open();
    defer script.deinit();
    try script.expectOmits(source.interpreter ++ " -");
    try script.expectOmits("<<'PY'");
    try script.expectContains(
        "RELEASE_TOOL=${UBUNTU2604_RELEASE_TOOL:-zig-out/bin/ubuntu2604_release}",
    );
    // The only remaining spellings are guest filesystem paths, not commands.
    try script.expectCount(
        "/usr/lib/" ++ source.interpreter ++ "/dist-packages/azurelinuxagent",
        1,
    );
    try script.expectCount(
        "/usr/lib/" ++ source.interpreter ++ "/dist-packages/cloudinit",
        1,
    );
    try script.expectCount(source.interpreter, 2);

    for ([_][]const u8{ script_path, library_path }) |path| {
        const root = try source.rootAlloc(std.testing.allocator);
        defer std.testing.allocator.free(root);
        const full = try std.fs.path.join(std.testing.allocator, &.{ root, path });
        defer std.testing.allocator.free(full);
        const result = try runProcess(
            std.testing.allocator,
            &.{ "bash", "-n", full },
            &.{},
        );
        defer result.deinit(std.testing.allocator);
        if (!result.succeeded()) {
            std.debug.print("{s}: shell syntax error: {s}\n", .{ path, result.stderr });
            return error.ShellSyntaxError;
        }
    }
}

test "core requests no VM agent and skips the vmAgent status check waagent alone can satisfy" {
    var script = try open();
    defer script.deinit();

    // azagent deliberately never implements the VM extension/status-blob
    // handshake real waagent uses (see azagent/main.zig, issue #112), and the
    // core contract elsewhere in this script asserts `az vm extension list`
    // is empty. Requesting --enable-agent true for core makes Azure's
    // OS-provisioning wait on a handshake that never arrives
    // (OSProvisioningTimedOut), and the vmAgent.statuses check can never
    // succeed either, so both must be conditioned on flavor.
    try script.expectContains("enable_agent=true\n");
    try script.expectContains(
        "if [[ \"$FLAVOR\" == core ]]; then\n  enable_agent=false\nfi",
    );
    try script.expectContains("--enable-agent \"$enable_agent\" \\");
    try script.expectOmits("--enable-agent true \\");

    try script.expectCount(
        "instanceView.vmAgent.statuses[?code=='ProvisioningState/succeeded']",
        2,
    );
    try script.expectCount("if [[ \"$FLAVOR\" != core ]]; then\n", 2);
}

test "the data disk first-sector read settles udev and retries a transient short read" {
    var script = try open();
    defer script.deinit();

    // A freshly attached data disk can report its final size before the
    // block layer has finished settling, so `dd` can return fewer than 512
    // bytes right after the reboot that follows `az disk create`/`az vm disk
    // attach` (issue #660). Require a full 512-byte read (1024 hex chars)
    // before trusting it, retrying with `udevadm settle` in between instead
    // of failing on the first short read.
    try script.expectContains("udevadm settle --timeout=5");
    try script.expectContains(
        "if [[ \"${#candidate}\" -eq 1024 ]]; then\n    first_sector=$candidate\n    break\n  fi",
    );
    try script.expectContains("test -n \"$first_sector\"");
    try script.expectContains("test -z \"${first_sector//0/}\"");
}

test "core az vm create tolerates a late OSProvisioningTimedOut instead of failing outright" {
    var script = try open();
    defer script.deinit();

    // Even with #658's --enable-agent false fix applied, `az vm create` can
    // still hit Azure's ARM-deployment-level OSProvisioningTimedOut for core
    // (issue #660): that error is documented by Azure itself as non-fatal
    // ("The VM may still finish provisioning successfully. Please check
    // provisioning state later."), unlike the vmAgent.statuses handshake
    // #658 addressed. Poll a while longer for core rather than failing on
    // the deployment's own timeout alone.
    try script.expectContains("|| vm_create_status=$?");
    try script.expectContains("if [[ \"$vm_create_status\" -ne 0 ]]; then");
    try script.expectContains(
        "if [[ \"$FLAVOR\" == core ]] &&\n      grep -q OSProvisioningTimedOut -- \"$vm_create_stderr\"; then",
    );
    try script.expectContains("extra_wait_seconds=${AZURE_VM_CREATE_EXTRA_WAIT_SECONDS:-1200}");
    try script.expectContains("ProvisioningState/succeeded");
    try script.expectContains("exit \"$vm_create_status\"");
}

// ---- process and fixture support ----

const Result = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: Result, allocator: Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }

    fn exitCode(self: Result) ?u8 {
        return switch (self.term) {
            .exited => |code| code,
            else => null,
        };
    }

    fn succeeded(self: Result) bool {
        return self.exitCode() == 0;
    }
};

const max_output_bytes: usize = 1024 * 1024;

fn toolPath(allocator: Allocator) ![]u8 {
    return source.releaseToolAlloc(allocator);
}

/// Runs `argv` from the repository root with `environment` layered over the
/// inherited environment.
fn runProcess(
    allocator: Allocator,
    argv: []const []const u8,
    environment: []const []const u8,
) !Result {
    const root = try source.rootAlloc(allocator);
    defer allocator.free(root);

    var map = try std.process.Environ.createMap(std.testing.environ, allocator);
    defer map.deinit();
    for (environment) |entry| {
        const separator = std.mem.indexOfScalar(u8, entry, '=').?;
        try map.put(entry[0..separator], entry[separator + 1 ..]);
    }

    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = argv,
        .cwd = .{ .path = root },
        .environ_map = &map,
        .stdout_limit = .limited(max_output_bytes),
        .stderr_limit = .limited(max_output_bytes),
    });
    return .{
        .term = result.term,
        .stdout = result.stdout,
        .stderr = result.stderr,
    };
}

/// Runs the release tool with `input` on standard input. The input is staged
/// in a private file and redirected by the shell, so the command under test is
/// exactly the one the harness pipes into.
fn runWithStdin(
    allocator: Allocator,
    command: []const u8,
    input: []const u8,
) !Result {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try source.rootAlloc(allocator);
    defer allocator.free(root);
    const stdin_path = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}/stdin",
        .{ root, tmp.sub_path },
    );
    defer allocator.free(stdin_path);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = stdin_path,
        .data = input,
    });

    const tool = try toolPath(allocator);
    defer allocator.free(tool);
    const script = try std.fmt.allocPrint(
        allocator,
        "\"$TOOL\" {s} <\"$STDIN\"",
        .{command},
    );
    defer allocator.free(script);
    const tool_variable = try std.fmt.allocPrint(allocator, "TOOL={s}", .{tool});
    defer allocator.free(tool_variable);
    const stdin_variable = try std.fmt.allocPrint(
        allocator,
        "STDIN={s}",
        .{stdin_path},
    );
    defer allocator.free(stdin_variable);
    return runProcess(
        allocator,
        &.{ "bash", "-c", script },
        &.{ tool_variable, stdin_variable },
    );
}

/// A private directory plus the environment the harness's `cleanup` path
/// requires, so each test's state and stub `az` are its own.
const Harness = struct {
    tmp: std.testing.TmpDir,
    root: []u8,

    fn create() !Harness {
        const tmp = std.testing.tmpDir(.{});
        const repository = try source.rootAlloc(std.testing.allocator);
        defer std.testing.allocator.free(repository);
        const root = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}/.zig-cache/tmp/{s}",
            .{ repository, tmp.sub_path },
        );
        errdefer std.testing.allocator.free(root);
        const bin = try std.fmt.allocPrint(std.testing.allocator, "{s}/bin", .{root});
        defer std.testing.allocator.free(bin);
        try Dir.cwd().createDirPath(std.testing.io, bin);
        return .{ .tmp = tmp, .root = root };
    }

    fn deinit(self: *Harness) void {
        std.testing.allocator.free(self.root);
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn path(self: *const Harness, buffer: []u8, name: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buffer, "{s}/{s}", .{ self.root, name });
    }

    /// A stub `az` that answers exactly the three subcommands `cleanup_group`
    /// issues, so the ownership-tag decision is the only variable.
    fn writeStubAz(self: *const Harness) !void {
        var buffer: [512]u8 = undefined;
        const az = try self.path(&buffer, "bin/az");
        try Dir.cwd().writeFile(std.testing.io, .{
            .sub_path = az,
            .data =
            \\#!/usr/bin/env bash
            \\set -euo pipefail
            \\case "$1 $2" in
            \\  "group exists") echo true ;;
            \\  "group show") printf '{"tags": %s}\n' "$MOCK_TAGS" ;;
            \\  "group delete") printf 'deleted\n' >"$DELETE_MARKER" ;;
            \\  *) echo "unexpected az arguments: $*" >&2; exit 1 ;;
            \\esac
            \\
            ,
            .flags = .{ .permissions = .fromMode(0o755) },
        });
    }

    fn runCleanup(
        self: *const Harness,
        key: []const u8,
        environment: []const []const u8,
    ) !Result {
        return self.run(&.{"cleanup"}, key, environment);
    }

    fn run(
        self: *const Harness,
        arguments: []const []const u8,
        key: []const u8,
        environment: []const []const u8,
    ) !Result {
        const repository = try source.rootAlloc(std.testing.allocator);
        defer std.testing.allocator.free(repository);
        const script = try std.fs.path.join(
            std.testing.allocator,
            &.{ repository, script_path },
        );
        defer std.testing.allocator.free(script);

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(std.testing.allocator);
        try argv.append(std.testing.allocator, script);
        try argv.appendSlice(std.testing.allocator, arguments);

        const existing_path = std.process.Environ.getAlloc(
            std.testing.environ,
            std.testing.allocator,
            "PATH",
        ) catch try std.testing.allocator.dupe(u8, "/usr/bin:/bin");
        defer std.testing.allocator.free(existing_path);

        const path_variable = try std.fmt.allocPrint(
            std.testing.allocator,
            "PATH={s}/bin:{s}",
            .{ self.root, existing_path },
        );
        defer std.testing.allocator.free(path_variable);
        const state_variable = try std.fmt.allocPrint(
            std.testing.allocator,
            "STATE_FILE={s}/state",
            .{self.root},
        );
        defer std.testing.allocator.free(state_variable);
        const key_variable = try std.fmt.allocPrint(
            std.testing.allocator,
            "CANDIDATE_KEY={s}",
            .{key},
        );
        defer std.testing.allocator.free(key_variable);
        const tool = try source.releaseToolAlloc(std.testing.allocator);
        defer std.testing.allocator.free(tool);
        const tool_variable = try std.fmt.allocPrint(
            std.testing.allocator,
            "UBUNTU2604_RELEASE_TOOL={s}",
            .{tool},
        );
        defer std.testing.allocator.free(tool_variable);

        var environment_list: std.ArrayList([]const u8) = .empty;
        defer environment_list.deinit(std.testing.allocator);
        try environment_list.appendSlice(std.testing.allocator, &.{
            path_variable,
            state_variable,
            key_variable,
            tool_variable,
            "GITHUB_RUN_ID=123",
            "GITHUB_RUN_ATTEMPT=4",
        });
        try environment_list.appendSlice(std.testing.allocator, environment);
        return runProcess(
            std.testing.allocator,
            argv.items,
            environment_list.items,
        );
    }

    fn runLibrary(self: *const Harness, command: []const u8) !Result {
        _ = self;
        const repository = try source.rootAlloc(std.testing.allocator);
        defer std.testing.allocator.free(repository);
        const library = try std.fs.path.join(
            std.testing.allocator,
            &.{ repository, library_path },
        );
        defer std.testing.allocator.free(library);
        const script = try std.fmt.allocPrint(
            std.testing.allocator,
            "source \"$ACCEPTANCE_LIBRARY\"; {s}",
            .{command},
        );
        defer std.testing.allocator.free(script);
        const variable = try std.fmt.allocPrint(
            std.testing.allocator,
            "ACCEPTANCE_LIBRARY={s}",
            .{library},
        );
        defer std.testing.allocator.free(variable);
        return runProcess(
            std.testing.allocator,
            &.{ "bash", "-c", script },
            &.{variable},
        );
    }
};
