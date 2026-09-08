//! Structural guards for the protected full ConfidentialVM capture workflow.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const workflow_path =
    ".github/workflows/ubuntu2404-confidential-capture.yml";
const harness_path = "scripts/ubuntu2404_confidential_capture.sh";
const github_policy_path =
    "scripts/ubuntu2404_confidential_github_policy.sh";
const provenance_tag_path =
    "scripts/ubuntu2404_confidential_provenance_tag.sh";
const publish_release_path =
    "scripts/ubuntu2404_confidential_publish_release.sh";
const guide_path = "doc/azure-confidential-vm.md";
const max_source_bytes = 4 * 1024 * 1024;
const max_output_bytes = 1024 * 1024;

fn rootAlloc(allocator: Allocator) ![]u8 {
    return std.testing.environ.getAlloc(
        allocator,
        "MIZ_UBUNTU2404_CONFIDENTIAL_ROOT",
    ) catch |err| switch (err) {
        error.EnvironmentVariableMissing => allocator.dupe(u8, "."),
        else => return err,
    };
}

fn readTracked(allocator: Allocator, relative: []const u8) ![]u8 {
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    return Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        allocator,
        .limited(max_source_bytes),
    );
}

fn expectContains(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) != null) return;
    std.debug.print("missing required text:\n{s}\n", .{needle});
    return error.RequiredTextMissing;
}

fn expectAbsent(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) == null) return;
    std.debug.print("forbidden text is present:\n{s}\n", .{needle});
    return error.ForbiddenTextPresent;
}

fn expectCount(text: []const u8, needle: []const u8, expected: usize) !void {
    const actual = std.mem.count(u8, text, needle);
    if (actual == expected) return;
    std.debug.print(
        "expected {d} occurrence(s) of \"{s}\", found {d}\n",
        .{ expected, needle, actual },
    );
    return error.UnexpectedOccurrenceCount;
}

fn indexOf(text: []const u8, needle: []const u8) !usize {
    return std.mem.indexOf(u8, text, needle) orelse
        error.RequiredTextMissing;
}

fn runShellFixture(
    allocator: Allocator,
    name: []const u8,
    source: []const u8,
) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const repository = try rootAlloc(allocator);
    defer allocator.free(repository);
    const root = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}",
        .{ repository, tmp.sub_path },
    );
    defer allocator.free(root);
    const path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ root, name },
    );
    defer allocator.free(path);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = path,
        .data = source,
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ "bash", path },
        .cwd = .{ .path = root },
        .stdout_limit = .limited(max_output_bytes),
        .stderr_limit = .limited(max_output_bytes),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| {
            if (code == 0) return;
            std.debug.print("fixture failed:\n{s}\n{s}\n", .{
                result.stdout,
                result.stderr,
            });
            return error.ShellFixtureFailed;
        },
        else => return error.ShellFixtureFailed,
    }
}

fn section(text: []const u8, start: []const u8, end: ?[]const u8) ![]const u8 {
    const start_index = try indexOf(text, start);
    const tail = text[start_index + start.len ..];
    const marker = end orelse return tail;
    const end_index = std.mem.indexOf(u8, tail, marker) orelse
        return error.RequiredTextMissing;
    return tail[0..end_index];
}

fn isHexSha(text: []const u8) bool {
    if (text.len != 40) return false;
    for (text) |character| switch (character) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

test "capture workflow is dispatch-only guarded and fully pinned" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);

    try expectCount(workflow, "workflow_dispatch:", 1);
    try expectAbsent(workflow, "\n  push:");
    try expectAbsent(workflow, "\n  pull_request:");
    try expectContains(
        workflow,
        "if: github.repository == 'cataggar/miz' && github.ref == 'refs/heads/main'",
    );
    try expectContains(
        workflow,
        "group: ubuntu2404-confidential-cvm-target-version\n  cancel-in-progress: false",
    );
    try expectCount(
        workflow,
        "environment: ubuntu2404-confidential-capture",
        3,
    );
    try expectCount(workflow, "id-token: write", 1);
    try expectAbsent(workflow, "uses: actions/checkout@v");
    try expectAbsent(workflow, "uses: azure/login@v");
    try expectCount(workflow, "ref: ${{ github.sha }}", 1);
    try expectCount(
        workflow,
        "ref: ${{ needs.prepare.outputs.workflow_commit }}",
        2,
    );
    try expectAbsent(
        workflow,
        "ref: ${{ needs.prepare.outputs.tool_commit }}",
    );
    try expectAbsent(workflow, "\n          ref: main\n");
    try expectCount(
        workflow,
        "test \"$(git rev-parse HEAD)\" = \"$GITHUB_SHA\"",
        5,
    );
    try expectCount(
        workflow,
        "git ls-remote origin refs/heads/main",
        4,
    );
    try expectContains(
        workflow,
        "main advanced after dispatch approval; redispatch the workflow",
    );
    try expectContains(
        workflow,
        "main advanced before Azure mutation; redispatch the workflow",
    );

    var lines = std.mem.splitScalar(u8, workflow, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, "uses: ")) continue;
        const at = std.mem.lastIndexOfScalar(u8, trimmed, '@') orelse
            return error.UnpinnedAction;
        const suffix = trimmed[at + 1 ..];
        const sha = suffix[0 .. std.mem.indexOfScalar(u8, suffix, ' ') orelse suffix.len];
        try std.testing.expect(isHexSha(sha));
    }
}

test "approved dispatch checkout stays fixed and rejects moved main" {
    try runShellFixture(std.testing.allocator, "dispatch-head-fixture.sh",
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\git init --bare --initial-branch=main remote.git >/dev/null
        \\git clone remote.git work >/dev/null 2>&1
        \\cd work
        \\git config user.name fixture
        \\git config user.email fixture@example.invalid
        \\echo approved >workflow
        \\git add workflow
        \\git commit -m approved >/dev/null
        \\git push origin HEAD:main >/dev/null 2>&1
        \\dispatch_sha=$(git rev-parse HEAD)
        \\git checkout --detach "$dispatch_sha" >/dev/null 2>&1
        \\test "$(git rev-parse HEAD)" = "$dispatch_sha"
        \\test "$(git ls-remote origin refs/heads/main | awk '{print $1}')" = "$dispatch_sha"
        \\git switch main >/dev/null 2>&1
        \\echo advanced >>workflow
        \\git commit -am advanced >/dev/null
        \\git push origin HEAD:main >/dev/null 2>&1
        \\advanced_sha=$(git rev-parse HEAD)
        \\test "$advanced_sha" != "$dispatch_sha"
        \\git checkout --detach "$dispatch_sha" >/dev/null 2>&1
        \\test "$(git rev-parse HEAD)" = "$dispatch_sha"
        \\remote_main=$(git ls-remote origin refs/heads/main | awk '{print $1}')
        \\test "$remote_main" = "$advanced_sha"
        \\if [[ "$remote_main" == "$dispatch_sha" ]]; then
        \\  exit 90
        \\fi
        \\
    );
}

test "policy and publication GitHub App tokens stay separated" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const prepare = try section(workflow, "\n  prepare:\n", "\n  capture:\n");
    const capture = try section(
        workflow,
        "\n  capture:\n",
        "\n  publish_provenance:\n",
    );
    const publication = try section(
        workflow,
        "\n  publish_provenance:\n",
        null,
    );

    try expectCount(
        workflow,
        "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349",
        4,
    );
    try expectCount(workflow, "secrets.CAPTURE_GITHUB_APP_ID", 7);
    try expectCount(workflow, "secrets.CAPTURE_GITHUB_APP_PRIVATE_KEY", 4);
    try expectAbsent(workflow, "permission-administration: read");
    try expectCount(workflow, "permission-administration: write", 3);
    try expectCount(workflow, "permission-actions: read", 3);
    try expectCount(workflow, "permission-contents: read", 3);
    try expectCount(workflow, "permission-contents: write", 1);
    try expectCount(workflow, "permission-workflows: write", 1);
    try expectAbsent(workflow, "\n      contents: write\n");

    for ([_][]const u8{ prepare, capture }) |job| {
        const token = try indexOf(job, "id: github_policy_token");
        const immutable = try indexOf(
            job,
            "repos/$GITHUB_REPOSITORY/immutable-releases",
        );
        try std.testing.expect(token < immutable);
        try expectContains(
            job,
            "GH_TOKEN: ${{ steps.github_policy_token.outputs.token }}",
        );
    }
    try expectContains(
        prepare,
        "environment: ubuntu2404-confidential-capture",
    );
    const policy_token = try section(
        publication,
        "- name: Mint protected provenance policy token",
        "- name: Mint isolated provenance publication token",
    );
    const publication_token = try section(
        publication,
        "- name: Mint isolated provenance publication token",
        "- name: Check out exact approved publication verifier",
    );
    try expectContains(policy_token, "permission-administration: write");
    try expectContains(policy_token, "permission-actions: read");
    try expectContains(policy_token, "permission-contents: read");
    try expectAbsent(policy_token, "permission-contents: write");
    try expectAbsent(policy_token, "permission-workflows: write");
    try expectContains(publication_token, "permission-contents: write");
    try expectContains(publication_token, "permission-workflows: write");
    try expectAbsent(publication_token, "permission-administration:");
    try expectAbsent(publication_token, "permission-actions:");
    try expectContains(
        publication,
        "POLICY_GH_TOKEN: ${{ steps.github_policy_token.outputs.token }}",
    );
    try expectContains(
        publication,
        "PUBLICATION_GH_TOKEN: ${{ steps.github_publication_token.outputs.token }}",
    );
    try expectContains(
        publication,
        "github-token: ${{ steps.github_policy_token.outputs.token }}",
    );
    try expectCount(publication, "GH_TOKEN=\"$POLICY_GH_TOKEN\"", 12);
    try expectCount(publication, "GH_TOKEN=\"$PUBLICATION_GH_TOKEN\"", 8);
    try expectAbsent(prepare, "gh api --method POST");
    try expectAbsent(prepare, "gh api --method PATCH");
    try expectAbsent(capture, "gh api --method POST");
    try expectAbsent(capture, "gh api --method PATCH");
    try expectAbsent(publication, "GH_TOKEN=\"$POLICY_GH_TOKEN\" gh api --method");
}

test "repository writer boundary and ruleset policy fail closed" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const policy = try readTracked(allocator, github_policy_path);
    defer allocator.free(policy);

    try expectCount(
        workflow,
        "scripts/ubuntu2404_confidential_github_policy.sh",
        7,
    );
    for ([_][]const u8{
        "repos/$GITHUB_REPOSITORY",
        ".full_name == $repository",
        ".login == $owner and .type == \"User\"",
        "((.organization? // null) == null)",
        "collaborators?affiliation=all&per_page=100",
        ".permissions.push or .permissions.maintain or .permissions.admin",
        "CAPTURE_RELEASE_WRITER_POLICY",
        "owner-and-publisher-app-only-v1",
        "protected release-writer policy acknowledgement is absent or wrong",
        "actions/permissions/workflow",
        ".default_workflow_permissions == \"read\"",
        ".can_approve_pull_request_reviews == false",
        "rulesets?includes_parents=true&targets=tag&per_page=100",
        "rulesets/$ruleset_id?includes_parents=true",
        ".target == \"tag\"",
        ".source_type == \"Repository\"",
        ".source == $repository",
        ".enforcement == \"active\"",
        "actor_id: $app_id",
        "actor_type: \"Integration\"",
        "bypass_mode: \"always\"",
        ".include == [$pattern]",
        ".exclude == []",
        "[\"creation\", \"deletion\", \"update\"]",
        "all(.[]; (keys | sort) == [\"type\"])",
    }) |needle| try expectContains(policy, needle);
    try expectAbsent(policy, "installation-id");
    try expectAbsent(workflow, "installation-id");
    try expectAbsent(policy, "OrganizationAdmin");
    try expectAbsent(policy, "RepositoryRole");
    try expectAbsent(
        policy,
        "repos/$GITHUB_REPOSITORY/installations",
    );
    try expectAbsent(
        workflow,
        "repos/$GITHUB_REPOSITORY/installations",
    );
    try expectCount(
        workflow,
        "CAPTURE_RELEASE_WRITER_POLICY: ${{ vars.CAPTURE_RELEASE_WRITER_POLICY }}",
        3,
    );

    try runShellFixture(allocator, "github-policy-fixture.sh",
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\mkdir bin
        \\cat >bin/gh <<'GH'
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\endpoint=
        \\for argument in "$@"; do
        \\  [[ "$argument" == repos/* ]] && endpoint=$argument
        \\done
        \\printf '%s\n' "$endpoint" >>"$GH_LOG"
        \\if [[ "$endpoint" == repos/cataggar/miz ]]; then
        \\  owner_type=User
        \\  owner_login=cataggar
        \\  organization=null
        \\  [[ "${GH_MODE:-valid}" == org-repository ]] && {
        \\    owner_type=Organization
        \\    organization='{"login":"cataggar"}'
        \\  }
        \\  [[ "${GH_MODE:-valid}" == wrong-owner ]] && owner_login=other
        \\  jq -n \
        \\    --arg owner_type "$owner_type" \
        \\    --arg owner_login "$owner_login" \
        \\    --argjson organization "$organization" \
        \\    '{full_name:"cataggar/miz",
        \\      owner:{login:$owner_login,type:$owner_type},
        \\      organization:$organization}'
        \\  exit
        \\fi
        \\if [[ "$endpoint" == *'/collaborators?'* ]]; then
        \\  owner='{"login":"cataggar","permissions":{"pull":true,"push":true,"maintain":true,"admin":true}}'
        \\  case "${GH_MODE:-valid}" in
        \\    extra-writer)
        \\      printf '%s\n' "[[$owner,{\"login\":\"other\",\"permissions\":{\"pull\":true,\"push\":true,\"maintain\":false,\"admin\":false}}]]"
        \\      ;;
        \\    missing-collaborator-permissions)
        \\      printf '%s\n' '[[{"login":"cataggar"}]]'
        \\      ;;
        \\    *)
        \\      printf '%s\n' "[[$owner]]"
        \\      ;;
        \\  esac
        \\  exit
        \\fi
        \\if [[ "$endpoint" == *'/actions/permissions/workflow' ]]; then
        \\  if [[ "${GH_MODE:-valid}" == unsafe-workflow-default ]]; then
        \\    printf '%s\n' '{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}'
        \\  else
        \\    printf '%s\n' '{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}'
        \\  fi
        \\  exit
        \\fi
        \\if [[ "$endpoint" == *'/rulesets?'* ]]; then
        \\  case "${GH_MODE:-valid}" in
        \\    missing) printf '%s\n' '[[]]' ;;
        \\    ambiguous) printf '%s\n' '[[{"id":42,"name":"ubuntu2404-confidential-provenance-tags"},{"id":43,"name":"other-tag-ruleset"}]]' ;;
        \\    *) printf '%s\n' '[[{"id":42,"name":"ubuntu2404-confidential-provenance-tags"}]]' ;;
        \\  esac
        \\  exit
        \\fi
        \\source_type=Repository
        \\enforcement=active
        \\bypass='[{"actor_id":1234,"actor_type":"Integration","bypass_mode":"always"}]'
        \\conditions='{"ref_name":{"include":["refs/tags/miz-provenance/ubuntu2404-confidential-cvm/*/*/*"],"exclude":[]}}'
        \\rules='[{"type":"creation"},{"type":"update"},{"type":"deletion"}]'
        \\case "${GH_MODE:-valid}" in
        \\  parent) source_type=Organization ;;
        \\  inactive) enforcement=evaluate ;;
        \\  wrong-app) bypass='[{"actor_id":9876,"actor_type":"Integration","bypass_mode":"always"}]' ;;
        \\  extra-bypass) bypass='[{"actor_id":1234,"actor_type":"Integration","bypass_mode":"always"},{"actor_id":6,"actor_type":"User","bypass_mode":"always"}]' ;;
        \\  missing-bypass) bypass=missing ;;
        \\  extra-condition) conditions='{"ref_name":{"include":["refs/tags/miz-provenance/ubuntu2404-confidential-cvm/*/*/*"],"exclude":[]},"repository_name":{"include":["miz"],"exclude":[]}}' ;;
        \\  missing-rule) rules='[{"type":"creation"},{"type":"update"}]' ;;
        \\esac
        \\if [[ "$bypass" == missing ]]; then
        \\  jq -n \
        \\    --arg source_type "$source_type" \
        \\    --arg enforcement "$enforcement" \
        \\    --argjson conditions "$conditions" \
        \\    --argjson rules "$rules" \
        \\    '{id:42,name:"ubuntu2404-confidential-provenance-tags",target:"tag",
        \\      source_type:$source_type,source:"cataggar/miz",enforcement:$enforcement,
        \\      conditions:$conditions,rules:$rules}'
        \\else
        \\  jq -n \
        \\    --arg source_type "$source_type" \
        \\    --arg enforcement "$enforcement" \
        \\    --argjson bypass "$bypass" \
        \\    --argjson conditions "$conditions" \
        \\    --argjson rules "$rules" \
        \\    '{id:42,name:"ubuntu2404-confidential-provenance-tags",target:"tag",
        \\      source_type:$source_type,source:"cataggar/miz",enforcement:$enforcement,
        \\      bypass_actors:$bypass,conditions:$conditions,rules:$rules}'
        \\fi
        \\GH
        \\chmod +x bin/gh
        \\export PATH="$PWD/bin:$PATH"
        \\export GH_LOG="$PWD/gh.log"
        \\export GH_TOKEN=fixture
        \\export GITHUB_REPOSITORY=cataggar/miz
        \\export GITHUB_REPOSITORY_OWNER=cataggar
        \\export GH_API_VERSION=2026-03-10
        \\export EXPECTED_PUBLISHER_APP_ID=1234
        \\export PROVENANCE_RULESET_NAME=ubuntu2404-confidential-provenance-tags
        \\export PROVENANCE_TAG_PATTERN='refs/tags/miz-provenance/ubuntu2404-confidential-cvm/*/*/*'
        \\export CAPTURE_RELEASE_WRITER_POLICY=owner-and-publisher-app-only-v1
        \\policy="$MIZ_UBUNTU2404_CONFIDENTIAL_ROOT/scripts/ubuntu2404_confidential_github_policy.sh"
        \\GH_MODE=valid "$policy" valid
        \\grep -F 'repos/cataggar/miz/collaborators?affiliation=all&per_page=100' gh.log >/dev/null
        \\if grep -F 'repos/cataggar/miz/installations' gh.log >/dev/null; then
        \\  exit 90
        \\fi
        \\grep -F 'repos/cataggar/miz/actions/permissions/workflow' gh.log >/dev/null
        \\grep -F 'repos/cataggar/miz/rulesets?includes_parents=true&targets=tag&per_page=100' gh.log >/dev/null
        \\grep -F 'repos/cataggar/miz/rulesets/42?includes_parents=true' gh.log >/dev/null
        \\if env -u CAPTURE_RELEASE_WRITER_POLICY \
        \\    GH_MODE=valid "$policy" missing-acknowledgement >/dev/null 2>&1; then
        \\  exit 91
        \\fi
        \\if CAPTURE_RELEASE_WRITER_POLICY=wrong \
        \\    GH_MODE=valid "$policy" wrong-acknowledgement >/dev/null 2>&1; then
        \\  exit 92
        \\fi
        \\for mode in \
        \\  org-repository wrong-owner extra-writer \
        \\  missing-collaborator-permissions \
        \\  unsafe-workflow-default missing ambiguous parent inactive \
        \\  wrong-app extra-bypass missing-bypass extra-condition missing-rule
        \\do
        \\  if GH_MODE=$mode "$policy" "$mode" >/dev/null 2>&1; then
        \\    exit 90
        \\  fi
        \\done
        \\
    );
}

test "ruleset path pattern matches generated tags with FNM_PATHNAME" {
    try runShellFixture(std.testing.allocator, "ruleset-pattern-fixture.sh",
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\pattern='refs/tags/miz-provenance/ubuntu2404-confidential-cvm/*/*/*'
        \\old_pattern='refs/tags/miz-provenance/ubuntu2404-confidential-cvm/**'
        \\tag='refs/tags/miz-provenance/ubuntu2404-confidential-cvm/v1.2.3/origin-123-attempt-4/tool-0123456789abcdef0123456789abcdef01234567'
        \\ruby_command=$(command -v ruby || command -v ruby-mri)
        \\"$ruby_command" -e '
        \\  pattern, old_pattern, tag = ARGV
        \\  flags = File::FNM_PATHNAME
        \\  abort "new pattern did not match" unless File.fnmatch?(pattern, tag, flags)
        \\  abort "old pattern unexpectedly matched" if File.fnmatch?(old_pattern, tag, flags)
        \\' "$pattern" "$old_pattern" "$tag"
        \\
    );
}

test "provenance tag verifier enforces absence then exact lightweight ref" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const tag_policy = try readTracked(allocator, provenance_tag_path);
    defer allocator.free(tag_policy);

    for ([_][]const u8{
        "git/matching-refs/tags/$tag_name",
        "([.[] | select(.ref == $ref)] | length) == 0",
        "git/ref/tags/$tag_name",
        ".object.type == \"commit\"",
        ".object.sha == $commit",
    }) |needle| try expectContains(tag_policy, needle);
    try expectCount(workflow, "require-absent \"$PROVENANCE_RELEASE_TAG\"", 3);
    try expectCount(workflow, "require-lightweight \"$PROVENANCE_RELEASE_TAG\"", 1);

    try runShellFixture(allocator, "provenance-tag-fixture.sh",
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\mkdir bin
        \\cat >bin/gh <<'GH'
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\endpoint=
        \\for argument in "$@"; do
        \\  [[ "$argument" == repos/* ]] && endpoint=$argument
        \\done
        \\printf '%s\n' "$endpoint" >>"$GH_LOG"
        \\ref='refs/tags/miz-provenance/ubuntu2404-confidential-cvm/v1.2.3/origin-123-attempt-4/tool-0123456789abcdef0123456789abcdef01234567'
        \\commit=0123456789abcdef0123456789abcdef01234567
        \\if [[ "$endpoint" == *'/matching-refs/'* ]]; then
        \\  if [[ "${GH_MODE:-absent}" == exists ]]; then
        \\    jq -n --arg ref "$ref" --arg commit "$commit" \
        \\      '[{ref:$ref,object:{type:"commit",sha:$commit}}]'
        \\  else
        \\    printf '%s\n' '[]'
        \\  fi
        \\else
        \\  object_type=commit
        \\  object_commit=$commit
        \\  [[ "${GH_MODE:-exact}" == annotated ]] && object_type=tag
        \\  [[ "${GH_MODE:-exact}" == wrong-commit ]] && object_commit=ffffffffffffffffffffffffffffffffffffffff
        \\  jq -n --arg ref "$ref" --arg type "$object_type" --arg commit "$object_commit" \
        \\    '{ref:$ref,object:{type:$type,sha:$commit}}'
        \\fi
        \\GH
        \\chmod +x bin/gh
        \\export PATH="$PWD/bin:$PATH"
        \\export GH_LOG="$PWD/gh.log"
        \\export GH_TOKEN=fixture
        \\export GITHUB_REPOSITORY=cataggar/miz
        \\export GH_API_VERSION=2026-03-10
        \\tag='miz-provenance/ubuntu2404-confidential-cvm/v1.2.3/origin-123-attempt-4/tool-0123456789abcdef0123456789abcdef01234567'
        \\commit=0123456789abcdef0123456789abcdef01234567
        \\policy="$MIZ_UBUNTU2404_CONFIDENTIAL_ROOT/scripts/ubuntu2404_confidential_provenance_tag.sh"
        \\GH_MODE=absent "$policy" require-absent "$tag" "$commit" absent
        \\if GH_MODE=exists "$policy" require-absent "$tag" "$commit" exists >/dev/null 2>&1; then
        \\  exit 90
        \\fi
        \\GH_MODE=exact "$policy" require-lightweight "$tag" "$commit" exact
        \\if GH_MODE=annotated "$policy" require-lightweight "$tag" "$commit" annotated >/dev/null 2>&1; then
        \\  exit 91
        \\fi
        \\if GH_MODE=wrong-commit "$policy" require-lightweight "$tag" "$commit" wrong >/dev/null 2>&1; then
        \\  exit 92
        \\fi
        \\grep -F 'git/matching-refs/tags/' gh.log >/dev/null
        \\grep -F 'git/ref/tags/' gh.log >/dev/null
        \\
    );
}

test "immutable source release and provenance identities fail closed" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const prepare = try section(workflow, "\n  prepare:\n", "\n  capture:\n");
    try expectContains(workflow, "source_release_tag:");
    try expectContains(workflow, "target_gallery_version:");

    for ([_][]const u8{
        "^Ubuntu-24\\.04-confidential-[0-9]{8}$",
        "TARGET_GALLERY_VERSION\" =~ ^(0|[1-9][0-9]{0,9})",
        "target_major != 0 || 10#$target_minor != 0 || 10#$target_patch != 0",
        "repos/$GITHUB_REPOSITORY/immutable-releases",
        "X-GitHub-Api-Version: $GH_API_VERSION",
        "jq -e '.enabled == true'",
        ".immutable == true",
        "REQUESTED_ORIGIN_RUN_ID",
        "REQUESTED_ORIGIN_RUN_ATTEMPT",
        "recovery_mode=true",
        "origin_run_id=$GITHUB_RUN_ID",
        "origin_run_attempt=$GITHUB_RUN_ATTEMPT",
        "actions/runs/$origin_run_id/attempts/$origin_run_attempt",
        ".repository.full_name == env.GITHUB_REPOSITORY",
        ".head_sha | test(\"^[0-9a-f]{40}$\")",
        "test \"$origin_head_sha\" = \"$tool_commit\"",
        "actions/runs/$origin_run_id/artifacts?name=$recovery_artifact_name",
        "test \"sha256:$(sha256sum .capture/prepare/recovery.zip",
        ".schema == 5 and .stage == \"prepared\"",
        "refs/tags/$SOURCE_RELEASE_TAG^{}",
        "workflow_commit=$(git rev-parse HEAD)",
        "test \"$workflow_commit\" = \"$GITHUB_SHA\"",
        "tool_commit=$workflow_commit",
        "git fetch --no-tags --depth=1 origin \"$tool_commit\"",
        "provenance_release_tag=\"miz-provenance/ubuntu2404-confidential-cvm/v$TARGET_GALLERY_VERSION/origin-$origin_run_id-attempt-$origin_run_attempt/tool-$tool_commit\"",
        "ubuntu2404_confidential_provenance_tag.sh",
        "require-absent \"$provenance_release_tag\" \"$tool_commit\"",
        ".draft == false",
        ".prerelease == false",
        "(.assets | type == \"array\" and length == 3)",
        "repos/$GITHUB_REPOSITORY/releases?per_page=100",
        "[.[][] | select(.tag_name == $tag)] | length == 0",
        "Provenance release already exists; use explicit recovery inputs",
    }) |needle| try expectContains(prepare, needle);
    try expectAbsent(
        prepare,
        "actions/runs/$origin_run_id\"",
    );
    try expectAbsent(prepare, "direct_provenance=");
    try expectAbsent(prepare, "peeled_provenance=");
}

test "source acquisition is exact and validated before Azure" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const capture_job = try section(
        workflow,
        "\n  capture:\n",
        "\n  publish_provenance:\n",
    );

    for ([_][]const u8{
        "repos/$GITHUB_REPOSITORY/immutable-releases",
        ".immutable == true",
        "Ubuntu-24.04-x86_64.confidential.qcow2",
        "Ubuntu-24.04-x86_64.confidential.qcow2.provenance.json",
        "Ubuntu-24.04-x86_64.confidential.azure-acceptance.json",
        "releases/assets/$SOURCE_QCOW_ASSET_ID",
        "releases/assets/$SOURCE_PROVENANCE_ASSET_ID",
        "releases/assets/$SOURCE_ACCEPTANCE_ASSET_ID",
        "test \"$(find \"$CANDIDATE_DIR\" -maxdepth 1 -type f | wc -l)\" -eq 3",
        "\"$RELEASE_TOOL\" verify-build",
        "\"$RELEASE_TOOL\" verify-acceptance",
        "source_group\" =~ ^miz-u2404-cvm-",
    }) |needle| try expectContains(capture_job, needle);
    try expectAbsent(capture_job, "gh release download");
    try expectAbsent(capture_job, "path: ${{ env.RESULT_DIR }}\n");

    const validate_source = try indexOf(
        capture_job,
        "- name: Validate source shape hashes and protected source identity",
    );
    const immutable_source = try indexOf(
        capture_job,
        "- name: Download exactly the accepted three-asset source release",
    );
    const first_login = try indexOf(
        capture_job,
        "- name: Log in capture principal with protected-environment OIDC",
    );
    const github_preflight = try indexOf(
        capture_job,
        "- name: Revalidate dispatch head and tag policy before Azure",
    );
    try std.testing.expect(immutable_source < first_login);
    try std.testing.expect(validate_source < first_login);
    try std.testing.expect(github_preflight < first_login);
}

test "dual OIDC contexts and staged freshness ordering are fixed" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const harness = try readTracked(allocator, harness_path);
    defer allocator.free(harness);
    const capture_job = try section(
        workflow,
        "\n  capture:\n",
        "\n  publish_provenance:\n",
    );

    for ([_][]const u8{
        "AZURE_CONFIG_DIR: ${{ github.workspace }}/.capture/azure/capture",
        "PUBLICATION_AZURE_CONFIG_DIR: ${{ github.workspace }}/.capture/azure/publication",
        "secrets.AZURE_CAPTURE_CLIENT_ID",
        "secrets.AZURE_PUBLICATION_CLIENT_ID",
        "scripts/ubuntu2404_confidential_capture.sh prepare",
        "scripts/ubuntu2404_confidential_capture.sh adopt-recovery",
        "scripts/ubuntu2404_confidential_capture.sh inspect-recovery",
        "scripts/ubuntu2404_confidential_capture.sh export-recovery",
        "scripts/ubuntu2404_confidential_capture.sh mark-recovery-durable",
        "scripts/ubuntu2404_confidential_capture.sh export-dispatch",
        "scripts/ubuntu2404_confidential_capture.sh mark-dispatch-durable",
        "scripts/ubuntu2404_confidential_capture.sh publish",
        "scripts/ubuntu2404_confidential_capture.sh recover",
        "scripts/ubuntu2404_confidential_capture.sh finalize",
        "- name: Refresh capture OIDC for unconditional exact cleanup",
        "if: always() && steps.result_discovery.outputs.result_artifact_id == ''",
        "steps.cleanup_login.outcome == 'success'",
        "Fresh cleanup login failed; retaining quarantined scratch state",
        "scripts/ubuntu2404_confidential_capture.sh cleanup",
    }) |needle| try expectContains(capture_job, needle);
    try expectContains(harness, "require_capture_account");
    try expectContains(harness, "require_publication_account");
    try expectContains(harness, "tenantId");
    try expectContains(harness, "Capture and publication principals must be distinct");

    const prepare = try indexOf(capture_job, "capture.sh prepare");
    const publisher_login = try indexOf(
        capture_job,
        "Log in exclusive publication principal after durable recovery",
    );
    const capture_refresh = try indexOf(
        capture_job,
        "Refresh capture OIDC before recovery or publication validation",
    );
    const recovery_upload = try indexOf(
        capture_job,
        "Upload only sanitized recovery intent and state",
    );
    const recovery_adoption = try indexOf(
        capture_job,
        "Adopt durable recovery dispatch into quarantined local state",
    );
    const result_discovery = try indexOf(
        capture_job,
        "Discover and validate one exact durable result across physical runs",
    );
    const dispatch_upload = try indexOf(
        capture_job,
        "Upload durable PUT dispatch marker before mutation",
    );
    const publish = try indexOf(
        capture_job,
        "Publish once or resume the exact existing version",
    );
    const cleanup_refresh = try indexOf(
        capture_job,
        "Refresh capture OIDC for unconditional exact cleanup",
    );
    const cleanup = try indexOf(capture_job, "capture.sh cleanup");
    try std.testing.expect(prepare < publisher_login);
    try std.testing.expect(prepare < recovery_upload);
    try std.testing.expect(recovery_upload < publisher_login);
    try std.testing.expect(recovery_adoption < result_discovery);
    try std.testing.expect(recovery_adoption < publisher_login);
    try std.testing.expect(publisher_login < capture_refresh);
    try std.testing.expect(capture_refresh < dispatch_upload);
    try std.testing.expect(dispatch_upload < publish);
    try std.testing.expect(publish < cleanup_refresh);
    try std.testing.expect(cleanup_refresh < cleanup);
}

test "publication boundary uploads one sanitized result and never deletes target" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const harness = try readTracked(allocator, harness_path);
    defer allocator.free(harness);
    const publication = try section(
        workflow,
        "\n  publish_provenance:\n",
        null,
    );

    try expectCount(workflow, "include-hidden-files: true", 3);
    for ([_][]const u8{
        "path: ${{ env.RESULT_DIR }}/capture-result.json",
        "retention-days: 90",
        "name: ${{ env.RECOVERY_ARTIFACT_NAME }}",
        "name: ${{ env.DISPATCH_ARTIFACT_NAME }}",
        "name: ${{ env.RESULT_ARTIFACT_NAME }}",
        "verify-capture-publication",
        "--expected-result-sha256 \"$EXPECTED_RESULT_SHA256\"",
        "(.assets | length == 1)",
        ".draft == true",
        ".immutable == true",
        ".target_commitish == $tool_commit",
        ".assets[0].digest == $digest",
        ".body == $notes",
        ".assets | length == 0 or length == 1",
        "release_count=$(jq -er 'length' \"$exact_releases_json\")",
        "(( release_count <= 1 ))",
        "gh api --method POST \"${api_headers[@]}\"",
        "repos/$GITHUB_REPOSITORY/releases/$release_id",
        "uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets",
        "github-policy-before-draft-discovery",
        "github-policy-before-create",
        "github-policy-before-upload",
        "github-policy-before-publish",
        "immutable-releases-before-publish.json",
        "tag-before-publish",
        "require-lightweight \"$PROVENANCE_RELEASE_TAG\" \"$TOOL_COMMIT\"",
        "origin-run-id: $ORIGIN_RUN_ID",
        "recovery-intent-sha256: $RECOVERY_INTENT_SHA256",
        "ubuntu2404_confidential_publish_release.sh",
        "publish-release.json",
        ".assets[0].digest == $digest",
    }) |needle| try expectContains(workflow, needle);
    try expectAbsent(publication, "gh release create");
    try expectAbsent(publication, "gh release upload");
    try expectAbsent(publication, "gh release edit");
    try expectAbsent(workflow, "attestation.jwt");
    try expectAbsent(workflow, "openid-configuration.json");
    try expectAbsent(workflow, "jwks.json");
    try expectAbsent(workflow, "id_ed25519");
    try expectAbsent(workflow, "retention-days: 7");
    try expectAbsent(publication, "azure/login@");
    try expectAbsent(harness, "sig image-version delete");
    try expectAbsent(harness, "sig image-definition delete");
    try expectAbsent(harness, "delete_created_version");
    try expectAbsent(harness, "delete_created_definition");
    try expectCount(
        harness,
        "publication_az \"${AZURE_CONFIDENTIAL_VM_ARGS[@]}\" \\\n      >\"$target_response\"",
        2,
    );
}

test "durable recovery preserves origin and gates PUT cleanup and publication" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const harness = try readTracked(allocator, harness_path);
    defer allocator.free(harness);

    for ([_][]const u8{
        "origin_run_id:",
        "origin_run_attempt:",
        "WORKFLOW_COMMIT: ${{ needs.prepare.outputs.workflow_commit }}",
        "ref: ${{ needs.prepare.outputs.workflow_commit }}",
        "test \"$GITHUB_SHA\" = \"$WORKFLOW_COMMIT\"",
        "test \"$origin_head_sha\" = \"$tool_commit\"",
        "recovery_artifact_name=\"ubuntu2404-confidential-capture-recovery-$origin_run_id-$origin_run_attempt-$TARGET_GALLERY_VERSION\"",
        "dispatch_artifact_name=\"ubuntu2404-confidential-capture-dispatch-$origin_run_id-$origin_run_attempt-$TARGET_GALLERY_VERSION\"",
        "result_artifact_name=\"ubuntu2404-confidential-capture-result-$origin_run_id-$origin_run_attempt-$TARGET_GALLERY_VERSION\"",
        "actions/runs/$origin_run_id/artifacts?name=$recovery_artifact_name",
        "actions/artifacts?name=$dispatch_artifact_name",
        "ORIGIN_DISPATCH_ARTIFACT_DIGEST",
        "actions/artifacts?name=$RESULT_ARTIFACT_NAME&per_page=100",
        ".workflow_run.id",
        "actions/runs/$physical_run_id",
        "Multiple exact durable result artifacts exist across physical runs",
        "selected_run_id=$physical_run_id",
        "result_artifact_run_id=$DISCOVERED_RESULT_RUN_ID",
        "result_artifact_run_id=$GITHUB_RUN_ID",
        "expired == false",
        "artifact-digest",
        "retention-days: 90",
        "steps.inspect.outputs.recovery_action == 'publish'",
        "steps.inspect.outputs.recovery_action",
        "needs.capture.outputs.capture_result_sha256 != ''",
        "needs.capture.outputs.result_uploaded == 'true'",
        "Reuse only an exact already durable protected result",
        "RESULT_ARTIFACT_RUN_ID",
        "run-id: ${{ env.RESULT_ARTIFACT_RUN_ID }}",
        "always() &&",
        "steps.finalize.outcome == 'success'",
        "steps.cleanup.outcome == 'success'",
    }) |needle| try expectContains(workflow, needle);

    for ([_][]const u8{
        ".origin_run_id == $origin_run_id",
        ".origin_run_attempt == $origin_run_attempt",
        ".target.publication.status = \"put_dispatched\"",
        ".target.publication.status = \"quarantined\"",
        "mark_dispatch_durable quarantined",
        "Target is absent after a durable PUT dispatch marker; refusing an ambiguous second PUT",
        "azure_confidential_vm_capture_gallery_version_get_args \"$target_version_id\"",
        "validate_existing_target_version",
        "MIZ_CAPTURE_TARGET=resumed-existing",
        "retaining post-dispatch scratch resources for recovery",
        "Capture result is not durably uploaded; retaining post-PUT scratch resources for recovery",
        ".result.status = \"ready\"",
        ".result.status = \"durable\"",
        "Sanitized recovery artifact contains a forbidden sensitive field",
    }) |needle| try expectContains(harness, needle);

    const recover_branch = try section(
        harness,
        "if [[ \"$command_name\" == recover ]]; then\n  publication_status=",
        "\nelse\n  require_target_version_absent pre-put",
    );
    try expectContains(recover_branch, "validate_existing_target_version");
    try expectAbsent(recover_branch, "publish_target_version_once");
}

test "hidden uploads and action versus REST digest formats are explicit" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const capture = try section(
        workflow,
        "\n  capture:\n",
        "\n  publish_provenance:\n",
    );

    try expectCount(workflow, "uses: actions/upload-artifact@", 3);
    try expectCount(workflow, "include-hidden-files: true", 3);
    for ([_][]const u8{
        "${{ env.RECOVERY_DIR }}/capture-state.json",
        "${{ env.RECOVERY_DIR }}/recovery-intent.json",
        "${{ env.DISPATCH_DIR }}/put-dispatch.json",
        "${{ env.RESULT_DIR }}/capture-result.json",
        "[[ \"$NEW_RECOVERY_DIGEST\" =~ ^[0-9a-f]{64}$ ]]",
        "recovery_digest=\"sha256:$NEW_RECOVERY_DIGEST\"",
        "[[ \"$NEW_DISPATCH_DIGEST\" =~ ^[0-9a-f]{64}$ ]]",
        "export DISPATCH_ARTIFACT_DIGEST=\"sha256:$NEW_DISPATCH_DIGEST\"",
        "[[ \"$artifact_digest\" =~ ^sha256:[0-9a-f]{64}$ ]]",
        "[[ \"$RECOVERY_ARTIFACT_DIGEST\" =~ ^sha256:[0-9a-f]{64}$ ]]",
    }) |needle| try expectContains(workflow, needle);
    try expectAbsent(capture, "path: ${{ env.RECOVERY_DIR }}\n");
    try expectAbsent(capture, "path: ${{ env.DISPATCH_DIR }}\n");
    try expectAbsent(capture, "path: ${{ env.RESULT_DIR }}\n");
}

test "draft release creation resume and ambiguity use numeric REST identity" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const publication = try section(
        workflow,
        "\n  publish_provenance:\n",
        null,
    );

    for ([_][]const u8{
        "gh api --paginate --slurp",
        "repos/$GITHUB_REPOSITORY/releases?per_page=100",
        "[.[][] | select(.tag_name == $tag)]",
        "(( release_count <= 1 ))",
        "Multiple releases use the exact provenance tag",
        "if (( release_count == 0 )); then",
        "tag_name: $tag",
        "target_commitish: $target",
        "gh api --method POST",
        "release_id=$(jq -er",
        "validate_release_identity \"$release_json\"",
        "repos/$GITHUB_REPOSITORY/releases/$release_id",
        ".target_commitish == $tool_commit",
        ".body == $notes",
        "uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets",
        "ubuntu2404_confidential_github_policy.sh",
        "require-absent \"$PROVENANCE_RELEASE_TAG\" \"$TOOL_COMMIT\"",
        "require-lightweight \"$PROVENANCE_RELEASE_TAG\" \"$TOOL_COMMIT\"",
        "ubuntu2404_confidential_publish_release.sh",
        "EXPECTED_RELEASE_NOTES=\"$expected_notes\"",
        "\"$VALIDATION_DIR/publish-release.json\"",
    }) |needle| try expectContains(publication, needle);
    try expectCount(
        publication,
        "releases/tags/$PROVENANCE_RELEASE_TAG",
        1,
    );
    const publish = try indexOf(
        publication,
        "scripts/ubuntu2404_confidential_publish_release.sh",
    );
    const tag_read = try indexOf(
        publication,
        "releases/tags/$PROVENANCE_RELEASE_TAG",
    );
    try std.testing.expect(publish < tag_read);
    const after_publish = publication[publish..];
    const response_digest = try indexOf(
        after_publish,
        ".assets[0].digest == $digest",
    );
    const tag_verify = try indexOf(
        after_publish,
        "require-lightweight \"$PROVENANCE_RELEASE_TAG\" \"$TOOL_COMMIT\"",
    );
    try std.testing.expect(response_digest < tag_verify);
}

test "publish route resends exact identity and keeps Latest unchanged" {
    const allocator = std.testing.allocator;
    const publisher_source = try readTracked(allocator, publish_release_path);
    defer allocator.free(publisher_source);
    for ([_][]const u8{
        "tag_name: $tag",
        "target_commitish: $target",
        "name: $title",
        "body: $notes",
        "draft: false",
        "prerelease: false",
        "make_latest: \"false\"",
        "gh api --method PATCH",
        "repos/$GITHUB_REPOSITORY/releases/$release_id",
    }) |needle| try expectContains(publisher_source, needle);

    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const publisher = try std.fs.path.join(
        allocator,
        &.{ root, publish_release_path },
    );
    defer allocator.free(publisher);
    const stat = try Dir.cwd().statFile(std.testing.io, publisher, .{});
    try std.testing.expect(stat.permissions.toMode() & 0o111 != 0);
    const syntax = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ "bash", "-n", publisher },
        .stdout_limit = .limited(max_output_bytes),
        .stderr_limit = .limited(max_output_bytes),
    });
    defer allocator.free(syntax.stdout);
    defer allocator.free(syntax.stderr);
    try std.testing.expectEqual(@as(?u8, 0), switch (syntax.term) {
        .exited => |code| code,
        else => null,
    });

    try runShellFixture(allocator, "publish-release-route-fixture.sh",
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\mkdir bin
        \\cat >bin/gh <<'GH'
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\method=GET
        \\input=
        \\endpoint=
        \\while (($#)); do
        \\  case "$1" in
        \\    --method) method=$2; shift 2 ;;
        \\    --input) input=$2; shift 2 ;;
        \\    repos/*) endpoint=$1; shift ;;
        \\    *) shift ;;
        \\  esac
        \\done
        \\test "$method" = PATCH
        \\test "$endpoint" = repos/cataggar/miz/releases/7
        \\jq -e '
        \\  (keys | sort) ==
        \\    ["body","draft","make_latest","name","prerelease","tag_name","target_commitish"] and
        \\  .tag_name == "miz-provenance/ubuntu2404-confidential-cvm/v1.2.3/origin-123-attempt-4/tool-0123456789abcdef0123456789abcdef01234567" and
        \\  .target_commitish == "0123456789abcdef0123456789abcdef01234567" and
        \\  .name == "Ubuntu 24.04 Confidential VM gallery provenance 1.2.3" and
        \\  .body == "exact origin and intent" and
        \\  .draft == false and .prerelease == false and
        \\  (.make_latest | type) == "string" and .make_latest == "false"
        \\' "$input" >/dev/null
        \\printf '%s %s\n' "$method" "$endpoint" >"$GH_LOG"
        \\cat "$input"
        \\GH
        \\chmod +x bin/gh
        \\export PATH="$PWD/bin:$PATH"
        \\export GH_LOG="$PWD/gh.log"
        \\export GH_TOKEN=fixture
        \\export GH_API_VERSION=2026-03-10
        \\export GITHUB_REPOSITORY=cataggar/miz
        \\export PROVENANCE_RELEASE_TAG=miz-provenance/ubuntu2404-confidential-cvm/v1.2.3/origin-123-attempt-4/tool-0123456789abcdef0123456789abcdef01234567
        \\export PROVENANCE_RELEASE_TITLE='Ubuntu 24.04 Confidential VM gallery provenance 1.2.3'
        \\export TOOL_COMMIT=0123456789abcdef0123456789abcdef01234567
        \\export EXPECTED_RELEASE_NOTES='exact origin and intent'
        \\publisher="$MIZ_UBUNTU2404_CONFIDENTIAL_ROOT/scripts/ubuntu2404_confidential_publish_release.sh"
        \\"$publisher" 7 request.json response.json
        \\cmp request.json response.json
        \\grep -Fx 'PATCH repos/cataggar/miz/releases/7' gh.log >/dev/null
        \\
    );
}

test "draft release fixtures accept fresh and exact resume but reject foreign and duplicate" {
    try runShellFixture(std.testing.allocator, "release-selection-fixture.sh",
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\tag=miz-provenance/ubuntu2404-confidential-cvm/v1.2.3/origin-123-attempt-4/tool-0123456789abcdef0123456789abcdef01234567
        \\title='Ubuntu 24.04 Confidential VM gallery provenance 1.2.3'
        \\asset=Ubuntu-24.04-x86_64.confidential-cvm-1.2.3.provenance.json
        \\tool_commit=0123456789abcdef0123456789abcdef01234567
        \\notes='exact origin and intent'
        \\fresh='[[]]'
        \\exact='[[{"id":7,"tag_name":"miz-provenance/ubuntu2404-confidential-cvm/v1.2.3/origin-123-attempt-4/tool-0123456789abcdef0123456789abcdef01234567","name":"Ubuntu 24.04 Confidential VM gallery provenance 1.2.3","target_commitish":"0123456789abcdef0123456789abcdef01234567","body":"exact origin and intent","draft":true,"immutable":false,"prerelease":false,"assets":[]}]]'
        \\foreign='[[{"id":8,"tag_name":"miz-provenance/ubuntu2404-confidential-cvm/v1.2.3/origin-123-attempt-4/tool-0123456789abcdef0123456789abcdef01234567","name":"foreign","target_commitish":"0123456789abcdef0123456789abcdef01234567","body":"wrong origin","draft":true,"immutable":false,"prerelease":false,"assets":[]}]]'
        \\duplicate='[[{"id":7,"tag_name":"miz-provenance/ubuntu2404-confidential-cvm/v1.2.3/origin-123-attempt-4/tool-0123456789abcdef0123456789abcdef01234567"},{"id":9,"tag_name":"miz-provenance/ubuntu2404-confidential-cvm/v1.2.3/origin-123-attempt-4/tool-0123456789abcdef0123456789abcdef01234567"}]]'
        \\select_exact() {
        \\  jq -c --arg tag "$tag" '[.[][] | select(.tag_name == $tag)]'
        \\}
        \\validate_identity() {
        \\  jq -e \
        \\    --arg tag "$tag" \
        \\    --arg title "$title" \
        \\    --arg name "$asset" \
        \\    --arg notes "$notes" \
        \\    --arg tool_commit "$tool_commit" \
        \\    '.tag_name == $tag and .name == $title and
        \\     .target_commitish == $tool_commit and
        \\     .body == $notes and .prerelease == false and
        \\     .draft == true and .immutable == false and
        \\     (.assets | length == 0 or length == 1) and
        \\     all(.assets[];
        \\       .name == $name and .state == "uploaded" and
        \\       (.id | type == "number" and . > 0))' >/dev/null
        \\}
        \\[[ "$(select_exact <<<"$fresh" | jq 'length')" == 0 ]]
        \\exact_selected=$(select_exact <<<"$exact")
        \\[[ "$(jq 'length' <<<"$exact_selected")" == 1 ]]
        \\validate_identity <<<"$(jq '.[0]' <<<"$exact_selected")"
        \\foreign_selected=$(select_exact <<<"$foreign")
        \\if validate_identity <<<"$(jq '.[0]' <<<"$foreign_selected")"; then
        \\  exit 90
        \\fi
        \\[[ "$(select_exact <<<"$duplicate" | jq 'length')" == 2 ]]
        \\
    );
}

test "result artifact fixtures preserve original and recovery physical run IDs" {
    try runShellFixture(std.testing.allocator, "result-artifact-selection-fixture.sh",
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\name=ubuntu2404-confidential-capture-result-123-4-1.2.3
        \\original='[{"artifacts":[{"id":1,"name":"ubuntu2404-confidential-capture-result-123-4-1.2.3","workflow_run":{"id":123}}]}]'
        \\recovery='[{"artifacts":[{"id":2,"name":"ubuntu2404-confidential-capture-result-123-4-1.2.3","workflow_run":{"id":456}}]}]'
        \\ambiguous='[{"artifacts":[{"id":1,"name":"ubuntu2404-confidential-capture-result-123-4-1.2.3","workflow_run":{"id":123}},{"id":2,"name":"ubuntu2404-confidential-capture-result-123-4-1.2.3","workflow_run":{"id":456}}]}]'
        \\select_artifacts() {
        \\  jq -c --arg name "$name" \
        \\    '[.[] | .artifacts[]? | select(.name == $name)]'
        \\}
        \\original_selected=$(select_artifacts <<<"$original")
        \\recovery_selected=$(select_artifacts <<<"$recovery")
        \\[[ "$(jq -r '.[0].workflow_run.id' <<<"$original_selected")" == 123 ]]
        \\[[ "$(jq -r '.[0].workflow_run.id' <<<"$recovery_selected")" == 456 ]]
        \\[[ "$(select_artifacts <<<"$ambiguous" | jq 'length')" == 2 ]]
        \\
    );
}

test "publisher scopes are pre-provisionable and delete-free" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const harness = try readTracked(allocator, harness_path);
    defer allocator.free(harness);

    for ([_][]const u8{
        "PUBLICATION_SNAPSHOT_READ_SCOPE",
        "PUBLICATION_VERSION_WRITE_SCOPE",
        "CAPTURE_TARGET_READ_SCOPE",
        "expected_snapshot_scope=\"/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$SCRATCH_RESOURCE_GROUP\"",
        "providers/Microsoft.Compute/galleries/$TARGET_GALLERY/images/$TARGET_IMAGE_DEFINITION",
    }) |needle| try expectContains(workflow, needle);
    for ([_][]const u8{
        "PUBLICATION_SNAPSHOT_READ_SCOPE",
        "PUBLICATION_VERSION_WRITE_SCOPE",
        "CAPTURE_TARGET_READ_SCOPE",
        "validate_publication_snapshot_access",
        "publication_az snapshot show --ids \"$snapshot_id\"",
    }) |needle| try expectContains(harness, needle);
    try expectAbsent(harness, "sig image-version delete");
    try expectAbsent(harness, "sig image-definition delete");
}

test "operator guide fixes prerequisites RBAC and quarantine boundary" {
    const allocator = std.testing.allocator;
    const guide = try readTracked(allocator, guide_path);
    defer allocator.free(guide);
    for ([_][]const u8{
        "Azure creates the captured VM Guest State",
        "`SecurityType=ConfidentialVM`",
        "`VMGuestStateOnly`",
        "`EncryptedVMGuestStateOnlyWithPmk`",
        "Replication is\n`Full`",
        "durable target resource group, private gallery",
        "`AZURE_CAPTURE_CLIENT_ID`",
        "`AZURE_PUBLICATION_CLIENT_ID`",
        "`PUBLICATION_SNAPSHOT_READ_SCOPE`",
        "`PUBLICATION_VERSION_WRITE_SCOPE`",
        "`CAPTURE_TARGET_READ_SCOPE`",
        "`SCRATCH_RESERVATION_TAG`",
        "`CAPTURE_GITHUB_APP_ID`",
        "`CAPTURE_GITHUB_APP_PRIVATE_KEY`",
        "**Administration: write**",
        "**Actions: read**",
        "**Contents: read**",
        "**Contents: write**",
        "**Workflows: write**",
        "omits `bypass_actors` from a ruleset response",
        "GitHub App/integration ID",
        "not the App installation ID",
        "security boundary deliberately supports only the personal repository",
        "collaborators?affiliation=all&per_page=100",
        "permissions.push",
        "permissions.maintain",
        "permissions.admin",
        "`CAPTURE_RELEASE_WRITER_POLICY`",
        "`owner-and-publisher-app-only-v1`",
        "manually audit",
        "not cryptographic proof",
        "trusted computing\nbase",
        "Compromised trusted administrators\nare outside",
        "actions/permissions/workflow",
        "default_workflow_permissions=read",
        "can_approve_pull_request_reviews=false",
        "repository owner remains the human writer and administrator trust root",
        "`ubuntu2404-confidential-provenance-tags`",
        "GET /repos/cataggar/miz/rulesets?includes_parents=true&targets=tag",
        "\"actor_type\": \"Integration\"",
        "\"bypass_mode\": \"always\"",
        "\"refs/tags/miz-provenance/ubuntu2404-confidential-cvm/*/*/*\"",
        "`File.fnmatch` with `FNM_PATHNAME`",
        "{\"type\": \"creation\"}",
        "{\"type\": \"deletion\"}",
        "Do not pre-create\nthe tag",
        "`scratch_resource_group`",
        "`miz-u2404-cvm-capture-<32-lowercase-hex>`",
        "require at least one designated release reviewer",
        "disable self-review",
        "GET /repos/cataggar/miz/immutable-releases",
        "`enabled=true`",
        "`Microsoft.Compute/snapshots/read`",
        "pre-provisioned scratch",
        "preexisting image-definition resource",
        "does not exist before dispatch",
        "no version delete permission",
        "outside what the workflow or harness\ncan prove",
        "stable, non-canceling concurrency group",
        "`origin_run_id`",
        "`origin_run_attempt`",
        "retained for 90 days",
        "never issues a second\nPUT",
        "exact owned draft may be resumed",
        "target_commitish=TOOL_COMMIT",
        "make_latest=\"false\"",
        "one protected job",
        "object.type=commit",
        "quarantined",
        "manual",
        "live Azure qualification run",
    }) |needle| try expectContains(guide, needle);
    try expectAbsent(guide, "GET /repos/cataggar/miz/installations");
}
