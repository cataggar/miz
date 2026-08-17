//! Small transport interfaces shared by local layouts and registries.
//! Metadata is bounded and allocated by the source; content blobs are always
//! copied through a destination-owned fixed-size temporary-file path.
const std = @import("std");
const model = @import("model.zig");
const reference = @import("reference.zig");

pub const Counts = struct {
    transferred: u64 = 0,
    reused: u64 = 0,
    mounted: u64 = 0,
};

/// Identity exposed by registry sources so a registry destination can try a
/// cross-repository mount before asking the source to stream a missing blob.
/// The slices are borrowed from the source transport.
pub const RegistryIdentity = struct {
    authority: []const u8,
    repository: []const u8,
    plain_http: bool,
};

pub const DescriptorRole = enum {
    blob,
    manifest,
};

pub const Source = struct {
    context: *anyopaque,
    read_metadata: *const fn (context: *anyopaque, descriptor: model.Descriptor) anyerror![]u8,
    read_manifest_metadata: *const fn (context: *anyopaque, descriptor: model.Descriptor) anyerror![]u8,
    copy_verified_to: *const fn (
        context: *anyopaque,
        descriptor: model.Descriptor,
        destination: std.Io.File,
    ) anyerror!void,
    registry_identity: ?RegistryIdentity = null,

    pub fn readMetadata(self: Source, descriptor: model.Descriptor) ![]u8 {
        return self.read_metadata(self.context, descriptor);
    }

    pub fn readManifestMetadata(self: Source, descriptor: model.Descriptor) ![]u8 {
        return self.read_manifest_metadata(self.context, descriptor);
    }

    pub fn copyVerifiedTo(self: Source, descriptor: model.Descriptor, destination: std.Io.File) !void {
        return self.copy_verified_to(self.context, descriptor, destination);
    }
};

pub const Destination = struct {
    context: *anyopaque,
    prepare: *const fn (
        context: *anyopaque,
        root: model.Descriptor,
        selection: ?reference.Selection,
    ) anyerror!void,
    /// `metadata` is the exact already-verified bytes for a manifest or index
    /// descriptor. It is null for opaque blobs.
    ensure_descriptor: *const fn (
        context: *anyopaque,
        source: Source,
        descriptor: model.Descriptor,
        role: DescriptorRole,
        metadata: ?[]const u8,
        counts: *Counts,
    ) anyerror!void,
    /// Local layouts can stage a selected root blob before the selected
    /// config check. Registry destinations intentionally leave this as a
    /// no-op so the final reference is their first root publication.
    stage_root: *const fn (
        context: *anyopaque,
        source: Source,
        root: model.Descriptor,
        counts: *Counts,
    ) anyerror!void,
    /// Called only after all root dependencies have completed. Registry
    /// destinations make the destination tag visible here.
    commit: *const fn (
        context: *anyopaque,
        source: Source,
        root: model.Descriptor,
        root_descriptor_json: []const u8,
        root_bytes: []const u8,
        selection: ?reference.Selection,
        counts: *Counts,
    ) anyerror!void,
    finish: *const fn (context: *anyopaque) anyerror!void,

    pub fn prepareRoot(
        self: Destination,
        root: model.Descriptor,
        selection: ?reference.Selection,
    ) !void {
        return self.prepare(self.context, root, selection);
    }

    pub fn ensureDescriptor(
        self: Destination,
        source: Source,
        descriptor: model.Descriptor,
        role: DescriptorRole,
        metadata: ?[]const u8,
        counts: *Counts,
    ) !void {
        return self.ensure_descriptor(self.context, source, descriptor, role, metadata, counts);
    }

    pub fn stageRoot(
        self: Destination,
        source: Source,
        root: model.Descriptor,
        counts: *Counts,
    ) !void {
        return self.stage_root(self.context, source, root, counts);
    }

    pub fn commitRoot(
        self: Destination,
        source: Source,
        root: model.Descriptor,
        root_descriptor_json: []const u8,
        root_bytes: []const u8,
        selection: ?reference.Selection,
        counts: *Counts,
    ) !void {
        return self.commit(
            self.context,
            source,
            root,
            root_descriptor_json,
            root_bytes,
            selection,
            counts,
        );
    }

    pub fn finishDestination(self: Destination) !void {
        return self.finish(self.context);
    }
};
