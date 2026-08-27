//! EDK II authenticated UEFI variable store (`*_VARS.fd`) parsing and editing.
//!
//! This is the native replacement for `virt-fw-vars` from
//! `python3-virt-firmware`. It understands the exact on-media layout that the
//! OVMF and AAVMF Secure-Boot variable templates use:
//!
//!   * `EFI_FIRMWARE_VOLUME_HEADER` at offset 0, with `_FVH`, the EDK II
//!     system NV data FV GUID, a block map and the UEFI-16 header checksum;
//!   * `VARIABLE_STORE_HEADER` with the authenticated-variable GUID, the
//!     formatted/healthy state pair and the store size; and
//!   * a run of 4-byte-aligned `AUTHENTICATED_VARIABLE_HEADER` records, each
//!     followed by its UTF-16LE name and its data, terminated by erased
//!     (`0xff`) flash.
//!
//! Editing preserves everything it does not need to change: the firmware
//! volume, its checksum, the store header, the authenticated PK/KEK/db/dbx
//! payloads and their timestamps, and every byte outside the variable region
//! (AAVMF pads a 768 KiB volume out to a 64 MiB pflash image). Re-serializing
//! compacts deleted and interrupted records, keeps live records in their
//! original order, pads each record to the 4-byte header alignment with
//! erased flash, and fills the remaining capacity with erased flash.
//!
//! Only a raw flash image is accepted, and only with its volume at offset 0.
//! `virt-fw-vars` scans for a volume further in and separately understands
//! QCOW2, but miz hands the store to QEMU as `format=raw` pflash: enrolling a
//! volume embedded in a container would produce a file whose Secure Boot
//! state the firmware never reads, and miz would then validate its own
//! invisible edit. Containers are refused by magic with a specific error.
//!
//! Three behaviors differ from `virt-fw-vars` on purpose. Records are written
//! in their original order instead of sorted by name, which UEFI does not
//! observe. Existing authenticated timestamps are preserved rather than
//! advanced to the appended certificate's `notBefore`, so appending a leaf
//! cannot narrow the window for a later authenticated update. And no dummy
//! `dbx` entry is synthesized: enrollment requires a vendor template that
//! already carries `PK`, `KEK`, and `db`, because miz appends to existing
//! trust rather than establishing it.

const std = @import("std");

const authenticode = @import("authenticode.zig");
const guid_mod = @import("guid.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Guid = guid_mod.Guid;
/// Structurally identical to `artifact_pipeline.Digest`, declared locally so
/// this module stays free of the disk-image dependency graph.
pub const Digest = [Sha256.digest_length]u8;

fn sha256Bytes(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    Sha256.hash(bytes, &digest, .{});
    return digest;
}

/// `EFI_SYSTEM_NV_DATA_FV_GUID`: the firmware volume that holds the variable
/// store, the fault-tolerant-write working block and its spare area.
pub const system_nv_data_fv_guid: Guid =
    guid_mod.parse("FFF12B8D-7696-4C8B-A985-2747075B4F50");
/// `gEfiAuthenticatedVariableGuid`: the only variable-store format that can
/// carry Secure Boot's time-based authenticated variables.
pub const authenticated_variable_store_guid: Guid =
    guid_mod.parse("AAF32C78-947B-439A-A180-2E144EC37792");
/// `gEfiVariableGuid`: the unauthenticated store format, recognized only so
/// the failure is specific instead of "not a variable store".
pub const plain_variable_store_guid: Guid =
    guid_mod.parse("DDCF3616-3275-4164-98B6-FE85707FFE7D");

pub const global_variable_guid: Guid =
    guid_mod.parse("8BE4DF61-93CA-11D2-AA0D-00E098032B8C");
pub const image_security_database_guid: Guid =
    guid_mod.parse("D719B2CB-3D3A-4596-A3BC-DAD00E67656F");
pub const secure_boot_enable_guid: Guid =
    guid_mod.parse("F0A30BC7-AF08-4556-99C4-001009C93A44");
pub const custom_mode_guid: Guid =
    guid_mod.parse("C076EC0C-7028-4399-A072-71EE5C448B9F");
/// `EFI_CERT_X509_GUID`: an `EFI_SIGNATURE_LIST` of DER X.509 certificates.
pub const cert_x509_guid: Guid =
    guid_mod.parse("A5C059A1-94E4-4AA7-87B5-AB155C2BF072");

/// The owner GUID miz stamps on the release signing leaf it appends to `db`.
/// It exists purely to make miz-enrolled entries identifiable; it is never
/// used as trust material.
pub const release_signature_owner_guid: Guid =
    guid_mod.parse("7F32D4A1-7C10-4E6D-8A89-15BA3F4DB734");

pub const attribute_non_volatile: u32 = 0x0000_0001;
pub const attribute_bootservice_access: u32 = 0x0000_0002;
pub const attribute_runtime_access: u32 = 0x0000_0004;
pub const attribute_time_based_authenticated_write_access: u32 = 0x0000_0020;

/// `EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS`, the
/// attributes EDK II gives `SecureBootEnable` and `CustomMode`.
pub const boot_service_attributes: u32 =
    attribute_non_volatile | attribute_bootservice_access;
/// The attributes every Secure Boot signature database carries.
pub const authenticated_variable_attributes: u32 =
    attribute_non_volatile |
    attribute_bootservice_access |
    attribute_runtime_access |
    attribute_time_based_authenticated_write_access;

const fv_signature: u32 = 0x4856_465f; // '_FVH'
const fv_revision: u8 = 2;
const fv_header_fixed_size: usize = 56;
const fv_block_map_entry_size: usize = 8;
const min_fv_header_size: usize = fv_header_fixed_size + fv_block_map_entry_size;

const store_header_size: usize = 28;
const store_format_formatted: u8 = 0x5a;
const store_state_healthy: u8 = 0xfe;

const variable_start_id: u16 = 0x55aa;
const erased_start_id: u16 = 0xffff;
const variable_header_size: usize = 60;
const header_alignment: usize = 4;
const erased_byte: u8 = 0xff;

/// EDK II variable states. A record moves `erased -> header_valid_only ->
/// added -> in_deleted_transition -> deleted` as flash bits are cleared, so
/// every intermediate value can legitimately appear in a store that lost
/// power mid-write.
const state_added: u8 = 0x3f;
const state_in_deleted_transition: u8 = 0x3e;
const state_deleted: u8 = 0x3d;
const state_deleted_after_transition: u8 = 0x3c;
const state_header_valid_only: u8 = 0x7f;

/// The largest variable store this module will read. AAVMF's pflash template
/// is 64 MiB; nothing legitimate is larger.
pub const max_store_bytes: usize = 128 * 1024 * 1024;
/// Refuses absurd `NameSize`/`DataSize` before they are used for arithmetic.
const max_variable_bytes: u32 = 16 * 1024 * 1024;

pub const ParseError = error{
    VariableStoreNotFound,
    UnsupportedVariableStoreContainer,
    InvalidFirmwareVolume,
    InvalidVariableStoreHeader,
    UnsupportedVariableStoreFormat,
    MalformedVariableStore,
    TruncatedVariableStore,
    DuplicateVariableRecord,
};

pub const EditError = error{
    VariableStoreFull,
    MissingSignatureDatabase,
    MissingPlatformKey,
    MissingKeyExchangeKey,
    UnauthenticatedSignatureDatabase,
    InvalidCertificate,
    InvalidSignatureDatabase,
};

pub const ValidateError = error{
    InvalidSecureBootVariables,
};

/// One live variable, owned by its `Store`.
pub const Variable = struct {
    /// UTF-16LE including the terminating code unit, exactly as stored.
    name_utf16le: []u8,
    vendor_guid: Guid,
    attributes: u32,
    monotonic_count: u64,
    /// Raw `EFI_TIME`. Preserved verbatim; authenticated variables carry the
    /// timestamp of the write that produced their contents.
    timestamp: [16]u8,
    pubkey_index: u32,
    data: []u8,

    fn deinit(self: *Variable, allocator: Allocator) void {
        allocator.free(self.name_utf16le);
        allocator.free(self.data);
        self.* = undefined;
    }

    /// Whether the UTF-16LE name equals `expected`, which must be ASCII.
    pub fn nameEquals(self: Variable, expected: []const u8) bool {
        if (self.name_utf16le.len != (expected.len + 1) * 2) return false;
        for (expected, 0..) |byte, index| {
            if (self.name_utf16le[index * 2] != byte) return false;
            if (self.name_utf16le[index * 2 + 1] != 0) return false;
        }
        return self.name_utf16le[expected.len * 2] == 0 and
            self.name_utf16le[expected.len * 2 + 1] == 0;
    }

    /// Bytes this variable occupies on media, including alignment padding.
    pub fn encodedSize(self: Variable) usize {
        return alignUp(variable_header_size + self.name_utf16le.len + self.data.len);
    }
};

/// A parsed store: the untouched backing image plus the live variables.
pub const Store = struct {
    allocator: Allocator,
    /// The complete file image. The NV-data firmware volume starts at offset
    /// 0; everything outside `[data_offset, data_end)` is written back
    /// byte-for-byte.
    image: []u8,
    fv_length: u64,
    fv_header_length: u16,
    store_offset: usize,
    store_size: u32,
    /// First byte of the variable region and one past its last byte.
    data_offset: usize,
    data_end: usize,
    variables: std.ArrayList(Variable),
    /// Records skipped because they were deleted, superseded or interrupted.
    /// Re-serializing reclaims their space.
    reclaimed_records: usize,

    pub fn deinit(self: *Store) void {
        for (self.variables.items) |*variable| variable.deinit(self.allocator);
        self.variables.deinit(self.allocator);
        self.allocator.free(self.image);
        self.* = undefined;
    }

    /// Total capacity of the variable region.
    pub fn capacity(self: Store) usize {
        return self.data_end - self.data_offset;
    }

    /// Bytes the current variable set needs, including alignment padding.
    pub fn usedBytes(self: Store) usize {
        var used: usize = 0;
        for (self.variables.items) |variable| used += variable.encodedSize();
        return used;
    }

    pub fn find(self: *const Store, name: []const u8, vendor_guid: Guid) ?*Variable {
        for (self.variables.items) |*variable| {
            if (std.mem.eql(u8, &variable.vendor_guid, &vendor_guid) and
                variable.nameEquals(name)) return variable;
        }
        return null;
    }

    /// Replaces `name`'s data, or appends the variable when it is absent.
    /// Newly created variables get a zero `EFI_TIME`, which is what EDK II
    /// writes for variables without
    /// `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS`.
    pub fn set(
        self: *Store,
        name: []const u8,
        vendor_guid: Guid,
        attributes: u32,
        data: []const u8,
    ) !void {
        if (self.find(name, vendor_guid)) |variable| {
            const owned = try self.allocator.dupe(u8, data);
            self.allocator.free(variable.data);
            variable.data = owned;
            variable.attributes = attributes;
            return;
        }
        const name_utf16le = try encodeNameAlloc(self.allocator, name);
        errdefer self.allocator.free(name_utf16le);
        const owned = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(owned);
        try self.variables.append(self.allocator, .{
            .name_utf16le = name_utf16le,
            .vendor_guid = vendor_guid,
            .attributes = attributes,
            .monotonic_count = 0,
            .timestamp = [_]u8{0} ** 16,
            .pubkey_index = 0,
            .data = owned,
        });
    }

    /// Renders the edited store back to a complete file image.
    pub fn serializeAlloc(self: *const Store, allocator: Allocator) ![]u8 {
        const used = self.usedBytes();
        if (used > self.capacity()) return error.VariableStoreFull;

        const output = try allocator.dupe(u8, self.image);
        errdefer allocator.free(output);
        @memset(output[self.data_offset..self.data_end], erased_byte);

        var offset = self.data_offset;
        for (self.variables.items) |variable| {
            std.debug.assert(offset % header_alignment == 0);
            const record = output[offset..];
            std.mem.writeInt(u16, record[0..2], variable_start_id, .little);
            record[2] = state_added;
            record[3] = 0;
            std.mem.writeInt(u32, record[4..8], variable.attributes, .little);
            std.mem.writeInt(u64, record[8..16], variable.monotonic_count, .little);
            @memcpy(record[16..32], &variable.timestamp);
            std.mem.writeInt(u32, record[32..36], variable.pubkey_index, .little);
            std.mem.writeInt(
                u32,
                record[36..40],
                @intCast(variable.name_utf16le.len),
                .little,
            );
            std.mem.writeInt(u32, record[40..44], @intCast(variable.data.len), .little);
            @memcpy(record[44..60], &variable.vendor_guid);
            @memcpy(
                record[variable_header_size..][0..variable.name_utf16le.len],
                variable.name_utf16le,
            );
            @memcpy(
                record[variable_header_size + variable.name_utf16le.len ..][0..variable.data.len],
                variable.data,
            );
            offset += variable.encodedSize();
        }
        std.debug.assert(offset == self.data_offset + used);
        std.debug.assert(verifyFirmwareVolumeChecksum(
            output[0..self.fv_header_length],
        ));
        return output;
    }
};

fn alignUp(value: usize) usize {
    return (value + header_alignment - 1) & ~(header_alignment - 1);
}

fn encodeNameAlloc(allocator: Allocator, name: []const u8) ![]u8 {
    const encoded = try allocator.alloc(u8, (name.len + 1) * 2);
    errdefer allocator.free(encoded);
    for (name, 0..) |byte, index| {
        if (byte == 0 or byte >= 0x80) return error.InvalidVariableName;
        encoded[index * 2] = byte;
        encoded[index * 2 + 1] = 0;
    }
    encoded[name.len * 2] = 0;
    encoded[name.len * 2 + 1] = 0;
    return encoded;
}

/// UEFI's 16-bit ones-of-two's-complement volume-header checksum: every
/// little-endian `u16` in the header must sum to zero.
pub fn verifyFirmwareVolumeChecksum(header: []const u8) bool {
    if (header.len < min_fv_header_size or header.len % 2 != 0) return false;
    var sum: u16 = 0;
    var index: usize = 0;
    while (index < header.len) : (index += 2) {
        sum +%= std.mem.readInt(u16, header[index..][0..2], .little);
    }
    return sum == 0;
}

/// Disk-image containers that must never be mistaken for raw flash. miz
/// hands the variable store to QEMU as `format=raw` pflash, so a store found
/// at some offset *inside* a container would be a store the firmware never
/// reads: miz would enroll and self-validate bytes the guest cannot see.
const ContainerFormat = struct {
    name: []const u8,
    offset: usize,
    magic: []const u8,
};

const container_formats = [_]ContainerFormat{
    .{ .name = "QCOW/QCOW2", .offset = 0, .magic = "QFI\xfb" },
    .{ .name = "VHDX", .offset = 0, .magic = "vhdxfile" },
    .{ .name = "VHD", .offset = 0, .magic = "conectix" },
    .{ .name = "VMDK", .offset = 0, .magic = "KDMV" },
    .{ .name = "VMDK descriptor", .offset = 0, .magic = "# Disk Descriptor" },
    .{ .name = "VDI", .offset = 0x40, .magic = "\x7f\x10\xda\xbe" },
};

/// Requires the supported shape: a raw image whose NV-data firmware volume
/// starts at offset 0. Scanning for a volume further in would accept exactly
/// the containers above, so the only volume miz will edit is the one the
/// firmware maps.
fn requireRawNvDataVolume(bytes: []const u8) ParseError!void {
    for (container_formats) |container| {
        const end = container.offset + container.magic.len;
        if (bytes.len >= end and
            std.mem.eql(u8, bytes[container.offset..end], container.magic))
            return error.UnsupportedVariableStoreContainer;
    }
    if (bytes.len < min_fv_header_size) return error.VariableStoreNotFound;
    if (!std.mem.eql(u8, bytes[16..32], &system_nv_data_fv_guid))
        return error.VariableStoreNotFound;
}

/// Parses `bytes` into an editable store.
///
/// On success the store owns `bytes` and `Store.deinit` frees them. On
/// failure the caller still owns `bytes`: a parser that freed its input on
/// the error path would turn a caller's `defer` into a double free.
pub fn parse(allocator: Allocator, bytes: []u8) !Store {
    var store = try parseHeaders(allocator, bytes);
    // Releases what `readVariables` accumulated without touching `bytes`.
    errdefer {
        for (store.variables.items) |*variable| variable.deinit(allocator);
        store.variables.deinit(allocator);
    }
    try readVariables(&store);
    return store;
}

/// Validates the firmware volume and store headers. `bytes` stays owned by
/// the caller until this succeeds.
fn parseHeaders(allocator: Allocator, bytes: []u8) ParseError!Store {
    if (bytes.len > max_store_bytes) return error.InvalidFirmwareVolume;

    try requireRawNvDataVolume(bytes);
    const volume = bytes;

    const fv_length = std.mem.readInt(u64, volume[32..40], .little);
    const signature = std.mem.readInt(u32, volume[40..44], .little);
    const header_length = std.mem.readInt(u16, volume[48..50], .little);
    const ext_header_offset = std.mem.readInt(u16, volume[52..54], .little);
    const revision = volume[55];

    if (signature != fv_signature) return error.InvalidFirmwareVolume;
    if (revision != fv_revision) return error.InvalidFirmwareVolume;
    // A variable store's FV has no extended header; refusing one keeps the
    // store offset (`header_length`) unambiguous.
    if (ext_header_offset != 0) return error.InvalidFirmwareVolume;
    if (header_length < min_fv_header_size or
        header_length % 2 != 0 or
        header_length > volume.len) return error.InvalidFirmwareVolume;
    if (fv_length < header_length + store_header_size or
        fv_length > volume.len) return error.InvalidFirmwareVolume;
    if (!verifyFirmwareVolumeChecksum(volume[0..header_length]))
        return error.InvalidFirmwareVolume;

    var mapped_bytes: u64 = 0;
    var map_offset: usize = fv_header_fixed_size;
    var terminated = false;
    while (map_offset + fv_block_map_entry_size <= header_length) : (map_offset += fv_block_map_entry_size) {
        const block_count = std.mem.readInt(u32, volume[map_offset..][0..4], .little);
        const block_length = std.mem.readInt(u32, volume[map_offset + 4 ..][0..4], .little);
        if (block_count == 0 and block_length == 0) {
            terminated = true;
            break;
        }
        if (block_count == 0 or block_length == 0) return error.InvalidFirmwareVolume;
        mapped_bytes += @as(u64, block_count) * @as(u64, block_length);
        if (mapped_bytes > fv_length) return error.InvalidFirmwareVolume;
    }
    if (!terminated or mapped_bytes != fv_length) return error.InvalidFirmwareVolume;

    const store_offset: usize = header_length;
    const store_header = bytes[store_offset..];
    if (store_header.len < store_header_size) return error.InvalidVariableStoreHeader;
    const store_guid: Guid = store_header[0..16].*;
    if (!std.mem.eql(u8, &store_guid, &authenticated_variable_store_guid)) {
        if (std.mem.eql(u8, &store_guid, &plain_variable_store_guid))
            return error.UnsupportedVariableStoreFormat;
        return error.InvalidVariableStoreHeader;
    }
    const store_size = std.mem.readInt(u32, store_header[16..20], .little);
    const store_format = store_header[20];
    const store_state = store_header[21];
    if (store_format != store_format_formatted or store_state != store_state_healthy)
        return error.UnsupportedVariableStoreFormat;
    if (store_size < store_header_size + variable_header_size or
        store_size > fv_length - header_length) return error.InvalidVariableStoreHeader;

    const data_offset = store_offset + store_header_size;
    const data_end = store_offset + store_size;
    if (data_offset % header_alignment != 0) return error.InvalidVariableStoreHeader;

    return .{
        .allocator = allocator,
        .image = bytes,
        .fv_length = fv_length,
        .fv_header_length = header_length,
        .store_offset = store_offset,
        .store_size = store_size,
        .data_offset = data_offset,
        .data_end = data_end,
        .variables = .empty,
        .reclaimed_records = 0,
    };
}

/// Reads `path` and parses it. The returned store owns the file contents.
pub fn parseFileAlloc(allocator: Allocator, io: Io, path: []const u8) !Store {
    const bytes = try Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(max_store_bytes),
    );
    errdefer allocator.free(bytes);
    return parse(allocator, bytes);
}

fn readVariables(store: *Store) !void {
    const allocator = store.allocator;
    var offset = store.data_offset;
    // Tracks, per accepted variable, whether the record it came from was a
    // completed `VAR_ADDED` rather than one caught in deleted transition.
    var completed: std.ArrayList(bool) = .empty;
    defer completed.deinit(allocator);

    while (offset + variable_header_size <= store.data_end) {
        const record = store.image[offset..store.data_end];
        const start_id = std.mem.readInt(u16, record[0..2], .little);
        if (start_id == erased_start_id) break;
        if (start_id != variable_start_id) return error.MalformedVariableStore;

        const state = record[2];
        const attributes = std.mem.readInt(u32, record[4..8], .little);
        const monotonic_count = std.mem.readInt(u64, record[8..16], .little);
        const pubkey_index = std.mem.readInt(u32, record[32..36], .little);
        const name_size = std.mem.readInt(u32, record[36..40], .little);
        const data_size = std.mem.readInt(u32, record[40..44], .little);

        switch (state) {
            state_added,
            state_in_deleted_transition,
            state_deleted,
            state_deleted_after_transition,
            state_header_valid_only,
            => {},
            else => return error.MalformedVariableStore,
        }
        if (name_size == 0 or
            name_size % 2 != 0 or
            name_size > max_variable_bytes or
            data_size > max_variable_bytes) return error.MalformedVariableStore;

        const body = variable_header_size + @as(usize, name_size) + @as(usize, data_size);
        if (body > record.len) return error.TruncatedVariableStore;
        const next = offset + alignUp(body);
        if (next > store.data_end) return error.TruncatedVariableStore;

        const name = record[variable_header_size..][0..name_size];
        if (name[name_size - 2] != 0 or name[name_size - 1] != 0)
            return error.MalformedVariableStore;

        if (state == state_added or state == state_in_deleted_transition) {
            const vendor_guid: Guid = record[44..60].*;
            const data = record[variable_header_size + name_size ..][0..data_size];
            const existing = findRaw(store, name, vendor_guid);
            // EDK II's `FindVariableEx` returns the *first* `VAR_ADDED`
            // record and only falls back to the last in-deleted-transition
            // one when no complete record exists. A store holding two
            // complete records for the same name and GUID is therefore
            // ambiguous in the most dangerous possible way: miz would report
            // one value while the firmware used the other. Refuse it rather
            // than pick a winner.
            if (existing) |index| {
                if (state == state_added and completed.items[index])
                    return error.DuplicateVariableRecord;
                store.reclaimed_records += 1;
                if (state != state_added) {
                    // A completed record already won; and with none, the
                    // last in-deleted-transition record is the live value.
                    if (completed.items[index]) {
                        offset = next;
                        continue;
                    }
                }
            }
            const owned_name = try allocator.dupe(u8, name);
            errdefer allocator.free(owned_name);
            const owned_data = try allocator.dupe(u8, data);
            errdefer allocator.free(owned_data);
            const variable: Variable = .{
                .name_utf16le = owned_name,
                .vendor_guid = vendor_guid,
                .attributes = attributes,
                .monotonic_count = monotonic_count,
                .timestamp = record[16..32].*,
                .pubkey_index = pubkey_index,
                .data = owned_data,
            };
            if (existing) |index| {
                store.variables.items[index].deinit(allocator);
                store.variables.items[index] = variable;
                completed.items[index] = state == state_added;
            } else {
                try store.variables.append(allocator, variable);
                errdefer _ = store.variables.pop();
                try completed.append(allocator, state == state_added);
            }
        } else {
            store.reclaimed_records += 1;
        }
        offset = next;
    }
}

fn findRaw(store: *const Store, name_utf16le: []const u8, vendor_guid: Guid) ?usize {
    for (store.variables.items, 0..) |variable, index| {
        if (std.mem.eql(u8, &variable.vendor_guid, &vendor_guid) and
            std.mem.eql(u8, variable.name_utf16le, name_utf16le)) return index;
    }
    return null;
}

/// One `EFI_SIGNATURE_LIST` inside a signature database.
pub const SignatureList = struct {
    signature_type: Guid,
    header: []const u8,
    signature_size: u32,
    signatures: []const u8,

    pub fn count(self: SignatureList) usize {
        return self.signatures.len / self.signature_size;
    }

    pub fn signatureOwner(self: SignatureList, index: usize) Guid {
        return self.signatures[index * self.signature_size ..][0..16].*;
    }

    pub fn signatureData(self: SignatureList, index: usize) []const u8 {
        const start = index * self.signature_size;
        return self.signatures[start + 16 ..][0 .. self.signature_size - 16];
    }
};

/// Walks a signature database, calling `visit` with each `EFI_SIGNATURE_LIST`.
/// Every structural inconsistency is an error: a database miz cannot fully
/// account for is one it must not certify.
pub fn forEachSignatureList(
    database: []const u8,
    context: anytype,
    comptime visit: fn (@TypeOf(context), SignatureList) void,
) EditError!void {
    var offset: usize = 0;
    while (offset < database.len) {
        if (database.len - offset < 28) return error.InvalidSignatureDatabase;
        const list_size = std.mem.readInt(u32, database[offset + 16 ..][0..4], .little);
        const header_size = std.mem.readInt(u32, database[offset + 20 ..][0..4], .little);
        const signature_size = std.mem.readInt(u32, database[offset + 24 ..][0..4], .little);
        if (list_size < 28 or signature_size <= 16)
            return error.InvalidSignatureDatabase;
        const list_end = std.math.add(usize, offset, list_size) catch
            return error.InvalidSignatureDatabase;
        const signatures_start = std.math.add(usize, offset + 28, header_size) catch
            return error.InvalidSignatureDatabase;
        if (list_end > database.len or signatures_start > list_end)
            return error.InvalidSignatureDatabase;
        const signatures_bytes = list_end - signatures_start;
        if (signatures_bytes == 0 or signatures_bytes % signature_size != 0)
            return error.InvalidSignatureDatabase;
        visit(context, .{
            .signature_type = database[offset..][0..16].*,
            .header = database[offset + 28 .. signatures_start],
            .signature_size = signature_size,
            .signatures = database[signatures_start..list_end],
        });
        offset = list_end;
    }
}

/// Number of `EFI_CERT_X509` entries in `database` whose DER hashes to
/// `certificate_sha256`. Anything structurally unaccountable is an error.
pub fn countX509Certificates(
    database: []const u8,
    certificate_sha256: Digest,
) EditError!usize {
    const Counter = struct {
        wanted: Digest,
        matches: usize = 0,

        fn visit(self: *@This(), list: SignatureList) void {
            if (!std.mem.eql(u8, &list.signature_type, &cert_x509_guid)) return;
            var index: usize = 0;
            while (index < list.count()) : (index += 1) {
                const digest = sha256Bytes(list.signatureData(index));
                if (std.mem.eql(u8, &digest, &self.wanted)) self.matches += 1;
            }
        }
    };
    var counter: Counter = .{ .wanted = certificate_sha256 };
    try forEachSignatureList(database, &counter, Counter.visit);
    return counter.matches;
}

/// Builds `db`'s replacement contents with `certificate_der` appended as a
/// single-entry `EFI_CERT_X509` signature list. Returns null when the exact
/// leaf is already present, so enrollment never creates a duplicate.
fn appendX509SignatureListAlloc(
    allocator: Allocator,
    database: []const u8,
    owner_guid: Guid,
    certificate_der: []const u8,
) !?[]u8 {
    if (certificate_der.len == 0) return error.InvalidCertificate;
    const digest = sha256Bytes(certificate_der);
    if (try countX509Certificates(database, digest) != 0) return null;

    const list_size = std.math.add(usize, 28 + 16, certificate_der.len) catch
        return error.InvalidCertificate;
    if (list_size > std.math.maxInt(u32)) return error.InvalidCertificate;
    const result = try allocator.alloc(u8, database.len + list_size);
    errdefer allocator.free(result);
    @memcpy(result[0..database.len], database);
    const list = result[database.len..];
    @memcpy(list[0..16], &cert_x509_guid);
    std.mem.writeInt(u32, list[16..20], @intCast(list_size), .little);
    std.mem.writeInt(u32, list[20..24], 0, .little);
    std.mem.writeInt(u32, list[24..28], @intCast(16 + certificate_der.len), .little);
    @memcpy(list[28..44], &owner_guid);
    @memcpy(list[44..], certificate_der);
    return result;
}

pub const EnrollOptions = struct {
    /// The DER-encoded release signing leaf to append to `db`.
    certificate_der: []const u8,
    owner_guid: Guid = release_signature_owner_guid,
};

pub const EnrollOutcome = struct {
    /// False when the exact leaf was already present and was left alone.
    appended: bool,
};

/// Appends the release leaf to `db` and puts the store into the enforcing
/// Secure Boot state (`SecureBootEnable = 1`, `CustomMode = 0`).
///
/// PK, KEK and `db` must already exist and be authenticated: miz appends a
/// leaf to a vendor Microsoft-enrolled template, it never mints trust.
pub fn enrollSecureBootCertificate(
    store: *Store,
    options: EnrollOptions,
) !EnrollOutcome {
    authenticode.validateX509CertificateDer(options.certificate_der) catch
        return error.InvalidCertificate;

    if (store.find("PK", global_variable_guid) == null)
        return error.MissingPlatformKey;
    if (store.find("KEK", global_variable_guid) == null)
        return error.MissingKeyExchangeKey;
    const database = store.find("db", image_security_database_guid) orelse
        return error.MissingSignatureDatabase;
    if (database.attributes & attribute_time_based_authenticated_write_access == 0)
        return error.UnauthenticatedSignatureDatabase;

    const appended = try appendX509SignatureListAlloc(
        store.allocator,
        database.data,
        options.owner_guid,
        options.certificate_der,
    );
    if (appended) |data| {
        store.allocator.free(database.data);
        database.data = data;
    }

    try store.set(
        "SecureBootEnable",
        secure_boot_enable_guid,
        boot_service_attributes,
        &.{0x01},
    );
    try store.set(
        "CustomMode",
        custom_mode_guid,
        boot_service_attributes,
        &.{0x00},
    );

    if (store.usedBytes() > store.capacity()) return error.VariableStoreFull;
    return .{ .appended = appended != null };
}

/// The digests that pin an enrolled store to one template and one release.
pub const TrustState = struct {
    pk_sha256: Digest,
    kek_sha256: Digest,
    db_sha256: Digest,

    pub fn eql(self: TrustState, other: TrustState) bool {
        return std.mem.eql(u8, &self.pk_sha256, &other.pk_sha256) and
            std.mem.eql(u8, &self.kek_sha256, &other.kek_sha256) and
            std.mem.eql(u8, &self.db_sha256, &other.db_sha256);
    }
};

/// Fail-closed check that `store` is exactly the enforcing Secure Boot state
/// miz enrolls: Secure Boot enabled, custom mode off, a single authenticated
/// PK, KEK and `db`, and exactly one copy of the release leaf in `db`.
pub fn validateSecureBootTrust(
    store: *const Store,
    certificate_sha256: Digest,
) ValidateError!TrustState {
    var secure_boot_enabled = false;
    var secure_boot_enable_seen = false;
    var custom_mode_disabled = false;
    var custom_mode_seen = false;
    var pk_sha256: ?Digest = null;
    var kek_sha256: ?Digest = null;
    var db_sha256: ?Digest = null;
    var certificate_matches: usize = 0;

    for (store.variables.items) |variable| {
        if (variable.nameEquals("SecureBootEnable")) {
            if (secure_boot_enable_seen or
                !std.mem.eql(u8, &variable.vendor_guid, &secure_boot_enable_guid) or
                variable.attributes != boot_service_attributes)
                return error.InvalidSecureBootVariables;
            secure_boot_enable_seen = true;
            secure_boot_enabled = std.mem.eql(u8, variable.data, &.{0x01});
        } else if (variable.nameEquals("CustomMode")) {
            if (custom_mode_seen or
                !std.mem.eql(u8, &variable.vendor_guid, &custom_mode_guid) or
                variable.attributes != boot_service_attributes)
                return error.InvalidSecureBootVariables;
            custom_mode_seen = true;
            custom_mode_disabled = std.mem.eql(u8, variable.data, &.{0x00});
        } else if (variable.nameEquals("PK")) {
            if (pk_sha256 != null or
                !std.mem.eql(u8, &variable.vendor_guid, &global_variable_guid) or
                variable.attributes != authenticated_variable_attributes or
                variable.data.len == 0)
                return error.InvalidSecureBootVariables;
            pk_sha256 = sha256Bytes(variable.data);
        } else if (variable.nameEquals("KEK")) {
            if (kek_sha256 != null or
                !std.mem.eql(u8, &variable.vendor_guid, &global_variable_guid) or
                variable.attributes != authenticated_variable_attributes or
                variable.data.len == 0)
                return error.InvalidSecureBootVariables;
            kek_sha256 = sha256Bytes(variable.data);
        } else if (variable.nameEquals("db")) {
            if (db_sha256 != null or
                !std.mem.eql(u8, &variable.vendor_guid, &image_security_database_guid) or
                variable.attributes != authenticated_variable_attributes)
                return error.InvalidSecureBootVariables;
            certificate_matches = countX509Certificates(
                variable.data,
                certificate_sha256,
            ) catch return error.InvalidSecureBootVariables;
            db_sha256 = sha256Bytes(variable.data);
        }
    }

    if (!secure_boot_enabled or
        !custom_mode_disabled or
        pk_sha256 == null or
        kek_sha256 == null or
        db_sha256 == null or
        certificate_matches != 1) return error.InvalidSecureBootVariables;
    return .{
        .pk_sha256 = pk_sha256.?,
        .kek_sha256 = kek_sha256.?,
        .db_sha256 = db_sha256.?,
    };
}

/// Reads `template_path`, appends `certificate_der` to `db`, enables Secure
/// Boot, writes the result atomically to `output_path`, then re-reads and
/// re-validates what actually landed on disk.
pub fn enrollSecureBootFile(
    allocator: Allocator,
    io: Io,
    template_path: []const u8,
    output_path: []const u8,
    certificate_der: []const u8,
) !TrustState {
    var store = try parseFileAlloc(allocator, io, template_path);
    defer store.deinit();
    _ = try enrollSecureBootCertificate(&store, .{ .certificate_der = certificate_der });
    const enrolled = try store.serializeAlloc(allocator);
    defer allocator.free(enrolled);
    try writeAtomic(io, output_path, enrolled);
    return validateSecureBootFile(
        allocator,
        io,
        output_path,
        sha256Bytes(certificate_der),
    );
}

/// Parses `vars_path` and returns its trust state, or fails closed.
pub fn validateSecureBootFile(
    allocator: Allocator,
    io: Io,
    vars_path: []const u8,
    certificate_sha256: Digest,
) !TrustState {
    var store = try parseFileAlloc(allocator, io, vars_path);
    defer store.deinit();
    return validateSecureBootTrust(&store, certificate_sha256);
}

fn writeAtomic(io: Io, destination: []const u8, bytes: []const u8) !void {
    var stage = try Io.Dir.cwd().createFileAtomic(io, destination, .{
        .permissions = privateFilePermissions(),
        .replace = true,
    });
    defer stage.deinit(io);
    try stage.file.writePositionalAll(io, bytes, 0);
    try stage.file.sync(io);
    try stage.replace(io);
}

fn privateFilePermissions() Io.File.Permissions {
    return switch (@import("builtin").os.tag) {
        .windows => .default_file,
        else => .fromMode(0o600),
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// The two variable-store shapes miz must support, taken from the vendor
/// Secure Boot templates: Debian/Ubuntu `OVMF_VARS_4M.ms.fd` (a 528 KiB
/// x86_64 flash image whose whole file is the NV FV) and `AAVMF_VARS.ms.fd`
/// (a 768 KiB AArch64 FV padded out to a 64 MiB pflash image).
const TemplateShape = struct {
    name: []const u8,
    fv_length: u64,
    /// `{ block_count, block_length }`, exactly as the vendor templates.
    block_map: [2]u32,
    store_size: u32,
    file_size: usize,
    /// Erased flash for x86_64, zero padding for the AArch64 pflash image.
    tail_byte: u8,

    const ovmf_4m: TemplateShape = .{
        .name = "OVMF_VARS_4M.ms.fd",
        .fv_length = 0x84000,
        .block_map = .{ 132, 0x1000 },
        .store_size = 0x3ffb8,
        .file_size = 0x84000,
        .tail_byte = 0xff,
    };

    const aavmf: TemplateShape = .{
        .name = "AAVMF_VARS.ms.fd",
        .fv_length = 0xc0000,
        .block_map = .{ 3, 0x40000 },
        .store_size = 0x3ffb8,
        .file_size = 0x4000000,
        .tail_byte = 0x00,
    };

    const all = [_]TemplateShape{ ovmf_4m, aavmf };
};

const TestVariable = struct {
    name: []const u8,
    guid: Guid,
    attributes: u32,
    data: []const u8,
    state: u8 = state_added,
    timestamp: [16]u8 = [_]u8{0} ** 16,
};

fn writeFirmwareVolumeHeader(image: []u8, shape: TemplateShape) void {
    @memset(image[0..16], 0);
    @memcpy(image[16..32], &system_nv_data_fv_guid);
    std.mem.writeInt(u64, image[32..40], shape.fv_length, .little);
    std.mem.writeInt(u32, image[40..44], fv_signature, .little);
    std.mem.writeInt(u32, image[44..48], 0x0004feff, .little);
    std.mem.writeInt(u16, image[48..50], 72, .little);
    std.mem.writeInt(u16, image[50..52], 0, .little);
    std.mem.writeInt(u16, image[52..54], 0, .little);
    image[54] = 0;
    image[55] = fv_revision;
    std.mem.writeInt(u32, image[56..60], shape.block_map[0], .little);
    std.mem.writeInt(u32, image[60..64], shape.block_map[1], .little);
    std.mem.writeInt(u32, image[64..68], 0, .little);
    std.mem.writeInt(u32, image[68..72], 0, .little);

    var sum: u16 = 0;
    var index: usize = 0;
    while (index < 72) : (index += 2) {
        sum +%= std.mem.readInt(u16, image[index..][0..2], .little);
    }
    std.mem.writeInt(u16, image[50..52], 0 -% sum, .little);
}

fn buildTemplateAlloc(
    allocator: Allocator,
    shape: TemplateShape,
    variables: []const TestVariable,
) ![]u8 {
    const image = try allocator.alloc(u8, shape.file_size);
    errdefer allocator.free(image);
    @memset(image[0..@intCast(shape.fv_length)], erased_byte);
    @memset(image[@intCast(shape.fv_length)..], shape.tail_byte);
    writeFirmwareVolumeHeader(image, shape);

    const store_offset: usize = 72;
    @memcpy(image[store_offset..][0..16], &authenticated_variable_store_guid);
    std.mem.writeInt(u32, image[store_offset + 16 ..][0..4], shape.store_size, .little);
    image[store_offset + 20] = store_format_formatted;
    image[store_offset + 21] = store_state_healthy;
    @memset(image[store_offset + 22 ..][0..6], 0);

    var offset = store_offset + store_header_size;
    for (variables) |variable| {
        const name = try encodeNameAlloc(allocator, variable.name);
        defer allocator.free(name);
        // Records written past the declared store end would be invisible to
        // the parser, which would quietly weaken whatever the test asserts.
        const size = alignUp(variable_header_size + name.len + variable.data.len);
        if (offset + size > store_offset + shape.store_size)
            return error.TestStoreTooSmall;
        const record = image[offset..];
        std.mem.writeInt(u16, record[0..2], variable_start_id, .little);
        record[2] = variable.state;
        record[3] = 0;
        std.mem.writeInt(u32, record[4..8], variable.attributes, .little);
        std.mem.writeInt(u64, record[8..16], 0, .little);
        @memcpy(record[16..32], &variable.timestamp);
        std.mem.writeInt(u32, record[32..36], 0, .little);
        std.mem.writeInt(u32, record[36..40], @intCast(name.len), .little);
        std.mem.writeInt(u32, record[40..44], @intCast(variable.data.len), .little);
        @memcpy(record[44..60], &variable.guid);
        @memcpy(record[variable_header_size..][0..name.len], name);
        @memcpy(record[variable_header_size + name.len ..][0..variable.data.len], variable.data);
        offset += size;
    }
    return image;
}

fn x509SignatureListAlloc(
    allocator: Allocator,
    owner: Guid,
    certificate: []const u8,
) ![]u8 {
    const list = try allocator.alloc(u8, 28 + 16 + certificate.len);
    @memcpy(list[0..16], &cert_x509_guid);
    std.mem.writeInt(u32, list[16..20], @intCast(list.len), .little);
    std.mem.writeInt(u32, list[20..24], 0, .little);
    std.mem.writeInt(u32, list[24..28], @intCast(16 + certificate.len), .little);
    @memcpy(list[28..44], &owner);
    @memcpy(list[44..], certificate);
    return list;
}

const test_certificate_pem = @embedFile("testdata/digicert_global_root_ca.crt.pem");
const other_certificate_pem = @embedFile("testdata/fulcio_intermediate_v1.crt.pem");

fn testCertificateDerAlloc(allocator: Allocator, pem: []const u8) ![]u8 {
    return authenticode.decodePemCertificateAlloc(allocator, pem);
}

fn microsoftTemplateAlloc(
    allocator: Allocator,
    shape: TemplateShape,
) ![]u8 {
    const microsoft_leaf = try x509SignatureListAlloc(
        allocator,
        global_variable_guid,
        "microsoft db certificate",
    );
    defer allocator.free(microsoft_leaf);
    return buildTemplateAlloc(allocator, shape, &.{
        .{
            .name = "KEK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "microsoft kek",
            .timestamp = [_]u8{ 0xe7, 0x07, 0x03, 0x02, 0x14, 0x15, 0x23, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        },
        .{
            .name = "PK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "microsoft pk",
        },
        .{
            .name = "db",
            .guid = image_security_database_guid,
            .attributes = authenticated_variable_attributes,
            .data = microsoft_leaf,
        },
        .{
            .name = "dbx",
            .guid = image_security_database_guid,
            .attributes = authenticated_variable_attributes,
            .data = "microsoft dbx",
        },
    });
}

test "both template shapes parse with their exact volume and store geometry" {
    const allocator = testing.allocator;
    for (TemplateShape.all) |shape| {
        const image = try microsoftTemplateAlloc(allocator, shape);
        var store = try parse(allocator, image);
        defer store.deinit();

        try testing.expectEqual(shape.fv_length, store.fv_length);
        try testing.expectEqual(@as(u16, 72), store.fv_header_length);
        try testing.expectEqual(@as(usize, 72), store.store_offset);
        try testing.expectEqual(shape.store_size, store.store_size);
        try testing.expectEqual(@as(usize, 100), store.data_offset);
        try testing.expectEqual(@as(usize, 72 + shape.store_size), store.data_end);
        try testing.expectEqual(@as(usize, 4), store.variables.items.len);
        try testing.expectEqual(@as(usize, 0), store.reclaimed_records);
        try testing.expect(store.find("PK", global_variable_guid) != null);
        try testing.expect(store.find("KEK", global_variable_guid) != null);
        try testing.expect(store.find("db", image_security_database_guid) != null);
        try testing.expect(store.find("db", global_variable_guid) == null);
    }
}

test "round-tripping an untouched template reproduces it byte for byte" {
    const allocator = testing.allocator;
    for (TemplateShape.all) |shape| {
        const image = try microsoftTemplateAlloc(allocator, shape);
        const original = try allocator.dupe(u8, image);
        defer allocator.free(original);
        var store = try parse(allocator, image);
        defer store.deinit();
        const rendered = try store.serializeAlloc(allocator);
        defer allocator.free(rendered);
        try testing.expectEqualSlices(u8, original, rendered);
    }
}

test "enrollment appends one leaf, enables Secure Boot and preserves the rest" {
    const allocator = testing.allocator;
    const certificate = try testCertificateDerAlloc(allocator, test_certificate_pem);
    defer allocator.free(certificate);
    const digest = sha256Bytes(certificate);

    for (TemplateShape.all) |shape| {
        const image = try microsoftTemplateAlloc(allocator, shape);
        const original = try allocator.dupe(u8, image);
        defer allocator.free(original);
        var store = try parse(allocator, image);
        defer store.deinit();

        const pk_before = try allocator.dupe(
            u8,
            store.find("PK", global_variable_guid).?.data,
        );
        defer allocator.free(pk_before);
        const db_before = try allocator.dupe(
            u8,
            store.find("db", image_security_database_guid).?.data,
        );
        defer allocator.free(db_before);
        const db_timestamp_before =
            store.find("db", image_security_database_guid).?.timestamp;

        const outcome = try enrollSecureBootCertificate(&store, .{
            .certificate_der = certificate,
        });
        try testing.expect(outcome.appended);

        // PK, KEK and dbx are untouched; db only grows by one signature list.
        try testing.expectEqualSlices(
            u8,
            pk_before,
            store.find("PK", global_variable_guid).?.data,
        );
        const database = store.find("db", image_security_database_guid).?;
        try testing.expectEqual(db_timestamp_before, database.timestamp);
        try testing.expectEqualSlices(u8, db_before, database.data[0..db_before.len]);
        try testing.expectEqual(
            db_before.len + 28 + 16 + certificate.len,
            database.data.len,
        );
        try testing.expectEqual(
            @as(usize, 1),
            try countX509Certificates(database.data, digest),
        );
        try testing.expectEqualSlices(
            u8,
            &release_signature_owner_guid,
            database.data[db_before.len + 28 ..][0..16],
        );
        try testing.expectEqual(
            authenticated_variable_attributes,
            database.attributes,
        );

        const enable = store.find("SecureBootEnable", secure_boot_enable_guid).?;
        try testing.expectEqualSlices(u8, &.{0x01}, enable.data);
        try testing.expectEqual(boot_service_attributes, enable.attributes);
        const custom_mode = store.find("CustomMode", custom_mode_guid).?;
        try testing.expectEqualSlices(u8, &.{0x00}, custom_mode.data);
        try testing.expectEqual(boot_service_attributes, custom_mode.attributes);

        const trust = try validateSecureBootTrust(&store, digest);
        try testing.expectEqual(
            sha256Bytes(pk_before),
            trust.pk_sha256,
        );

        const rendered = try store.serializeAlloc(allocator);
        defer allocator.free(rendered);
        try testing.expectEqual(original.len, rendered.len);
        // The firmware volume header, store header and everything past the
        // variable region survive verbatim.
        try testing.expectEqualSlices(u8, original[0..100], rendered[0..100]);
        try testing.expectEqualSlices(
            u8,
            original[store.data_end..],
            rendered[store.data_end..],
        );
        try testing.expect(verifyFirmwareVolumeChecksum(rendered[0..72]));

        var reparsed = try parse(allocator, try allocator.dupe(u8, rendered));
        defer reparsed.deinit();
        const reparsed_trust = try validateSecureBootTrust(&reparsed, digest);
        try testing.expect(reparsed_trust.eql(trust));
        try testing.expectEqual(@as(usize, 6), reparsed.variables.items.len);
        // Existing variables keep their original relative order.
        try testing.expect(reparsed.variables.items[0].nameEquals("KEK"));
        try testing.expect(reparsed.variables.items[1].nameEquals("PK"));
        try testing.expect(reparsed.variables.items[2].nameEquals("db"));
        try testing.expect(reparsed.variables.items[3].nameEquals("dbx"));
        try testing.expect(reparsed.variables.items[4].nameEquals("SecureBootEnable"));
        try testing.expect(reparsed.variables.items[5].nameEquals("CustomMode"));
    }
    // Serialization keeps every record 4-byte aligned even with odd-length
    // names and data.
    const image = try buildTemplateAlloc(allocator, TemplateShape.ovmf_4m, &.{
        .{
            .name = "Odd",
            .guid = global_variable_guid,
            .attributes = boot_service_attributes,
            .data = "abcde",
        },
        .{
            .name = "Second",
            .guid = global_variable_guid,
            .attributes = boot_service_attributes,
            .data = "x",
        },
    });
    var store = try parse(allocator, image);
    defer store.deinit();
    try testing.expectEqual(@as(usize, 2), store.variables.items.len);
    try testing.expectEqual(alignUp(60 + 8 + 5), store.variables.items[0].encodedSize());
    const rendered = try store.serializeAlloc(allocator);
    defer allocator.free(rendered);
    const second_offset = store.data_offset + store.variables.items[0].encodedSize();
    try testing.expectEqual(@as(usize, 0), second_offset % 4);
    try testing.expectEqual(
        variable_start_id,
        std.mem.readInt(u16, rendered[second_offset..][0..2], .little),
    );
    try testing.expectEqual(
        erased_byte,
        rendered[store.data_offset + store.usedBytes()],
    );
}

test "enrollment is idempotent and never duplicates the release leaf" {
    const allocator = testing.allocator;
    const certificate = try testCertificateDerAlloc(allocator, test_certificate_pem);
    defer allocator.free(certificate);
    const digest = sha256Bytes(certificate);

    const image = try microsoftTemplateAlloc(allocator, TemplateShape.ovmf_4m);
    var store = try parse(allocator, image);
    defer store.deinit();
    _ = try enrollSecureBootCertificate(&store, .{ .certificate_der = certificate });
    const once = try allocator.dupe(
        u8,
        store.find("db", image_security_database_guid).?.data,
    );
    defer allocator.free(once);

    const second = try enrollSecureBootCertificate(&store, .{
        .certificate_der = certificate,
    });
    try testing.expect(!second.appended);
    try testing.expectEqualSlices(
        u8,
        once,
        store.find("db", image_security_database_guid).?.data,
    );
    try testing.expectEqual(
        @as(usize, 1),
        try countX509Certificates(once, digest),
    );
    _ = try validateSecureBootTrust(&store, digest);
}

test "a db that already carries two copies of the leaf fails validation" {
    const allocator = testing.allocator;
    const certificate = try testCertificateDerAlloc(allocator, test_certificate_pem);
    defer allocator.free(certificate);
    const digest = sha256Bytes(certificate);

    const first = try x509SignatureListAlloc(
        allocator,
        release_signature_owner_guid,
        certificate,
    );
    defer allocator.free(first);
    const second = try x509SignatureListAlloc(
        allocator,
        release_signature_owner_guid,
        certificate,
    );
    defer allocator.free(second);
    const database = try std.mem.concat(allocator, u8, &.{ first, second });
    defer allocator.free(database);
    try testing.expectEqual(
        @as(usize, 2),
        try countX509Certificates(database, digest),
    );

    const image = try buildTemplateAlloc(allocator, TemplateShape.ovmf_4m, &.{
        .{
            .name = "PK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "pk",
        },
        .{
            .name = "KEK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "kek",
        },
        .{
            .name = "db",
            .guid = image_security_database_guid,
            .attributes = authenticated_variable_attributes,
            .data = database,
        },
    });
    var store = try parse(allocator, image);
    defer store.deinit();
    const outcome = try enrollSecureBootCertificate(&store, .{
        .certificate_der = certificate,
    });
    try testing.expect(!outcome.appended);
    try testing.expectError(
        error.InvalidSecureBootVariables,
        validateSecureBootTrust(&store, digest),
    );
}

test "enrollment refuses templates without Microsoft trust material" {
    const allocator = testing.allocator;
    const certificate = try testCertificateDerAlloc(allocator, test_certificate_pem);
    defer allocator.free(certificate);

    const cases = [_]struct {
        variables: []const TestVariable,
        expected: anyerror,
    }{
        .{ .variables = &.{}, .expected = error.MissingPlatformKey },
        .{
            .variables = &.{.{
                .name = "PK",
                .guid = global_variable_guid,
                .attributes = authenticated_variable_attributes,
                .data = "pk",
            }},
            .expected = error.MissingKeyExchangeKey,
        },
        .{
            .variables = &.{
                .{
                    .name = "PK",
                    .guid = global_variable_guid,
                    .attributes = authenticated_variable_attributes,
                    .data = "pk",
                },
                .{
                    .name = "KEK",
                    .guid = global_variable_guid,
                    .attributes = authenticated_variable_attributes,
                    .data = "kek",
                },
            },
            .expected = error.MissingSignatureDatabase,
        },
        .{
            .variables = &.{
                .{
                    .name = "PK",
                    .guid = global_variable_guid,
                    .attributes = authenticated_variable_attributes,
                    .data = "pk",
                },
                .{
                    .name = "KEK",
                    .guid = global_variable_guid,
                    .attributes = authenticated_variable_attributes,
                    .data = "kek",
                },
                .{
                    .name = "db",
                    .guid = image_security_database_guid,
                    .attributes = attribute_non_volatile | attribute_bootservice_access,
                    .data = "",
                },
            },
            .expected = error.UnauthenticatedSignatureDatabase,
        },
    };

    for (cases) |case| {
        const image = try buildTemplateAlloc(
            allocator,
            TemplateShape.ovmf_4m,
            case.variables,
        );
        var store = try parse(allocator, image);
        defer store.deinit();
        try testing.expectError(
            case.expected,
            enrollSecureBootCertificate(&store, .{ .certificate_der = certificate }),
        );
    }
}

test "enrollment refuses anything that is not a DER X.509 certificate" {
    const allocator = testing.allocator;
    const image = try microsoftTemplateAlloc(allocator, TemplateShape.ovmf_4m);
    var store = try parse(allocator, image);
    defer store.deinit();
    for ([_][]const u8{ "", "not a certificate", &.{ 0x30, 0x82, 0xff, 0xff } }) |bogus| {
        try testing.expectError(
            error.InvalidCertificate,
            enrollSecureBootCertificate(&store, .{ .certificate_der = bogus }),
        );
    }
}

test "capacity exhaustion fails closed instead of overrunning the store" {
    const allocator = testing.allocator;
    const certificate = try testCertificateDerAlloc(allocator, test_certificate_pem);
    defer allocator.free(certificate);

    const shape = TemplateShape.ovmf_4m;
    const store_capacity = shape.store_size - store_header_size;
    const boot_variables =
        alignUp(variable_header_size + "SecureBootEnable".len * 2 + 2 + 1) +
        alignUp(variable_header_size + "CustomMode".len * 2 + 2 + 1);
    const appended_list = 28 + 16 + certificate.len;

    const microsoft_leaf = try x509SignatureListAlloc(
        allocator,
        global_variable_guid,
        "microsoft db certificate",
    );
    defer allocator.free(microsoft_leaf);
    const fixed =
        alignUp(variable_header_size + "PK".len * 2 + 2 + 2) +
        alignUp(variable_header_size + "KEK".len * 2 + 2 + 3) +
        alignUp(variable_header_size + "db".len * 2 + 2 + microsoft_leaf.len);

    // Size the filler so the enrolled store overshoots the variable region by
    // between one and four bytes: the tightest boundary the alignment allows.
    const filler_record = alignUp(
        store_capacity - fixed - boot_variables - appended_list + 1,
    );
    const filler_header = variable_header_size + "Filler".len * 2 + 2;
    const filler = try allocator.alloc(u8, filler_record - filler_header);
    defer allocator.free(filler);
    @memset(filler, 'F');

    const variables = [_]TestVariable{
        .{
            .name = "PK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "pk",
        },
        .{
            .name = "KEK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "kek",
        },
        .{
            .name = "db",
            .guid = image_security_database_guid,
            .attributes = authenticated_variable_attributes,
            .data = microsoft_leaf,
        },
        .{
            .name = "Filler",
            .guid = global_variable_guid,
            .attributes = boot_service_attributes,
            .data = filler,
        },
    };

    const image = try buildTemplateAlloc(allocator, shape, &variables);
    var store = try parse(allocator, image);
    defer store.deinit();
    try testing.expectEqual(fixed + filler_record, store.usedBytes());
    const enrolled_bytes = store.usedBytes() + boot_variables + appended_list;
    try testing.expect(enrolled_bytes > store.capacity());
    try testing.expect(enrolled_bytes <= store.capacity() + header_alignment);
    try testing.expectError(
        error.VariableStoreFull,
        enrollSecureBootCertificate(&store, .{ .certificate_der = certificate }),
    );
    // The refusal is not merely advisory: rendering the oversized set is
    // refused too, so nothing can write past the variable region.
    try testing.expectError(
        error.VariableStoreFull,
        store.serializeAlloc(allocator),
    );

    // Reclaiming one aligned record's worth of space is enough for exactly
    // the same enrollment to succeed.
    const roomy = try buildTemplateAlloc(allocator, shape, &.{
        variables[0],
        variables[1],
        variables[2],
        .{
            .name = "Filler",
            .guid = global_variable_guid,
            .attributes = boot_service_attributes,
            .data = filler[0 .. filler.len - header_alignment],
        },
    });
    var roomy_store = try parse(allocator, roomy);
    defer roomy_store.deinit();
    _ = try enrollSecureBootCertificate(&roomy_store, .{
        .certificate_der = certificate,
    });
    try testing.expect(roomy_store.usedBytes() <= roomy_store.capacity());
    try testing.expect(
        roomy_store.capacity() - roomy_store.usedBytes() < 2 * header_alignment,
    );
    const rendered = try roomy_store.serializeAlloc(allocator);
    defer allocator.free(rendered);
    var reparsed = try parse(allocator, try allocator.dupe(u8, rendered));
    defer reparsed.deinit();
    _ = try validateSecureBootTrust(&reparsed, sha256Bytes(certificate));
}

test "deleted, superseded and interrupted records are reclaimed" {
    const allocator = testing.allocator;
    const image = try buildTemplateAlloc(allocator, TemplateShape.aavmf, &.{
        .{
            .name = "Deleted",
            .guid = global_variable_guid,
            .attributes = boot_service_attributes,
            .data = "gone",
            .state = state_deleted,
        },
        .{
            .name = "Interrupted",
            .guid = global_variable_guid,
            .attributes = boot_service_attributes,
            .data = "half written",
            .state = state_header_valid_only,
        },
        .{
            .name = "Kept",
            .guid = global_variable_guid,
            .attributes = boot_service_attributes,
            .data = "old value",
            .state = state_in_deleted_transition,
        },
        .{
            .name = "Kept",
            .guid = global_variable_guid,
            .attributes = boot_service_attributes,
            .data = "new value",
            .state = state_added,
        },
        .{
            .name = "Transitional",
            .guid = global_variable_guid,
            .attributes = boot_service_attributes,
            .data = "only copy",
            .state = state_in_deleted_transition,
        },
        .{
            .name = "AfterTransition",
            .guid = global_variable_guid,
            .attributes = boot_service_attributes,
            .data = "gone too",
            .state = state_deleted_after_transition,
        },
    });
    var store = try parse(allocator, image);
    defer store.deinit();

    try testing.expectEqual(@as(usize, 2), store.variables.items.len);
    try testing.expectEqual(@as(usize, 4), store.reclaimed_records);
    try testing.expect(store.find("Deleted", global_variable_guid) == null);
    try testing.expect(store.find("Interrupted", global_variable_guid) == null);
    try testing.expect(store.find("AfterTransition", global_variable_guid) == null);
    try testing.expectEqualSlices(
        u8,
        "new value",
        store.find("Kept", global_variable_guid).?.data,
    );
    // An in-deleted-transition record with no completed replacement is the
    // live value, exactly as EDK II's reclaim treats it.
    try testing.expectEqualSlices(
        u8,
        "only copy",
        store.find("Transitional", global_variable_guid).?.data,
    );

    const rendered = try store.serializeAlloc(allocator);
    defer allocator.free(rendered);
    var reparsed = try parse(allocator, try allocator.dupe(u8, rendered));
    defer reparsed.deinit();
    try testing.expectEqual(@as(usize, 2), reparsed.variables.items.len);
    try testing.expectEqual(@as(usize, 0), reparsed.reclaimed_records);
    try testing.expectEqual(state_added, rendered[reparsed.data_offset + 2]);
}

test "duplicate complete records are refused, not silently resolved" {
    const allocator = testing.allocator;
    const duplicated = [_]TestVariable{
        .{
            .name = "Rewritten",
            .guid = global_variable_guid,
            .attributes = boot_service_attributes,
            .data = "first",
            .state = state_added,
        },
        .{
            .name = "Rewritten",
            .guid = global_variable_guid,
            .attributes = boot_service_attributes,
            .data = "second",
            .state = state_added,
        },
    };
    // EDK II would boot with "first"; a last-wins parser would report
    // "second". Neither guess is safe, so the store is refused outright.
    const image = try buildTemplateAlloc(
        allocator,
        TemplateShape.ovmf_4m,
        &duplicated,
    );
    defer allocator.free(image);
    try testing.expectError(
        error.DuplicateVariableRecord,
        parse(allocator, image),
    );

    // A third copy is no more acceptable than a second.
    const tripled = duplicated ++ [_]TestVariable{.{
        .name = "Rewritten",
        .guid = global_variable_guid,
        .attributes = boot_service_attributes,
        .data = "third",
        .state = state_added,
    }};
    const tripled_image = try buildTemplateAlloc(
        allocator,
        TemplateShape.ovmf_4m,
        &tripled,
    );
    defer allocator.free(tripled_image);
    try testing.expectError(
        error.DuplicateVariableRecord,
        parse(allocator, tripled_image),
    );

    // Duplicate PK is the case that matters: miz must not certify a store
    // whose platform key the firmware would resolve differently.
    const duplicate_pk = try buildTemplateAlloc(allocator, TemplateShape.aavmf, &.{
        .{
            .name = "PK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "attacker platform key",
        },
        .{
            .name = "KEK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "kek",
        },
        .{
            .name = "PK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "benign platform key",
        },
    });
    defer allocator.free(duplicate_pk);
    try testing.expectError(
        error.DuplicateVariableRecord,
        parse(allocator, duplicate_pk),
    );

    // The same name under a different vendor GUID is a different variable.
    const distinct = try buildTemplateAlloc(allocator, TemplateShape.ovmf_4m, &.{
        duplicated[0],
        .{
            .name = "Rewritten",
            .guid = image_security_database_guid,
            .attributes = boot_service_attributes,
            .data = "other namespace",
            .state = state_added,
        },
    });
    var store = try parse(allocator, distinct);
    defer store.deinit();
    try testing.expectEqual(@as(usize, 2), store.variables.items.len);
    try testing.expectEqual(@as(usize, 0), store.reclaimed_records);
    try testing.expectEqualSlices(
        u8,
        "first",
        store.find("Rewritten", global_variable_guid).?.data,
    );
    try testing.expectEqualSlices(
        u8,
        "other namespace",
        store.find("Rewritten", image_security_database_guid).?.data,
    );
}

test "in-deleted-transition records resolve exactly as EDK II resolves them" {
    const allocator = testing.allocator;
    const Case = struct {
        label: []const u8,
        variables: []const TestVariable,
        expected: []const u8,
        reclaimed: usize,
    };
    const cases = [_]Case{
        // A complete record wins over an interrupted deletion regardless of
        // which one the walk reaches first.
        .{
            .label = "transition before added",
            .variables = &.{
                .{
                    .name = "Var",
                    .guid = global_variable_guid,
                    .attributes = boot_service_attributes,
                    .data = "being deleted",
                    .state = state_in_deleted_transition,
                },
                .{
                    .name = "Var",
                    .guid = global_variable_guid,
                    .attributes = boot_service_attributes,
                    .data = "complete",
                    .state = state_added,
                },
            },
            .expected = "complete",
            .reclaimed = 1,
        },
        .{
            .label = "added before transition",
            .variables = &.{
                .{
                    .name = "Var",
                    .guid = global_variable_guid,
                    .attributes = boot_service_attributes,
                    .data = "complete",
                    .state = state_added,
                },
                .{
                    .name = "Var",
                    .guid = global_variable_guid,
                    .attributes = boot_service_attributes,
                    .data = "being deleted",
                    .state = state_in_deleted_transition,
                },
            },
            .expected = "complete",
            .reclaimed = 1,
        },
        // With no complete record, EDK II keeps the last in-deleted-transition
        // one it walks past.
        .{
            .label = "only transitions",
            .variables = &.{
                .{
                    .name = "Var",
                    .guid = global_variable_guid,
                    .attributes = boot_service_attributes,
                    .data = "older",
                    .state = state_in_deleted_transition,
                },
                .{
                    .name = "Var",
                    .guid = global_variable_guid,
                    .attributes = boot_service_attributes,
                    .data = "newer",
                    .state = state_in_deleted_transition,
                },
            },
            .expected = "newer",
            .reclaimed = 1,
        },
        .{
            .label = "single transition",
            .variables = &.{.{
                .name = "Var",
                .guid = global_variable_guid,
                .attributes = boot_service_attributes,
                .data = "only copy",
                .state = state_in_deleted_transition,
            }},
            .expected = "only copy",
            .reclaimed = 0,
        },
    };

    for (cases) |case| {
        const image = try buildTemplateAlloc(
            allocator,
            TemplateShape.ovmf_4m,
            case.variables,
        );
        var store = try parse(allocator, image);
        defer store.deinit();
        testing.expectEqual(@as(usize, 1), store.variables.items.len) catch |err| {
            std.debug.print("case '{s}' resolved wrongly\n", .{case.label});
            return err;
        };
        testing.expectEqualSlices(
            u8,
            case.expected,
            store.find("Var", global_variable_guid).?.data,
        ) catch |err| {
            std.debug.print("case '{s}' resolved wrongly\n", .{case.label});
            return err;
        };
        try testing.expectEqual(case.reclaimed, store.reclaimed_records);

        // Re-serializing writes the winner as the one complete record, so a
        // second pass has nothing left to resolve.
        const rendered = try store.serializeAlloc(allocator);
        defer allocator.free(rendered);
        var reparsed = try parse(allocator, try allocator.dupe(u8, rendered));
        defer reparsed.deinit();
        try testing.expectEqual(@as(usize, 1), reparsed.variables.items.len);
        try testing.expectEqual(@as(usize, 0), reparsed.reclaimed_records);
        try testing.expectEqualSlices(
            u8,
            case.expected,
            reparsed.find("Var", global_variable_guid).?.data,
        );
    }
}

test "malformed firmware volumes and stores are rejected" {
    const allocator = testing.allocator;
    const Mutation = struct {
        label: []const u8,
        offset: usize,
        bytes: []const u8,
        expected: anyerror,
        /// Header mutations get a fresh checksum so each one fails on its own
        /// merits; the checksum case itself deliberately keeps a stale one.
        repair_checksum: bool = true,
    };
    const mutations = [_]Mutation{
        .{
            .label = "bad FV signature",
            .offset = 40,
            .bytes = &.{ 'X', 'F', 'V', 'H' },
            .expected = error.InvalidFirmwareVolume,
        },
        .{
            .label = "bad FV revision",
            .offset = 55,
            .bytes = &.{1},
            .expected = error.InvalidFirmwareVolume,
        },
        .{
            .label = "extended header offset",
            .offset = 52,
            .bytes = &.{ 0x40, 0x00 },
            .expected = error.InvalidFirmwareVolume,
        },
        .{
            .label = "corrupt header checksum",
            .offset = 50,
            .bytes = &.{ 0x00, 0x00 },
            .expected = error.InvalidFirmwareVolume,
            .repair_checksum = false,
        },
        .{
            .label = "block map does not cover the volume",
            .offset = 56,
            .bytes = &.{ 0x01, 0x00, 0x00, 0x00 },
            .expected = error.InvalidFirmwareVolume,
        },
        .{
            .label = "unauthenticated store format",
            .offset = 72,
            .bytes = &plain_variable_store_guid,
            .expected = error.UnsupportedVariableStoreFormat,
        },
        .{
            .label = "unhealthy store state",
            .offset = 72 + 21,
            .bytes = &.{0x00},
            .expected = error.UnsupportedVariableStoreFormat,
        },
        .{
            .label = "store larger than the volume",
            .offset = 72 + 16,
            .bytes = &.{ 0x00, 0x00, 0xf0, 0x00 },
            .expected = error.InvalidVariableStoreHeader,
        },
        .{
            .label = "unknown variable start id",
            .offset = 100,
            .bytes = &.{ 0x5a, 0xa5 },
            .expected = error.MalformedVariableStore,
        },
        .{
            .label = "unknown variable state",
            .offset = 100 + 2,
            .bytes = &.{0x11},
            .expected = error.MalformedVariableStore,
        },
        .{
            .label = "odd name size",
            .offset = 100 + 36,
            .bytes = &.{ 0x07, 0x00, 0x00, 0x00 },
            .expected = error.MalformedVariableStore,
        },
        .{
            .label = "zero name size",
            .offset = 100 + 36,
            .bytes = &.{ 0x00, 0x00, 0x00, 0x00 },
            .expected = error.MalformedVariableStore,
        },
        .{
            .label = "unterminated variable name",
            .offset = 100 + 60 + 6,
            .bytes = &.{ 0x41, 0x00 },
            .expected = error.MalformedVariableStore,
        },
        .{
            .label = "data size past the end of the store",
            .offset = 100 + 40,
            .bytes = &.{ 0x00, 0x00, 0x30, 0x00 },
            .expected = error.TruncatedVariableStore,
        },
        .{
            .label = "absurd data size",
            .offset = 100 + 40,
            .bytes = &.{ 0x00, 0x00, 0x00, 0x40 },
            .expected = error.MalformedVariableStore,
        },
    };

    for (mutations) |mutation| {
        const image = try buildTemplateAlloc(allocator, TemplateShape.ovmf_4m, &.{
            .{
                .name = "KEK",
                .guid = global_variable_guid,
                .attributes = authenticated_variable_attributes,
                .data = "microsoft kek",
            },
        });
        // A rejected parse hands `image` back, so the test still owns it.
        defer allocator.free(image);
        @memcpy(image[mutation.offset..][0..mutation.bytes.len], mutation.bytes);
        if (mutation.repair_checksum and mutation.offset < 72)
            writeChecksumOnly(image);
        testing.expectError(mutation.expected, parse(allocator, image)) catch |err| {
            std.debug.print("mutation '{s}' did not fail as expected\n", .{mutation.label});
            return err;
        };
    }

    // Not a firmware volume at all.
    const empty = try allocator.alloc(u8, 4096);
    defer allocator.free(empty);
    @memset(empty, 0);
    try testing.expectError(error.VariableStoreNotFound, parse(allocator, empty));
    const tiny = try allocator.alloc(u8, 8);
    defer allocator.free(tiny);
    try testing.expectError(error.VariableStoreNotFound, parse(allocator, tiny));
}

/// Wraps `volume` at `offset` behind `prefix`, the shape a container image
/// gives a raw firmware volume it stores as payload.
fn embedVolumeAlloc(
    allocator: Allocator,
    prefix: []const u8,
    offset: usize,
    volume: []const u8,
) ![]u8 {
    std.debug.assert(prefix.len <= offset);
    const image = try allocator.alloc(u8, offset + volume.len);
    @memset(image, 0);
    @memcpy(image[0..prefix.len], prefix);
    @memcpy(image[offset..], volume);
    return image;
}

test "a firmware volume that is not at offset 0 is refused" {
    const allocator = testing.allocator;
    const volume = try microsoftTemplateAlloc(allocator, TemplateShape.ovmf_4m);
    defer allocator.free(volume);
    // Sanity: the same bytes parse when they are the whole image.
    {
        var store = try parse(allocator, try allocator.dupe(u8, volume));
        defer store.deinit();
        try testing.expect(store.find("PK", global_variable_guid) != null);
    }

    // A QCOW2 vars template is the case that matters. `miz qemu` passes the
    // variable store to QEMU as `format=raw` pflash, so a store enrolled at
    // a cluster offset inside a QCOW2 file would be one the firmware never
    // maps: miz would enroll and then self-validate invisible bytes.
    const qcow2_header =
        "QFI\xfb" ++ // magic
        "\x00\x00\x00\x03" ++ // version 3
        "\x00" ** 8 ++ // backing file offset
        "\x00" ** 4 ++ // backing file size
        "\x00\x00\x00\x0c"; // cluster_bits = 12 (4 KiB clusters)
    const qcow2 = try embedVolumeAlloc(allocator, qcow2_header, 0x1000, volume);
    defer allocator.free(qcow2);
    try testing.expectError(
        error.UnsupportedVariableStoreContainer,
        parse(allocator, qcow2),
    );

    // Every container magic is refused with the same specific error, at
    // whichever offset the format puts it.
    for (container_formats) |container| {
        const prefix = try allocator.alloc(u8, container.offset + container.magic.len);
        defer allocator.free(prefix);
        @memset(prefix, 0);
        @memcpy(prefix[container.offset..], container.magic);
        const image = try embedVolumeAlloc(allocator, prefix, 0x1000, volume);
        defer allocator.free(image);
        testing.expectError(
            error.UnsupportedVariableStoreContainer,
            parse(allocator, image),
        ) catch |err| {
            std.debug.print("container '{s}' was not refused\n", .{container.name});
            return err;
        };
    }

    // A container miz does not recognize must not fall through to a scan
    // either: the volume simply is not where a raw flash image keeps it.
    for ([_]usize{ 1024, 0x1000, 0x10000 }) |offset| {
        const image = try embedVolumeAlloc(allocator, "", offset, volume);
        defer allocator.free(image);
        try testing.expectError(
            error.VariableStoreNotFound,
            parse(allocator, image),
        );
    }

    // Neither does a leading EDK II code volume: `miz qemu` maps the code
    // and vars volumes as separate pflash units, so a combined image is not
    // a variable store miz may edit.
    const ffs_prefix =
        "\x00" ** 16 ++
        "\x78\xe5\x8c\x8c\x3d\x8a\x1c\x4f\x99\x35\x89\x61\x85\xc3\x2d\xd3";
    const combined = try embedVolumeAlloc(allocator, ffs_prefix, 0x1000, volume);
    defer allocator.free(combined);
    try testing.expectError(
        error.VariableStoreNotFound,
        parse(allocator, combined),
    );
}

test "a rejected parse leaves the caller owning its buffer" {
    const allocator = testing.allocator;
    const image = try buildTemplateAlloc(allocator, TemplateShape.ovmf_4m, &.{
        .{
            .name = "KEK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "microsoft kek",
        },
        .{
            .name = "PK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "microsoft pk",
        },
    });
    defer allocator.free(image);
    const original = try allocator.dupe(u8, image);
    defer allocator.free(original);

    // Corrupt the second record so the walk fails only after the first one
    // has already been copied out: the partial variable list is released and
    // the caller's buffer is not.
    const second = 100 + alignUp(variable_header_size + 8 + "microsoft kek".len);
    image[second + 2] = 0x11;
    try testing.expectError(
        error.MalformedVariableStore,
        parse(allocator, image),
    );
    // The buffer is untouched and still the caller's, so it can be repaired
    // and handed to a parse that does take ownership.
    try testing.expectEqualSlices(u8, original[0..second], image[0..second]);
    @memcpy(image, original);
    var store = try parse(allocator, try allocator.dupe(u8, image));
    defer store.deinit();
    try testing.expectEqual(@as(usize, 2), store.variables.items.len);
}

/// Recomputes only the volume header checksum, so header mutations are
/// rejected on their own merits rather than as checksum failures.
fn writeChecksumOnly(image: []u8) void {
    std.mem.writeInt(u16, image[50..52], 0, .little);
    var sum: u16 = 0;
    var index: usize = 0;
    while (index < 72) : (index += 2) {
        sum +%= std.mem.readInt(u16, image[index..][0..2], .little);
    }
    std.mem.writeInt(u16, image[50..52], 0 -% sum, .little);
}

test "malformed signature databases are rejected instead of silently counted" {
    const allocator = testing.allocator;
    const certificate = "DER certificate";
    const digest = sha256Bytes(certificate);
    const valid = try x509SignatureListAlloc(
        allocator,
        release_signature_owner_guid,
        certificate,
    );
    defer allocator.free(valid);
    try testing.expectEqual(
        @as(usize, 1),
        try countX509Certificates(valid, digest),
    );
    try testing.expectEqual(
        @as(usize, 0),
        try countX509Certificates(valid, [_]u8{0xff} ** 32),
    );
    try testing.expectEqual(@as(usize, 0), try countX509Certificates("", digest));

    // A non-X.509 signature list holding the same bytes must not count.
    const wrong_type = try allocator.dupe(u8, valid);
    defer allocator.free(wrong_type);
    @memset(wrong_type[0..16], 0);
    try testing.expectEqual(
        @as(usize, 0),
        try countX509Certificates(wrong_type, digest),
    );

    try testing.expectError(
        error.InvalidSignatureDatabase,
        countX509Certificates(valid[0 .. valid.len - 1], digest),
    );
    try testing.expectError(
        error.InvalidSignatureDatabase,
        countX509Certificates(valid[0..20], digest),
    );

    const short_list = try allocator.dupe(u8, valid);
    defer allocator.free(short_list);
    std.mem.writeInt(u32, short_list[16..20], 27, .little);
    try testing.expectError(
        error.InvalidSignatureDatabase,
        countX509Certificates(short_list, digest),
    );

    const tiny_signature = try allocator.dupe(u8, valid);
    defer allocator.free(tiny_signature);
    std.mem.writeInt(u32, tiny_signature[24..28], 16, .little);
    try testing.expectError(
        error.InvalidSignatureDatabase,
        countX509Certificates(tiny_signature, digest),
    );

    const ragged = try allocator.dupe(u8, valid);
    defer allocator.free(ragged);
    std.mem.writeInt(u32, ragged[24..28], @intCast(15 + certificate.len), .little);
    try testing.expectError(
        error.InvalidSignatureDatabase,
        countX509Certificates(ragged, digest),
    );

    const huge_header = try allocator.dupe(u8, valid);
    defer allocator.free(huge_header);
    std.mem.writeInt(u32, huge_header[20..24], 0xffff_fff0, .little);
    try testing.expectError(
        error.InvalidSignatureDatabase,
        countX509Certificates(huge_header, digest),
    );
}

test "trust validation demands the exact enforcing Secure Boot state" {
    const allocator = testing.allocator;
    const certificate = "DER certificate";
    const digest = sha256Bytes(certificate);
    const database = try x509SignatureListAlloc(
        allocator,
        release_signature_owner_guid,
        certificate,
    );
    defer allocator.free(database);

    const enrolled = [_]TestVariable{
        .{
            .name = "SecureBootEnable",
            .guid = secure_boot_enable_guid,
            .attributes = boot_service_attributes,
            .data = &.{0x01},
        },
        .{
            .name = "CustomMode",
            .guid = custom_mode_guid,
            .attributes = boot_service_attributes,
            .data = &.{0x00},
        },
        .{
            .name = "PK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "pk",
        },
        .{
            .name = "KEK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "kek",
        },
        .{
            .name = "db",
            .guid = image_security_database_guid,
            .attributes = authenticated_variable_attributes,
            .data = database,
        },
    };

    {
        const image = try buildTemplateAlloc(allocator, TemplateShape.ovmf_4m, &enrolled);
        var store = try parse(allocator, image);
        defer store.deinit();
        const trust = try validateSecureBootTrust(&store, digest);
        try testing.expectEqual(sha256Bytes("pk"), trust.pk_sha256);
        try testing.expectEqual(sha256Bytes("kek"), trust.kek_sha256);
        try testing.expectEqual(sha256Bytes(database), trust.db_sha256);
        var changed = trust;
        changed.pk_sha256 = sha256Bytes("different platform key");
        try testing.expect(!changed.eql(trust));
        try testing.expect(trust.eql(trust));
        // A different release leaf is not enrolled here.
        try testing.expectError(
            error.InvalidSecureBootVariables,
            validateSecureBootTrust(
                &store,
                sha256Bytes("other certificate"),
            ),
        );
    }

    const Case = struct { label: []const u8, mutate: usize, apply: TestVariable };
    const cases = [_]Case{
        .{
            .label = "Secure Boot disabled",
            .mutate = 0,
            .apply = .{
                .name = "SecureBootEnable",
                .guid = secure_boot_enable_guid,
                .attributes = boot_service_attributes,
                .data = &.{0x00},
            },
        },
        .{
            .label = "SecureBootEnable under the wrong GUID",
            .mutate = 0,
            .apply = .{
                .name = "SecureBootEnable",
                .guid = global_variable_guid,
                .attributes = boot_service_attributes,
                .data = &.{0x01},
            },
        },
        .{
            .label = "SecureBootEnable with runtime access",
            .mutate = 0,
            .apply = .{
                .name = "SecureBootEnable",
                .guid = secure_boot_enable_guid,
                .attributes = boot_service_attributes | attribute_runtime_access,
                .data = &.{0x01},
            },
        },
        .{
            .label = "custom mode left enabled",
            .mutate = 1,
            .apply = .{
                .name = "CustomMode",
                .guid = custom_mode_guid,
                .attributes = boot_service_attributes,
                .data = &.{0x01},
            },
        },
        .{
            .label = "CustomMode under the wrong GUID",
            .mutate = 1,
            .apply = .{
                .name = "CustomMode",
                .guid = global_variable_guid,
                .attributes = boot_service_attributes,
                .data = &.{0x00},
            },
        },
        .{
            .label = "PK under the wrong GUID",
            .mutate = 2,
            .apply = .{
                .name = "PK",
                .guid = image_security_database_guid,
                .attributes = authenticated_variable_attributes,
                .data = "pk",
            },
        },
        .{
            .label = "unauthenticated PK",
            .mutate = 2,
            .apply = .{
                .name = "PK",
                .guid = global_variable_guid,
                .attributes = boot_service_attributes,
                .data = "pk",
            },
        },
        .{
            .label = "empty PK",
            .mutate = 2,
            .apply = .{
                .name = "PK",
                .guid = global_variable_guid,
                .attributes = authenticated_variable_attributes,
                .data = "",
            },
        },
        .{
            .label = "unauthenticated KEK",
            .mutate = 3,
            .apply = .{
                .name = "KEK",
                .guid = global_variable_guid,
                .attributes = authenticated_variable_attributes | 0x40,
                .data = "kek",
            },
        },
        .{
            .label = "db under the wrong GUID",
            .mutate = 4,
            .apply = .{
                .name = "db",
                .guid = global_variable_guid,
                .attributes = authenticated_variable_attributes,
                .data = "",
            },
        },
        .{
            .label = "empty db",
            .mutate = 4,
            .apply = .{
                .name = "db",
                .guid = image_security_database_guid,
                .attributes = authenticated_variable_attributes,
                .data = "",
            },
        },
    };

    for (cases) |case| {
        var variables = enrolled;
        variables[case.mutate] = case.apply;
        const image = try buildTemplateAlloc(
            allocator,
            TemplateShape.ovmf_4m,
            &variables,
        );
        var store = try parse(allocator, image);
        defer store.deinit();
        testing.expectError(
            error.InvalidSecureBootVariables,
            validateSecureBootTrust(&store, digest),
        ) catch |err| {
            std.debug.print("case '{s}' did not fail as expected\n", .{case.label});
            return err;
        };
    }

    // A missing variable is just as fatal as a wrong one.
    inline for (.{ 0, 1, 2, 3, 4 }) |skipped| {
        var remaining: [enrolled.len - 1]TestVariable = undefined;
        var next: usize = 0;
        for (enrolled, 0..) |variable, index| {
            if (index == skipped) continue;
            remaining[next] = variable;
            next += 1;
        }
        const image = try buildTemplateAlloc(
            allocator,
            TemplateShape.ovmf_4m,
            &remaining,
        );
        var store = try parse(allocator, image);
        defer store.deinit();
        try testing.expectError(
            error.InvalidSecureBootVariables,
            validateSecureBootTrust(&store, digest),
        );
    }

    // A second PK record makes the store ambiguous, so it never reaches
    // validation: the parser refuses it.
    {
        var duplicated: [enrolled.len + 1]TestVariable = undefined;
        @memcpy(duplicated[0..enrolled.len], &enrolled);
        duplicated[enrolled.len] = .{
            .name = "PK",
            .guid = global_variable_guid,
            .attributes = authenticated_variable_attributes,
            .data = "second platform key",
        };
        const image = try buildTemplateAlloc(
            allocator,
            TemplateShape.ovmf_4m,
            &duplicated,
        );
        defer allocator.free(image);
        try testing.expectError(
            error.DuplicateVariableRecord,
            parse(allocator, image),
        );

        // A `PK` under the image-security-database GUID is a distinct
        // variable, so it parses -- and then fails trust validation, because
        // the name is reserved for the global-variable namespace.
        duplicated[enrolled.len].guid = image_security_database_guid;
        const image2 = try buildTemplateAlloc(
            allocator,
            TemplateShape.ovmf_4m,
            &duplicated,
        );
        var store2 = try parse(allocator, image2);
        defer store2.deinit();
        try testing.expectEqual(@as(usize, 6), store2.variables.items.len);
        try testing.expectError(
            error.InvalidSecureBootVariables,
            validateSecureBootTrust(&store2, digest),
        );
    }
}

test "enrolling through the file API writes atomically and revalidates" {
    const allocator = testing.allocator;
    const io = testing.io;
    const certificate = try testCertificateDerAlloc(allocator, test_certificate_pem);
    defer allocator.free(certificate);
    const other = try testCertificateDerAlloc(allocator, other_certificate_pem);
    defer allocator.free(other);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const base = path_buffer[0..try tmp.dir.realPath(io, &path_buffer)];

    const template_path = try std.fs.path.join(allocator, &.{ base, "template.fd" });
    defer allocator.free(template_path);
    const output_path = try std.fs.path.join(allocator, &.{ base, "enrolled.fd" });
    defer allocator.free(output_path);

    const template = try microsoftTemplateAlloc(allocator, TemplateShape.ovmf_4m);
    defer allocator.free(template);
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = template_path,
        .data = template,
        .flags = .{ .truncate = true },
    });

    const trust = try enrollSecureBootFile(
        allocator,
        io,
        template_path,
        output_path,
        certificate,
    );
    const revalidated = try validateSecureBootFile(
        allocator,
        io,
        output_path,
        sha256Bytes(certificate),
    );
    try testing.expect(trust.eql(revalidated));

    // The output is a complete image of the template's size, and the
    // template itself is untouched.
    const written = try Io.Dir.cwd().readFileAlloc(
        io,
        output_path,
        allocator,
        .limited(max_store_bytes),
    );
    defer allocator.free(written);
    try testing.expectEqual(template.len, written.len);
    const template_after = try Io.Dir.cwd().readFileAlloc(
        io,
        template_path,
        allocator,
        .limited(max_store_bytes),
    );
    defer allocator.free(template_after);
    try testing.expectEqualSlices(u8, template, template_after);

    // A different leaf is not in the enrolled store.
    try testing.expectError(
        error.InvalidSecureBootVariables,
        validateSecureBootFile(
            allocator,
            io,
            output_path,
            sha256Bytes(other),
        ),
    );

    // Rewriting over an existing output replaces it wholesale.
    const second = try enrollSecureBootFile(
        allocator,
        io,
        template_path,
        output_path,
        certificate,
    );
    try testing.expect(second.eql(trust));
}

test "system firmware templates parse and enroll when present" {
    // Optional integration coverage. These paths exist only on hosts with the
    // distribution Secure Boot firmware installed, and
    // `MIZ_EFI_VARSTORE_TEMPLATES` can name extra colon-separated templates.
    // Every correctness guarantee above is proven on synthetic stores, so this
    // test contributes nothing but breadth when firmware happens to be here.
    const allocator = testing.allocator;
    const io = testing.io;
    const certificate = try testCertificateDerAlloc(allocator, test_certificate_pem);
    defer allocator.free(certificate);
    const digest = sha256Bytes(certificate);
    var examined: usize = 0;

    const system_candidates = [_][]const u8{
        "/usr/share/OVMF/OVMF_VARS_4M.ms.fd",
        "/usr/share/OVMF/OVMF_VARS_4M.fd",
        "/usr/share/OVMF/OVMF_VARS.secboot.fd",
        "/usr/share/edk2/ovmf/OVMF_VARS.secboot.fd",
        "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        "/usr/share/AAVMF/AAVMF_VARS.ms.fd",
        "/usr/share/AAVMF/AAVMF_VARS.fd",
        "/usr/share/edk2/aarch64/vars-template-pflash.raw",
        "/usr/share/edk2/aarch64/QEMU_VARS.fd",
        "/usr/share/qemu/edk2-i386-vars.fd",
        "/usr/share/qemu/edk2-arm-vars.fd",
    };

    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(allocator);
    for (system_candidates) |path| try paths.append(allocator, path);
    const extra = testing.environ.getAlloc(
        allocator,
        "MIZ_EFI_VARSTORE_TEMPLATES",
    ) catch |err| switch (err) {
        error.EnvironmentVariableMissing => null,
        else => return err,
    };
    defer if (extra) |value| allocator.free(value);
    if (extra) |value| {
        var it = std.mem.tokenizeScalar(u8, value, ':');
        while (it.next()) |path| try paths.append(allocator, path);
    }

    // Distributions ship the same variable templates as QCOW2 next to the
    // raw ones. They must be refused, not quietly enrolled at a cluster
    // offset, because `miz qemu` maps the store as `format=raw` pflash.
    const container_candidates = [_][]const u8{
        "/usr/share/OVMF/OVMF_VARS_4M.qcow2",
        "/usr/share/OVMF/OVMF_VARS_4M.secboot.qcow2",
        "/usr/share/OVMF/OVMF_VARS_4M.ms.qcow2",
        "/usr/share/edk2/ovmf/OVMF_VARS_4M.qcow2",
        "/usr/share/edk2/ovmf/OVMF_VARS_4M.secboot.qcow2",
        "/usr/share/AAVMF/AAVMF_VARS.qcow2",
        "/usr/share/AAVMF/AAVMF_VARS.ms.qcow2",
        "/usr/share/edk2/aarch64/vars-template-pflash.qcow2",
    };
    for (container_candidates) |path| {
        Io.Dir.cwd().access(io, path, .{ .read = true }) catch continue;
        examined += 1;
        testing.expectError(
            error.UnsupportedVariableStoreContainer,
            parseFileAlloc(allocator, io, path),
        ) catch |err| {
            std.debug.print("'{s}' was not refused as a container\n", .{path});
            return err;
        };
    }

    for (paths.items) |path| {
        Io.Dir.cwd().access(io, path, .{ .read = true }) catch continue;
        var store = parseFileAlloc(allocator, io, path) catch |err| switch (err) {
            // Some distributions ship these names as QCOW2 rather than raw
            // flash images; those are simply not this module's input.
            error.VariableStoreNotFound => continue,
            else => {
                std.debug.print(
                    "failed to parse '{s}': {s}\n",
                    .{ path, @errorName(err) },
                );
                return err;
            },
        };
        defer store.deinit();
        examined += 1;
        try testing.expectEqual(
            authenticated_variable_store_guid,
            @as(Guid, store.image[store.store_offset..][0..16].*),
        );
        const rendered = try store.serializeAlloc(allocator);
        defer allocator.free(rendered);
        try testing.expectEqual(store.image.len, rendered.len);
        try testing.expectEqualSlices(
            u8,
            store.image[store.data_end..],
            rendered[store.data_end..],
        );
        // A pristine vendor template has nothing to reclaim, so re-rendering
        // it reproduces the shipped image byte for byte.
        if (store.reclaimed_records == 0)
            try testing.expectEqualSlices(u8, store.image, rendered);

        // Only Microsoft-enrolled templates carry the trust miz appends to.
        if (store.find("PK", global_variable_guid) == null) continue;
        _ = try enrollSecureBootCertificate(&store, .{ .certificate_der = certificate });
        const enrolled = try store.serializeAlloc(allocator);
        defer allocator.free(enrolled);
        var reparsed = try parse(allocator, try allocator.dupe(u8, enrolled));
        defer reparsed.deinit();
        _ = try validateSecureBootTrust(&reparsed, digest);
    }
    if (examined == 0) return error.SkipZigTest;
}
