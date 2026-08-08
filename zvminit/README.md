# zvminit

A minimal (~160 KB), statically-linked PID 1 replacement for real-boot testing of images built with `zvmi build-image --skip-iso-rootfs`, e.g. against a real Azure VM. It exists to validate the fix for [issue #88](https://github.com/cataggar/zvmi/issues/88) end-to-end on real hardware rather than only structurally/in QEMU, and to serve as a small reference for what a from-scratch container-image init needs to do.

## What it does

- Mounts `/proc`, `/sys`, `/dev`, and `/run`. Immutable mode is the default: root stays read-only, `/var` and `/tmp` use tmpfs, and `/etc` uses a tmpfs-backed overlay. The opt-in `zvminit.mode=persistent` kernel option instead remounts root read-write, leaves `/etc`, `/var`, and `/home` persistent, and mounts only `/tmp` as tmpfs. If `/etc/machine-id` is empty after image generalization, zvminit generates and persists a new 128-bit machine ID.
- Loads the kernel modules this appliance needs directly via a raw `init_module()` syscall (decompressing the shipped `.ko.xz` with `std.compress.xz`): `overlay` for immutable `/etc`, `hv_netvsc` for Hyper-V networking, and `crc-itu-t`/`udf`/`isofs` for Azure's provisioning DVD. There's no udev/mdev daemon to drive `request_module()` through modprobe/kmod, so zvminit loads the fixed dependency order itself.
- Mounts the ESP, sets the hostname, brings up loopback, then runs a small
  DHCP client on the first non-`lo` interface it finds and writes
  `/etc/resolv.conf`. DHCP replies are received on a raw `AF_PACKET` socket
  bound to the interface rather than a plain UDP socket: on Azure's SDN
  fabric (unlike simpler local QEMU networking), the kernel's normal IPv4
  input path drops broadcast-destined DHCP replies before they reach a
  `recvfrom()` on an `AF_INET`/`SOCK_DGRAM` socket, because the interface
  has no IP configured yet and there's no local route to validate the relay
  address against (logged as `IPv4: martian source ... on dev ethN`). A raw
  packet socket taps the device's receive path before that check applies --
  the same technique real DHCP clients (dhclient/udhcpc/systemd-networkd)
  use.
- Installs `SIGTERM`/`SIGINT` handlers that stop managed children before
  cleanly powering off/rebooting, and
  doubles as `/sbin/poweroff`, `/sbin/reboot`, `/sbin/shutdown` (dispatched
  by `argv[0]`) so the kernel's `orderly_poweroff()` usermode-helper path
  (driven by Hyper-V's shutdown integration service) has something to exec.
- Runs a PID-1 supervisor loop that never returns and reaps every child.
  It discovers serial consoles from `console=` entries and
  `/sys/class/tty/console/active`, with architecture fallbacks of `ttyS0`
  (x86_64) and `ttyAMA0` (AArch64). Normal logs prefer `/dev/console`.
  `zvminit.shell=on` explicitly enables a respawning diagnostic root shell on
  the discovered serial device; the default is `off`.
- Detects Azure before launching `azagent`. Automatic detection accepts either
  a readable `ovf-env.xml` provisioning disc or DHCP option 245. Missing
  positive evidence remains unknown and is retried because Azure can expose
  the provisioning disc after networking completes. Persistent mode stores
  positive Azure detections in `/var/lib/azagent/azure-environment`, bound to
  the current DMI product UUID so moving the disk to a different VM forces
  redetection.
- Distinguishes synthetic local OVF media only by the explicit
  `zvmi-local-provisioning` marker file. Marked media runs
  `azagent --skip-ready` under the default automatic policy; an unmarked
  `ovf-env.xml` remains Azure media and keeps fail-closed, retriable WireServer
  Ready acknowledgement.
- If `/usr/sbin/azagent` (the guest provisioning agent, see `azagent/`, issue
  #112) is present, runs it as a direct child after Azure is detected and
  retries failures every five seconds. A completed local-provisioning sentinel
  gates SSH independently from retriable WireServer Ready acknowledgement.
- Supervises exactly one **access provider** — the program that makes the
  machine reachable. By default that is `/usr/sbin/sshd`, run as
  `/usr/sbin/sshd -D -e` once the provisioning sentinel exists, so a fresh
  non-Azure persistent image never exposes SSH. An image that ships
  `/usr/local/sbin/zvminit-access` replaces the default with it: zvminit runs
  that binary *instead of* sshd, with no arguments, so an appliance whose way
  in is a mesh VPN or a console enrollment agent needs no fork of PID 1. Only
  one is ever supervised, and an image that ships no override behaves exactly
  as before. Unexpected exits are reaped and restarted with exponential
  backoff capped at 30 seconds. The loop manages only these fixed processes
  and the optional shell; it is not a general service manager.
- A replacement provider does **not** wait for the provisioning sentinel. The
  sentinel proves an administrator's authorized key was installed, which says
  nothing about a provider carrying its own credentials — and making it wait
  would let a stalled provisioner take away the machine's only remaining way
  in, which on an appliance with a fixed kernel command line is unrecoverable.
- Emits `[zvminit] ZVMINIT_PID1_READY supervisor loop active` once PID 1 has
  verified its actual PID is 1, completed base initialization, and entered its
  supervisor loop. This marker does not claim that provisioning, WireServer
  Ready, or SSH acceptance has completed.
- On shutdown, prevents new service starts, broadcasts `SIGTERM` to all
  permitted guest processes, drains all direct and adopted children, then
  escalates remaining processes to `SIGKILL` before rebooting or powering off.

## Building

Built as part of the repo-root build graph (there's no separate `zvminit/build.zig`):

```
zig build
zig build test-zvminit
```

The installed executable cross-compiles statically for the architecture
selected by `-Dazurelinux-arch=x86_64|aarch64`; there is no `-Doptimize=`
toggle because the binary hardcodes `ReleaseSmall`. Tests build for the
selected native test target.

## Using it

Add the built `zig-out/bin/zvminit` binary to a container image as
`sbin/zvminit`, with relative `sbin/init`, `sbin/poweroff`, `sbin/reboot`, and
`sbin/shutdown` symlinks pointing to `zvminit`, then build an immutable bootable
disk image with:

```
zvmi build-image --iso <azurelinux.iso> --container <oci-layout-with-zvminit> \
  --generation 2 --size 768M --skip-iso-rootfs \
  --extra-kernel-options "console=tty0 console=ttyS0,115200n8" \
  -o out.vhd -O vhd
```

For a generalized Azure image, include `/usr/sbin/azagent`, `/usr/sbin/sshd`, `ssh-keygen`, and their runtime dependencies in the container, then opt into persistent mode:

```
zvmi build-image --iso <azurelinux.iso> --container <oci-layout-with-zvminit-agent-sshd> \
  --generation 2 --size 768M --skip-iso-rootfs \
  --extra-kernel-options "init=/sbin/zvminit zvminit.mode=persistent zvminit.azure=auto console=tty0 console=ttyS0,115200n8" \
  -o out.vhd -O vhd
```

`init=/sbin/zvminit` is required when the packaged OpenSSH dependency set includes systemd; otherwise the systemd-based initramfs selects `/usr/lib/systemd/systemd` directly instead of zvminit. Persistent mode is intentionally incompatible with a read-only dm-verity root. If the root remount fails, zvminit leaves provisioning and SSH disabled and retains serial-console access for diagnosis.

`zvminit.azure=auto` is the default and does not infer non-Azure from temporarily missing evidence. Use `zvminit.azure=on` to force provisioning retries when Azure's early-boot signals are unavailable, or `zvminit.azure=off` to suppress `azagent` explicitly. Overrides apply only to the current boot and do not replace the cached automatic decision. `zvmi azure deprovision` removes `/var/lib/azagent`, including both the provisioning sentinel and cached environment decision.

`zvminit.shell=off` is also the default. Add `zvminit.shell=on` only to a
temporary diagnostic boot command line when unauthenticated serial root access
is acceptable. Released builder command lines intentionally omit it.

The `/sbin/poweroff`, `/sbin/reboot`, and `/sbin/shutdown` helper links signal
PID 1 so the same complete child-drain path is used rather than rebooting
around the supervisor.

Generalized Azure deployments must still provide `adminUsername`; use `g` for
the project image convention. With the builder's `waagent.conf`, azagent mounts
the temporary resource disk at `/d`, then mounts existing ext4 partition 1 on
managed disks by stable Azure LUN at `/e` through `/z`. Blank and unknown
managed-disk layouts are never modified.

The released `AzureLinux-4.0-*.core.qcow2` images use this `zvminit` +
`azagent` contract. They require a valid public SSH key in the Azure
provisioning profile; there is no password or baked fallback credential.
Unsuffixed full images instead use systemd, cloud-init, WALinuxAgent, and
`sshd.service`. Release SHA-256 digests are documented in release notes and
workflow summaries only, never as checksum sidecar assets.
