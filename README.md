# AllBoot ISO Maker

A Tauri 2 desktop utility for preparing bootable USB drives, HDDs and SSDs. The goal is to automate image selection, device discovery, compatibility checks, writing, verification and recovery through a graphical workflow rather than asking users to type terminal commands.

## Current implementation status

- React + TypeScript + Vite desktop interface.
- Tauri 2 native Windows application launches successfully.
- Windows USB discovery using Get-Disk, including model, capacity, serial number and stable unique ID.
- Windows boot and system disks excluded from the selectable destination list.
- Source image inspection for ISO 9660 primary-volume descriptors, El Torito boot records and Apple UDIF/DMG trailer signatures.
- Streaming SHA-256 hashing of source images (1 MiB chunks; does not load the entire image into memory).
- Read-only write preflight re-queries the selected disk immediately before preparation and checks USB bus type, boot/system flags, stable unique ID and image capacity.
- Preflight produces a future erase-confirmation phrase; no disk-writing command is currently registered or enabled.
- Windows native debug app built and launched; Rust unit tests pass, including a real connected-USB preflight and a deliberate identity-mismatch rejection.
- The Rust/MSVC toolchain and Windows SDK are installed on the development workstation.

## Important macOS installer limitation

A macOS installer USB is not always created by copying a DMG or ISO byte-for-byte. Apple's supported installer workflow uses the macOS createinstallmedia utility from a compatible full macOS installer app. That operation must run on macOS. AllBoot must detect the image type and guide users through the correct platform-specific path:

1. For a verified raw/hybrid boot image, use a validated raw-write workflow where the OS supports it.
2. For Apple's full installer app, run Apple's createinstallmedia on a Mac after confirming the USB target.
3. Do not label a drive bootable merely because a file was copied, a DMG signature was found, or an ISO descriptor was detected.

## Safety requirements before enabling writes

- Display exact drive model, capacity, disk number, serial/unique ID and partition style.
- Exclude system/boot disks by default.
- Require explicit confirmation of the exact target and warn that all target data will be erased.
- Re-query the target immediately before writing and compare stable identity fields.
- Never trust a drive letter or disk number alone.
- Require elevated permissions only for the actual write operation.
- Write in cancellable chunks, flush data and verify by read-back/hash where appropriate.
- Keep logs and report partial-write/recovery state honestly.
- Never treat a successful write as proof that a Mac can boot from the media; validate the supported installer workflow.

## Development

Prerequisites: Node.js 20+, Rust stable toolchain, Visual Studio 2022 Build Tools with the C++ workload and Windows 10/11 SDK.

~~~powershell
npm install
npm run dev
npm run build
npm run tauri:dev
npm run tauri:build
~~~

The native Tauri commands require the Visual Studio Developer environment on Windows. The browser preview cannot enumerate or write physical disks. Device operations belong in the native desktop application.

## Verified checks

- npm run build — passed.
- cargo check — passed.
- cargo test — 3 passed, 0 failed.
- git diff --check — passed.
- Windows inventory currently identifies one eligible USB destination: SanDisk 3.2Gen1, Disk 2, approximately 61.5 GB. The internal boot/system disk is excluded.
- No USB drive has been erased or modified by AllBoot.

## One-time Windows Drive Helper

On first launch, AllBoot checks for its small Drive Helper in `%LOCALAPPDATA%\AllBoot\DriveHelper\AllBootDriveHelper.ps1`. If it is missing, the app offers an **Install Drive Helper** action. The installer creates the per-user folder, writes the 201-byte PowerShell inventory helper, and verifies that it exists. No administrator permission is requested for ordinary USB discovery. Subsequent launches detect the helper automatically and enumerate drives through it. The helper only reads Windows disk inventory; it does not partition, format, erase, or write to storage devices. The native Rust preflight still independently rechecks the destination identity before any future write operation.

## Windows and macOS Drive Helper

The same AllBoot first-run setup flow installs a tiny helper tailored to the host OS:

- **Windows:** %LOCALAPPDATA%\AllBoot\DriveHelper\AllBootDriveHelper.ps1. It uses built-in Windows Storage cmdlets to read disk inventory.
- **macOS:** ~/Library/Application Support/AllBoot/DriveHelper/AllBootDriveHelper.sh. It uses Apple's built-in diskutil and plutil to list external physical disks, inspect device identity and query the startup volume.

The helper is installed per user, requires no administrator privileges for read-only discovery, and does not write, erase, partition or format disks. The app independently rechecks the selected device identity and excludes internal/startup disks before any future write operation.

Tauri packaging uses the host platform's default bundle targets so Windows builds produce Windows installers and macOS builds produce macOS app/DMG packages. A macOS build must be produced and tested on macOS; this Windows development machine cannot validate the macOS helper against real Apple hardware. The macOS implementation is present in the shared Rust code but requires a native macOS build and device test before being called release-ready.
