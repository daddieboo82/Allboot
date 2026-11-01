# AllBoot ISO Maker

A desktop-first, AI-assisted utility for preparing bootable USB drives, HDDs and SSDs from supported operating-system images. Designed for Windows, Linux, macOS and other compatible bootable image formats.

## Current status

This repository begins with the product architecture and safety requirements. The application is not yet a production disk imager: device discovery, image inspection, partition planning, raw writing, read-back verification, cancellation/recovery and signed packaging must be implemented and tested before destructive operations are enabled.

## Product goals

- Select supported bootable image files, including ISO, IMG, DMG, RAW, BIN, VHD/VHDX, WIM and ESD candidates.
- Detect USB drives, HDDs and SSDs using stable device identifiers.
- Inspect image structure and report platform/firmware compatibility.
- Prepare, write and verify selected media with progress and clear error reporting.
- Use AI for image identification, setup guidance and troubleshooting—not to autonomously choose or erase a device.

## Safety requirements

A production writer must display the exact destination model, capacity and device identity; exclude system/boot disks by default; require explicit user confirmation; re-check identity immediately before writing; and verify the result. Never infer a target from a drive letter alone. Writing may permanently erase all data on the selected destination.

## Development

The initial UI uses React, TypeScript and Vite. The planned desktop shell and privileged native engine use Tauri 2 and Rust. A browser-only website cannot safely perform raw physical-disk writes, so disk operations belong in a carefully permissioned native application.

```bash
npm install
npm run dev
npm run build
```

## Roadmap

1. Desktop shell and responsive creation workflow.
2. Windows device enumeration and safe image inspection.
3. Verified boot-media writing with cancellation and read-back checks.
4. Linux and macOS device backends.
5. AI-assisted identification and troubleshooting.
6. Signed installers, accessibility and release QA.

Extension acceptance does not guarantee that an image is bootable or compatible. Compatibility must be determined by inspecting the actual image.