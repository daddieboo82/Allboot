#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    process::Command,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DestinationDrive {
    disk_number: u32,
    name: String,
    bus_type: String,
    size_bytes: u64,
    serial_number: String,
    unique_id: String,
    partition_style: String,
    is_boot: bool,
    is_system: bool,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PowerShellDisk {
    number: u32,
    friendly_name: Option<String>,
    bus_type: Option<String>,
    size: Option<u64>,
    serial_number: Option<String>,
    unique_id: Option<String>,
    partition_style: Option<String>,
    is_boot: Option<bool>,
    is_system: Option<bool>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImageInspection {
    name: String,
    path: String,
    size_bytes: u64,
    extension: String,
    detected_format: String,
    iso9660_signature: bool,
    el_torito_boot_record: bool,
    udif_signature: bool,
    macos_candidate: bool,
    sha256: String,
    bootability: String,
    write_compatibility: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreflightReport {
    disk_number: u32,
    drive_name: String,
    disk_size_bytes: u64,
    image_name: String,
    image_size_bytes: u64,
    image_sha256: String,
    write_readiness: String,
    confirmation_phrase: String,
    checks: Vec<String>,
}

#[cfg(target_os = "windows")]
fn drive_helper_path() -> Result<std::path::PathBuf, String> {
    let local = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| "Windows local application-data folder is unavailable.".to_string())?;
    Ok(std::path::PathBuf::from(local)
        .join("AllBoot")
        .join("DriveHelper")
        .join("AllBootDriveHelper.ps1"))
}

#[cfg(target_os = "macos")]
fn drive_helper_path() -> Result<std::path::PathBuf, String> {
    let home =
        std::env::var_os("HOME").ok_or_else(|| "macOS home folder is unavailable.".to_string())?;
    Ok(std::path::PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("AllBoot")
        .join("DriveHelper")
        .join("AllBootDriveHelper.sh"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn drive_helper_path() -> Result<std::path::PathBuf, String> {
    Err("AllBoot Drive Helper currently supports Windows and macOS.".into())
}

fn verified_drive_helper_path() -> Result<std::path::PathBuf, String> {
    let path = drive_helper_path()?;
    let contents = std::fs::read_to_string(&path).map_err(|_| {
        "AllBoot Drive Helper is missing or unreadable. Reinstall it before drive detection."
            .to_string()
    })?;
    if !helper_version_supported(&contents) {
        return Err(
            "AllBoot Drive Helper has an unsupported version. Reinstall it before drive detection."
                .into(),
        );
    }
    Ok(path)
}
#[cfg(any(target_os = "windows", test))]
fn windows_disk_is_eligible(
    bus_type: &str,
    is_boot: bool,
    is_system: bool,
    unique_id: &str,
    size_bytes: u64,
) -> bool {
    bus_type.eq_ignore_ascii_case("USB")
        && !is_boot
        && !is_system
        && !unique_id.trim().is_empty()
        && size_bytes > 0
}
fn valid_el_torito_catalog(boot_record: &[u8], catalog: &[u8]) -> bool {
    if boot_record.len() < 75 || catalog.len() < 64 {
        return false;
    }
    if boot_record[0] != 0
        || &boot_record[1..6] != b"CD001"
        || &boot_record[7..30] != b"EL TORITO SPECIFICATION"
    {
        return false;
    }
    let validation = &catalog[..32];
    if validation[0] != 0x01 || validation[30] != 0x55 || validation[31] != 0xaa {
        return false;
    }
    let checksum = validation
        .chunks_exact(2)
        .map(|word| u16::from_le_bytes([word[0], word[1]]))
        .fold(0_u16, u16::wrapping_add);
    let initial_entry = &catalog[32..64];
    let media_type = initial_entry[1];
    let sector_count = u16::from_le_bytes([initial_entry[6], initial_entry[7]]);
    let load_rba = u32::from_le_bytes([
        initial_entry[8],
        initial_entry[9],
        initial_entry[10],
        initial_entry[11],
    ]);
    checksum == 0 && initial_entry[0] == 0x88 && media_type <= 4 && sector_count > 0 && load_rba > 0
}

fn file_metadata_unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}
fn image_write_readiness(
    extension: &str,
    el_torito_boot_record: bool,
    udif_signature: bool,
) -> &'static str {
    if udif_signature || extension.eq_ignore_ascii_case("dmg") {
        "Not ready: macOS DMG requires Apple's installer-specific workflow, which is not implemented."
    } else if matches!(
        extension.to_ascii_lowercase().as_str(),
        "wim" | "esd" | "vhd" | "vhdx"
    ) {
        "Not ready: this is a container format, not a directly writable boot image."
    } else if extension.eq_ignore_ascii_case("iso") && el_torito_boot_record {
        "Candidate only: El Torito boot record detected. Target operating-system and firmware compatibility still need validation; writing is not implemented."
    } else if extension.eq_ignore_ascii_case("iso") {
        "Not ready: no El Torito boot record was detected in this ISO."
    } else if matches!(
        extension.to_ascii_lowercase().as_str(),
        "img" | "raw" | "bin"
    ) {
        "Not ready: raw-image boot structure and partition layout are not yet validated by AllBoot."
    } else {
        "Not ready: image format is not supported by a verified writing workflow."
    }
}

fn image_write_compatibility(
    extension: &str,
    iso9660_signature: bool,
    el_torito_boot_record: bool,
    udif_signature: bool,
) -> &'static str {
    if udif_signature || extension.eq_ignore_ascii_case("dmg") {
        "macOS installer workflow required; do not raw-write this DMG"
    } else if matches!(
        extension.to_ascii_lowercase().as_str(),
        "wim" | "esd" | "vhd" | "vhdx"
    ) {
        "container format; not eligible for direct raw USB writing"
    } else if el_torito_boot_record {
        "raw-image candidate; target firmware and operating-system compatibility still require validation"
    } else if iso9660_signature {
        "ISO 9660 detected without El Torito boot record; bootability is unconfirmed"
    } else if matches!(
        extension.to_ascii_lowercase().as_str(),
        "img" | "raw" | "bin"
    ) {
        "raw-image candidate; bootability and partition layout are unverified"
    } else {
        "unverified format; direct USB writing is not recommended"
    }
}

#[cfg(target_os = "windows")]
fn drive_helper_source() -> &'static str {
    r#"# ALLBOOT_DRIVE_HELPER_VERSION=1
$ErrorActionPreference = 'Stop'
$disks = @(Get-Disk | Select-Object Number,FriendlyName,BusType,Size,SerialNumber,UniqueId,PartitionStyle,IsBoot,IsSystem)
ConvertTo-Json -InputObject $disks -Compress
"#
}

#[cfg(target_os = "macos")]
fn drive_helper_source() -> &'static str {
    r#"#!/bin/sh
# ALLBOOT_DRIVE_HELPER_VERSION=1
set -eu
action="$1"
case "$action" in
  list)
    /usr/sbin/diskutil list -plist external physical | /usr/bin/plutil -convert json -o - -
    ;;
  info)
    disk="$2"
    case "$disk" in
      disk[0-9]*) ;;
      *) echo "Invalid disk identifier" >&2; exit 2 ;;
    esac
    number=$(printf '%s' "$disk" | /usr/bin/cut -c 5-)
    case "$number" in
      *[!0-9]*|'') echo "Invalid disk identifier" >&2; exit 2 ;;
    esac
    /usr/sbin/diskutil info -plist "/dev/$disk" | /usr/bin/plutil -convert json -o - -
    ;;
  boot)
    /usr/sbin/diskutil info -plist / | /usr/bin/plutil -convert json -o - -
    ;;
  *)
    echo "Supported actions: list, info, boot" >&2
    exit 2
    ;;
esac
"#
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn drive_helper_source() -> &'static str {
    ""
}

fn helper_version_supported(contents: &str) -> bool {
    contents == drive_helper_source()
}
#[tauri::command]
fn drive_helper_installed() -> bool {
    drive_helper_path()
        .and_then(|path| std::fs::read_to_string(path).map_err(|e| e.to_string()))
        .map(|contents| helper_version_supported(&contents))
        .unwrap_or(false)
}

#[tauri::command]
fn install_drive_helper() -> Result<String, String> {
    let path = drive_helper_path()?;
    let folder = path
        .parent()
        .ok_or_else(|| "Could not determine helper installation folder.".to_string())?;
    std::fs::create_dir_all(folder)
        .map_err(|e| format!("Could not create the AllBoot helper folder: {e}"))?;

    #[cfg(target_os = "windows")]
    {
        let script = drive_helper_source();
        std::fs::write(&path, script)
            .map_err(|e| format!("Could not install the Windows drive helper: {e}"))?;
    }
    #[cfg(target_os = "macos")]
    {
        let script = drive_helper_source();
        std::fs::write(&path, script)
            .map_err(|e| format!("Could not install the macOS drive helper: {e}"))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Could not make the macOS helper executable: {e}"))?;
    }
    let installed_contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Could not verify the installed helper contents: {e}"))?;
    if !helper_version_supported(&installed_contents) {
        return Err("The installed drive helper failed its version check.".into());
    }
    if !path.is_file() {
        return Err("The helper could not be verified after installation.".into());
    }
    Ok(path.to_string_lossy().to_string())
}
#[cfg(any(target_os = "macos", test))]
fn is_whole_macos_disk_identifier(identifier: &str) -> bool {
    let Some(number) = identifier.strip_prefix("disk") else {
        return false;
    };
    !number.is_empty() && number.chars().all(|c| c.is_ascii_digit())
}
#[cfg(any(target_os = "macos", test))]
fn parent_disk_identifier(volume_id: &str) -> Option<String> {
    let rest = volume_id.strip_prefix("disk")?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let suffix = &rest[digits.len()..];
    if !suffix.is_empty() {
        let partitions = suffix.strip_prefix('s')?;
        if partitions.is_empty()
            || !partitions
                .split('s')
                .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
        {
            return None;
        }
    }
    Some(format!("disk{}", digits))
}
#[cfg(any(target_os = "macos", test))]
fn is_usb_bus_protocol(protocol: &str) -> bool {
    protocol.trim().eq_ignore_ascii_case("USB")
}

#[cfg(any(target_os = "macos", test))]
fn macos_disk_is_eligible(
    internal: bool,
    whole: bool,
    is_boot: bool,
    bus_protocol: &str,
    has_stable_identity: bool,
    size_bytes: u64,
) -> bool {
    !internal
        && whole
        && !is_boot
        && is_usb_bus_protocol(bus_protocol)
        && has_stable_identity
        && size_bytes > 0
}
fn stable_macos_disk_identity(detail: &serde_json::Value) -> Option<String> {
    let serial = detail
        .get("SerialNumber")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let media_uuid = detail
        .get("MediaUUID")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let device_tree = detail
        .get("DeviceTreePath")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if serial.is_empty() && media_uuid.is_empty() && device_tree.is_empty() {
        return None;
    }
    Some(format!("{}|{}|{}", serial, media_uuid, device_tree))
}
#[tauri::command]
fn list_destination_drives() -> Result<Vec<DestinationDrive>, String> {
    #[cfg(target_os = "windows")]
    {
        let script = "$ErrorActionPreference='Stop'; $helper=$env:ALLBOOT_HELPER_PATH; if (-not (Test-Path -LiteralPath $helper)) { throw 'AllBoot Drive Helper is not installed. Install it from the AllBoot setup prompt.' }; & $helper";
        let output = Command::new("powershell.exe")
            .env(
                "ALLBOOT_HELPER_PATH",
                verified_drive_helper_path()?.to_string_lossy().to_string(),
            )
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .output()
            .map_err(|e| format!("Could not enumerate disks: {e}"))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }
        let disks: Vec<PowerShellDisk> = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("Could not read Windows disk inventory: {e}"))?;
        let mut result = Vec::new();
        for disk in disks {
            let bus_type = disk.bus_type.unwrap_or_default();
            let is_boot = disk.is_boot.unwrap_or(false);
            let is_system = disk.is_system.unwrap_or(false);
            let unique_id = disk.unique_id.as_deref().unwrap_or("");
            let size_bytes = disk.size.unwrap_or(0);
            if !windows_disk_is_eligible(&bus_type, is_boot, is_system, unique_id, size_bytes) {
                continue;
            }
            result.push(DestinationDrive {
                disk_number: disk.number,
                name: disk
                    .friendly_name
                    .unwrap_or_else(|| "USB storage device".into()),
                bus_type,
                size_bytes,
                serial_number: disk.serial_number.unwrap_or_default(),
                unique_id: unique_id.to_string(),
                partition_style: disk.partition_style.unwrap_or_default(),
                is_boot,
                is_system,
            });
        }
        Ok(result)
    }
    #[cfg(target_os = "macos")]
    {
        let helper = verified_drive_helper_path()?;
        let run = |args: &[&str]| -> Result<serde_json::Value, String> {
            let output = Command::new("sh")
                .arg(&helper)
                .args(args)
                .output()
                .map_err(|e| format!("Could not run AllBoot Drive Helper: {e}"))?;
            if !output.status.success() {
                return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
            }
            serde_json::from_slice(&output.stdout)
                .map_err(|e| format!("Could not parse macOS disk information: {e}"))
        };
        let inventory = run(&["list"])?;
        let boot_info = run(&["boot"])?;
        let boot_volume = boot_info.get("DeviceIdentifier").and_then(|v| v.as_str())
            .or_else(|| boot_info.get("PartOfWhole").and_then(|v| v.as_str()))
            .ok_or_else(|| "Could not identify the current macOS startup volume; discovery is blocked for safety.".to_string())?;
        let boot_disk = parent_disk_identifier(boot_volume)
            .ok_or_else(|| "Could not identify the parent of the macOS startup volume; discovery is blocked for safety.".to_string())?;
        let disks = inventory
            .get("AllDisksAndPartitions")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "macOS returned no external physical disk list.".to_string())?;
        let mut result = Vec::new();
        for entry in disks {
            let identifier = match entry.get("DeviceIdentifier").and_then(|v| v.as_str()) {
                Some(v) => v,
                None => continue,
            };
            if !is_whole_macos_disk_identifier(identifier) {
                continue;
            }
            let detail = match run(&["info", identifier]) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let internal = detail
                .get("Internal")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let whole = detail
                .get("Whole")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let actual_id = detail
                .get("DeviceIdentifier")
                .and_then(|v| v.as_str())
                .unwrap_or(identifier);
            let is_boot = actual_id == boot_disk;

            let bus = detail
                .get("BusProtocol")
                .or_else(|| detail.get("Protocol"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !is_usb_bus_protocol(bus) {
                continue;
            }
            let size = detail
                .get("TotalSize")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let number = match identifier[4..].parse::<u32>() {
                Ok(value) => value,
                Err(_) => continue,
            };
            let name = detail
                .get("MediaName")
                .and_then(|v| v.as_str())
                .unwrap_or("External storage device")
                .to_string();
            let stable_id = match stable_macos_disk_identity(&detail) {
                Some(value) => value,
                None => continue,
            };
            if !macos_disk_is_eligible(internal, whole, is_boot, bus, !stable_id.is_empty(), size) {
                continue;
            }

            let serial = detail
                .get("SerialNumber")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            result.push(DestinationDrive {
                disk_number: number,
                name,
                bus_type: bus.to_string(),
                size_bytes: size,
                serial_number: serial.clone(),
                unique_id: stable_id,
                partition_style: detail
                    .get("PartitionMapPartition")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
                is_boot,
                is_system: is_boot,
            });
        }
        Ok(result)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Err("AllBoot drive discovery supports Windows and macOS.".into())
    }
}

#[tauri::command]
fn inspect_image(path: String) -> Result<ImageInspection, String> {
    let image_path = Path::new(&path);
    if !image_path.is_file() {
        return Err("The selected image file could not be found.".into());
    }
    let mut file = File::open(image_path).map_err(|e| format!("Could not open image: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Could not read opened image metadata: {e}"))?;
    if !metadata.is_file() {
        return Err("The selected source is not a regular image file.".into());
    }
    let extension = image_path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let name = image_path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("Selected image")
        .to_string();

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| format!("Could not hash image: {e}"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let after_handle_metadata = file
        .metadata()
        .map_err(|e| format!("Could not re-check opened image after hashing: {e}"))?;
    let after_path_metadata = std::fs::metadata(image_path)
        .map_err(|e| format!("Could not re-check image path after hashing: {e}"))?;
    if !file_metadata_unchanged(&metadata, &after_handle_metadata)
        || !file_metadata_unchanged(&metadata, &after_path_metadata)
    {
        return Err("The image changed while AllBoot was inspecting it. Re-select the file and inspect it again. Nothing was written.".into());
    }
    let sha256 = format!("{:x}", hasher.finalize());

    let mut pvd = [0_u8; 6];
    let iso9660_signature = if metadata.len() >= 32_774 {
        file.seek(SeekFrom::Start(32_768))
            .map_err(|e| format!("Could not inspect ISO header: {e}"))?;
        file.read_exact(&mut pvd).is_ok() && pvd[0] == 1 && &pvd[1..6] == b"CD001"
    } else {
        false
    };

    let mut boot_record = [0_u8; 75];
    let el_torito_boot_record = if metadata.len() >= 34_891 {
        file.seek(SeekFrom::Start(34_816))
            .map_err(|e| format!("Could not inspect ISO boot record: {e}"))?;
        if file.read_exact(&mut boot_record).is_err()
            || boot_record[0] != 0
            || &boot_record[1..6] != b"CD001"
            || &boot_record[7..30] != b"EL TORITO SPECIFICATION"
        {
            false
        } else {
            let catalog_lba = u32::from_le_bytes([
                boot_record[71],
                boot_record[72],
                boot_record[73],
                boot_record[74],
            ]) as u64;
            let catalog_offset = catalog_lba.saturating_mul(2048);
            let mut catalog = [0_u8; 64];
            if catalog_offset
                .checked_add(64)
                .is_some_and(|end| end <= metadata.len())
                && file.seek(SeekFrom::Start(catalog_offset)).is_ok()
                && file.read_exact(&mut catalog).is_ok()
            {
                valid_el_torito_catalog(&boot_record, &catalog)
            } else {
                false
            }
        }
    } else {
        false
    };

    let mut udif = [0_u8; 4];
    let udif_signature = if metadata.len() >= 512 {
        file.seek(SeekFrom::Start(metadata.len() - 512))
            .map_err(|e| format!("Could not inspect DMG trailer: {e}"))?;
        file.read_exact(&mut udif).is_ok() && &udif == b"koly"
    } else {
        false
    };

    let detected_format = if udif_signature {
        "Apple UDIF disk image (DMG)".to_string()
    } else if iso9660_signature {
        "ISO 9660".to_string()
    } else {
        match extension.as_str() {
            "dmg" => "DMG extension; UDIF trailer signature not detected".into(),
            "iso" => "ISO candidate; ISO 9660 primary-volume signature not found".into(),
            "img" | "raw" | "bin" => "Raw disk-image candidate".into(),
            "vhd" | "vhdx" => "Virtual hard-disk image".into(),
            "wim" | "esd" => "Windows image container".into(),
            _ => "Unknown image format".into(),
        }
    };
    let macos_candidate = matches!(extension.as_str(), "dmg" | "iso" | "img" | "raw");
    let bootability = if udif_signature {
        "Apple UDIF container detected. This does not prove it is a full macOS installer or a bootable USB source.".into()
    } else if el_torito_boot_record {
        "El Torito boot record detected. Confirm operating-system compatibility before writing."
            .into()
    } else if iso9660_signature {
        "ISO 9660 structure detected; no El Torito boot record found. Bootability is unconfirmed."
            .into()
    } else if macos_candidate {
        "Candidate only. File extension does not prove that this image is bootable.".into()
    } else {
        "Not identified as a supported macOS installer image.".into()
    };

    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Could not restart image integrity verification: {e}"))?;
    let mut verification_hasher = Sha256::new();
    loop {
        let count = file.read(&mut buffer).map_err(|e| {
            format!("Could not verify image integrity after header inspection: {e}")
        })?;
        if count == 0 {
            break;
        }
        verification_hasher.update(&buffer[..count]);
    }
    let verification_sha256 = format!("{:x}", verification_hasher.finalize());
    if !verification_sha256.eq_ignore_ascii_case(&sha256) {
        return Err("The image contents changed during inspection. Select the file again and repeat inspection. Nothing was written.".into());
    }
    let final_handle_metadata = file
        .metadata()
        .map_err(|e| format!("Could not perform final image integrity check: {e}"))?;
    let final_path_metadata = std::fs::metadata(image_path)
        .map_err(|e| format!("The selected image path changed during inspection: {e}"))?;
    if !file_metadata_unchanged(&metadata, &final_handle_metadata)
        || !file_metadata_unchanged(&metadata, &final_path_metadata)
    {
        return Err("The image changed during inspection. Select it again and repeat inspection. Nothing was written.".into());
    }

    let write_compatibility = image_write_compatibility(
        &extension,
        iso9660_signature,
        el_torito_boot_record,
        udif_signature,
    )
    .to_string();

    Ok(ImageInspection {
        name,
        path,
        size_bytes: metadata.len(),
        extension,
        detected_format,
        iso9660_signature,
        el_torito_boot_record,
        udif_signature,
        macos_candidate,
        sha256,
        bootability,
        write_compatibility,
    })
}

#[tauri::command]
fn preflight_write(
    disk_number: u32,
    expected_unique_id: String,
    image_path: String,
    expected_sha256: String,
) -> Result<PreflightReport, String> {
    #[cfg(target_os = "windows")]
    {
        let script = "$ErrorActionPreference='Stop'; $helper=$env:ALLBOOT_HELPER_PATH; if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw 'AllBoot Drive Helper is missing. Reinstall it before preparation.' }; $inventory = & $helper | ConvertFrom-Json; $n=[uint32]$env:ALLBOOT_DISK_NUMBER; $disk = @($inventory) | Where-Object { [uint32]$_.Number -eq $n } | Select-Object -First 1; if ($null -eq $disk) { throw 'The selected disk is no longer present in the helper inventory.' }; $disk | Select-Object Number,FriendlyName,BusType,Size,SerialNumber,UniqueId,PartitionStyle,IsBoot,IsSystem | ConvertTo-Json -Compress";
        let output = Command::new("powershell.exe")
            .env("ALLBOOT_DISK_NUMBER", disk_number.to_string())
            .env(
                "ALLBOOT_HELPER_PATH",
                verified_drive_helper_path()?.to_string_lossy().to_string(),
            )
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .output()
            .map_err(|e| format!("Could not re-check the selected disk: {e}"))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }
        let disk: PowerShellDisk = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("Could not read selected disk identity: {e}"))?;
        let bus_type = disk.bus_type.unwrap_or_default();
        if !bus_type.eq_ignore_ascii_case("USB") {
            return Err(
                "The selected device is no longer identified as USB storage. Nothing was written."
                    .into(),
            );
        }
        if disk.is_boot.unwrap_or(false) || disk.is_system.unwrap_or(false) {
            return Err("Safety check blocked this device because Windows identifies it as a boot or system disk. Nothing was written.".into());
        }
        let actual_id = disk.unique_id.unwrap_or_default();
        if !windows_disk_is_eligible(
            &bus_type,
            disk.is_boot.unwrap_or(false),
            disk.is_system.unwrap_or(false),
            &actual_id,
            disk.size.unwrap_or(0),
        ) {
            return Err("The selected USB disk no longer meets AllBoot's identity, capacity, or system-disk safety checks. Nothing was written.".into());
        }
        if expected_unique_id.trim().is_empty()
            || !actual_id.eq_ignore_ascii_case(expected_unique_id.trim())
        {
            return Err("The selected USB device identity changed since selection. Scan again and re-select the intended drive. Nothing was written.".into());
        }
        let disk_size = disk.size.unwrap_or(0);
        let image = inspect_image(image_path)?;
        if !image.sha256.eq_ignore_ascii_case(expected_sha256.trim()) {
            return Err("The selected image changed after inspection. Re-select the image and run preflight again. Nothing was written.".into());
        }
        if image.size_bytes > disk_size {
            return Err(format!("The image is larger than the selected USB drive ({} bytes available, {} bytes required). Nothing was written.", disk_size, image.size_bytes));
        }
        let write_readiness = image_write_readiness(
            &image.extension,
            image.el_torito_boot_record,
            image.udif_signature,
        )
        .to_string();
        Ok(PreflightReport {
            disk_number,
            drive_name: disk
                .friendly_name
                .unwrap_or_else(|| "USB storage device".into()),
            disk_size_bytes: disk_size,
            image_name: image.name,
            image_size_bytes: image.size_bytes,
            image_sha256: image.sha256,
            write_readiness,
            confirmation_phrase: format!("ERASE DISK {}", disk_number),
            checks: vec![
                "Destination re-queried immediately before preparation".into(),
                "USB bus type confirmed".into(),
                "Windows boot and system disks excluded".into(),
                "Stable disk identity matched the selected device".into(),
                "Image exists and SHA-256 was recalculated".into(),
                "Image size fits within the selected device".into(),
            ],
        })
    }
    #[cfg(target_os = "macos")]
    {
        let helper = verified_drive_helper_path()?;
        let disk_id = format!("disk{}", disk_number);
        let run_info = |action: &str, id: Option<&str>| -> Result<serde_json::Value, String> {
            let mut command = Command::new("sh");
            command.arg(&helper).arg(action);
            if let Some(value) = id {
                command.arg(value);
            }
            let output = command
                .output()
                .map_err(|e| format!("Could not re-check macOS disk: {e}"))?;
            if !output.status.success() {
                return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
            }
            serde_json::from_slice(&output.stdout)
                .map_err(|e| format!("Could not parse macOS disk identity: {e}"))
        };
        let detail = run_info("info", Some(&disk_id))?;
        let boot = run_info("boot", None)?;
        let boot_volume = boot
            .get("DeviceIdentifier")
            .and_then(|v| v.as_str())
            .or_else(|| boot.get("PartOfWhole").and_then(|v| v.as_str()))
            .ok_or_else(|| {
                "Could not identify the current macOS startup volume. Nothing was written."
                    .to_string()
            })?;
        let boot_disk = parent_disk_identifier(boot_volume).ok_or_else(|| {
            "Could not identify the parent of the macOS startup volume. Nothing was written."
                .to_string()
        })?;
        let actual_id = detail
            .get("DeviceIdentifier")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let internal = detail
            .get("Internal")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let whole = detail
            .get("Whole")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let is_boot = actual_id == boot_disk;
        let bus = detail
            .get("BusProtocol")
            .or_else(|| detail.get("Protocol"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let serial = detail
            .get("SerialNumber")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let stable_id = stable_macos_disk_identity(&detail).ok_or_else(|| {
            "The external disk does not expose a stable hardware identity. For safety, AllBoot will not prepare this device. Nothing was written.".to_string()
        })?;
        let disk_size = detail
            .get("TotalSize")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if actual_id != disk_id
            || !macos_disk_is_eligible(
                internal,
                whole,
                is_boot,
                bus,
                !stable_id.is_empty(),
                disk_size,
            )
        {
            return Err("The selected disk no longer meets AllBoot's external USB, startup-disk, identity, or capacity checks. Nothing was written.".into());
        }
        if expected_unique_id.trim().is_empty() || stable_id != expected_unique_id {
            return Err("The selected external disk identity changed. Scan again and re-select it. Nothing was written.".into());
        }
        let image = inspect_image(image_path)?;

        if !image.sha256.eq_ignore_ascii_case(expected_sha256.trim()) {
            return Err("The selected image changed after inspection. Re-select the image and run preflight again. Nothing was written.".into());
        }
        if image.size_bytes > disk_size {
            return Err(format!("The image is larger than the selected external disk ({} bytes available, {} bytes required). Nothing was written.", disk_size, image.size_bytes));
        }
        let write_readiness = image_write_readiness(
            &image.extension,
            image.el_torito_boot_record,
            image.udif_signature,
        )
        .to_string();
        Ok(PreflightReport {
            disk_number,
            drive_name: detail
                .get("MediaName")
                .and_then(|v| v.as_str())
                .unwrap_or("External storage device")
                .to_string(),
            disk_size_bytes: disk_size,
            image_name: image.name,
            image_size_bytes: image.size_bytes,
            image_sha256: image.sha256,
            write_readiness,
            confirmation_phrase: format!("ERASE DISK {}", disk_number),
            checks: vec![
                "External physical disk re-queried immediately before preparation".into(),
                format!("External connection protocol confirmed: {}", bus),
                "Internal and current startup disks excluded".into(),
                "Stable device identity matched the selected disk".into(),
                "Image exists and SHA-256 was recalculated".into(),
                "Image size fits within the selected external disk".into(),
            ],
        })
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = (disk_number, expected_unique_id, image_path, expected_sha256);
        Err("AllBoot preflight supports Windows and macOS.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn validates_el_torito_catalog_checksum_signature_and_boot_entry() {
        let mut boot_record = [0_u8; 75];
        boot_record[0] = 0;
        boot_record[1..6].copy_from_slice(b"CD001");
        boot_record[7..30].copy_from_slice(b"EL TORITO SPECIFICATION");
        let mut catalog = [0_u8; 64];
        catalog[0] = 1;
        catalog[30] = 0x55;
        catalog[31] = 0xaa;
        catalog[32] = 0x88;
        catalog[33] = 0;
        catalog[38..40].copy_from_slice(&4_u16.to_le_bytes());
        catalog[40..44].copy_from_slice(&21_u32.to_le_bytes());
        let sum = catalog[..32]
            .chunks_exact(2)
            .map(|word| u16::from_le_bytes([word[0], word[1]]))
            .fold(0_u16, u16::wrapping_add);
        catalog[28..30].copy_from_slice(&sum.wrapping_neg().to_le_bytes());
        assert!(valid_el_torito_catalog(&boot_record, &catalog));
        catalog[31] = 0;
        assert!(!valid_el_torito_catalog(&boot_record, &catalog));
        catalog[31] = 0xaa;
        catalog[32] = 0;
        assert!(!valid_el_torito_catalog(&boot_record, &catalog));
        catalog[32] = 0x88;
        catalog[33] = 5;
        assert!(!valid_el_torito_catalog(&boot_record, &catalog));
        catalog[33] = 0;
        catalog[38..40].fill(0);
        assert!(!valid_el_torito_catalog(&boot_record, &catalog));
        catalog[38..40].copy_from_slice(&4_u16.to_le_bytes());
        catalog[40..44].fill(0);
        assert!(!valid_el_torito_catalog(&boot_record, &catalog));
        catalog[40..44].copy_from_slice(&21_u32.to_le_bytes());
        catalog[28] ^= 1;
        assert!(!valid_el_torito_catalog(&boot_record, &catalog));
        assert!(!valid_el_torito_catalog(&boot_record[..30], &catalog));
    }

    #[test]
    fn write_readiness_never_confuses_preflight_with_write_support() {
        assert!(image_write_readiness("iso", true, false).starts_with("Candidate only"));
        assert!(image_write_readiness("iso", false, false).contains("no El Torito"));
        assert!(image_write_readiness("dmg", false, true).contains("Apple's installer"));
        assert!(image_write_readiness("wim", false, false).contains("container format"));
        assert!(image_write_readiness("vhdx", false, false).contains("container format"));
        assert!(image_write_readiness("img", false, false).contains("partition layout"));
        assert!(image_write_readiness("unknown", false, false).contains("not supported"));
    }

    #[test]
    fn image_write_compatibility_distinguishes_raw_candidates_and_containers() {
        assert!(
            image_write_compatibility("iso", true, true, false).starts_with("raw-image candidate")
        );
        assert!(image_write_compatibility("dmg", false, false, true)
            .contains("macOS installer workflow"));
        assert!(image_write_compatibility("wim", false, false, false).contains("not eligible"));
        assert!(image_write_compatibility("vhdx", false, false, false).contains("not eligible"));
        assert!(image_write_compatibility("iso", true, false, false).contains("unconfirmed"));
        assert!(image_write_compatibility("img", false, false, false)
            .starts_with("raw-image candidate"));
        assert!(image_write_compatibility("unknown", false, false, false).starts_with("unverified"));
    }

    #[test]
    fn drive_helper_installation_requires_exact_shipped_source() {
        let shipped = drive_helper_source();
        assert!(helper_version_supported(shipped));
        assert!(!helper_version_supported("Get-Disk"));
        assert!(!helper_version_supported(&format!(
            "{}\\n# altered helper payload",
            shipped
        )));
        assert!(!helper_version_supported(
            "# ALLBOOT_DRIVE_HELPER_VERSION=2"
        ));
    }
    #[test]
    fn image_metadata_change_during_inspection_is_detected() {
        let path = std::env::temp_dir().join(format!(
            "allboot-image-stability-{}.tmp",
            std::process::id()
        ));
        std::fs::write(&path, b"initial image bytes").unwrap();
        let before = std::fs::metadata(&path).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, b"changed").unwrap();
        drop(file);
        let after = std::fs::metadata(&path).unwrap();
        assert!(!file_metadata_unchanged(&before, &after));
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn windows_disk_eligibility_requires_usb_identity_and_safe_capacity() {
        assert!(windows_disk_is_eligible(
            "USB",
            false,
            false,
            "USB-SERIAL-1",
            1024
        ));
        assert!(!windows_disk_is_eligible(
            "SATA",
            false,
            false,
            "USB-SERIAL-1",
            1024
        ));
        assert!(!windows_disk_is_eligible(
            "USB",
            true,
            false,
            "USB-SERIAL-1",
            1024
        ));
        assert!(!windows_disk_is_eligible(
            "USB",
            false,
            true,
            "USB-SERIAL-1",
            1024
        ));
        assert!(!windows_disk_is_eligible("USB", false, false, "", 1024));
        assert!(!windows_disk_is_eligible("USB", false, false, "   ", 1024));
        assert!(!windows_disk_is_eligible(
            "USB",
            false,
            false,
            "USB-SERIAL-1",
            0
        ));
    }
    #[test]
    fn macos_disk_eligibility_requires_every_safety_condition() {
        assert!(macos_disk_is_eligible(
            false, true, false, "USB", true, 1024
        ));
        assert!(!macos_disk_is_eligible(
            true, true, false, "USB", true, 1024
        ));
        assert!(!macos_disk_is_eligible(
            false, false, false, "USB", true, 1024
        ));
        assert!(!macos_disk_is_eligible(
            false, true, true, "USB", true, 1024
        ));
        assert!(!macos_disk_is_eligible(
            false,
            true,
            false,
            "Thunderbolt",
            true,
            1024
        ));
        assert!(!macos_disk_is_eligible(
            false, true, false, "USB", false, 1024
        ));
        assert!(!macos_disk_is_eligible(false, true, false, "USB", true, 0));
    }
    #[test]
    fn macos_drive_filter_accepts_only_usb_bus_protocol() {
        assert!(is_usb_bus_protocol("USB"));
        assert!(is_usb_bus_protocol("usb"));
        assert!(is_usb_bus_protocol(" USB "));
        assert!(!is_usb_bus_protocol("Thunderbolt"));
        assert!(!is_usb_bus_protocol("SATA"));
        assert!(!is_usb_bus_protocol("External"));
        assert!(!is_usb_bus_protocol(""));
    }
    #[test]
    fn macos_whole_disk_identifier_rejects_partition_and_malformed_names() {
        assert!(is_whole_macos_disk_identifier("disk0"));
        assert!(is_whole_macos_disk_identifier("disk23"));
        assert!(!is_whole_macos_disk_identifier("disk"));
        assert!(!is_whole_macos_disk_identifier("disk3s1"));
        assert!(!is_whole_macos_disk_identifier("disk3junk"));
        assert!(!is_whole_macos_disk_identifier("rdisk3"));
        assert!(!is_whole_macos_disk_identifier("disk-1"));
    }
    #[test]
    fn parses_macos_startup_volume_parent_disk() {
        assert_eq!(parent_disk_identifier("disk3s5"), Some("disk3".into()));
        assert_eq!(parent_disk_identifier("disk12s1"), Some("disk12".into()));
        assert_eq!(parent_disk_identifier("disk0"), Some("disk0".into()));
        assert_eq!(parent_disk_identifier("not-a-disk"), None);
        assert_eq!(parent_disk_identifier("diskx1"), None);
        assert_eq!(parent_disk_identifier("disk3s"), None);
        assert_eq!(parent_disk_identifier("disk3s1s2"), Some("disk3".into()));
        assert_eq!(parent_disk_identifier("disk3sabc"), None);
        assert_eq!(parent_disk_identifier("disk3abc"), None);
    }

    #[test]
    fn macos_disk_identity_requires_a_hardware_or_device_tree_identifier() {
        let empty = serde_json::json!({
            "SerialNumber": "",
            "MediaUUID": "",
            "DeviceTreePath": ""
        });
        assert_eq!(stable_macos_disk_identity(&empty), None);

        let media_uuid = serde_json::json!({
            "SerialNumber": "",
            "MediaUUID": "A1B2-C3D4",
            "DeviceTreePath": ""
        });
        assert_eq!(
            stable_macos_disk_identity(&media_uuid),
            Some("|A1B2-C3D4|".into())
        );

        let serial_and_path = serde_json::json!({
            "SerialNumber": "USB-SERIAL-123",
            "MediaUUID": "",
            "DeviceTreePath": "IODeviceTree:/pci/usb"
        });
        assert_eq!(
            stable_macos_disk_identity(&serial_and_path),
            Some("USB-SERIAL-123||IODeviceTree:/pci/usb".into())
        );
    }
    #[test]
    fn detects_iso9660_and_el_torito_and_hashes_source() {
        let path = std::env::temp_dir().join(format!(
            "allboot-test-{}.iso",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut bytes = vec![0_u8; 20 * 2048 + 64];
        bytes[32_768] = 1;
        bytes[32_769..32_774].copy_from_slice(b"CD001");
        bytes[34_816] = 0;
        bytes[34_817..34_822].copy_from_slice(b"CD001");
        bytes[34_823..34_846].copy_from_slice(b"EL TORITO SPECIFICATION");
        bytes[34_887..34_891].copy_from_slice(&20_u32.to_le_bytes());
        let mut catalog = [0_u8; 64];
        catalog[0] = 1;
        catalog[30] = 0x55;
        catalog[31] = 0xaa;
        catalog[32] = 0x88;
        catalog[33] = 0;
        catalog[38..40].copy_from_slice(&4_u16.to_le_bytes());
        catalog[40..44].copy_from_slice(&21_u32.to_le_bytes());
        let sum = catalog[..32]
            .chunks_exact(2)
            .map(|word| u16::from_le_bytes([word[0], word[1]]))
            .fold(0_u16, u16::wrapping_add);
        catalog[28..30].copy_from_slice(&sum.wrapping_neg().to_le_bytes());
        bytes[20 * 2048..20 * 2048 + 64].copy_from_slice(&catalog);
        fs::write(&path, &bytes).unwrap();
        let result = inspect_image(path.to_string_lossy().to_string()).unwrap();
        assert!(result.iso9660_signature);
        assert!(result.el_torito_boot_record);
        assert!(!result.udif_signature);
        assert_eq!(result.sha256.len(), 64);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn does_not_mistake_a_dmg_extension_for_a_udif_container() {
        let path = std::env::temp_dir().join(format!(
            "allboot-test-{}.dmg",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, vec![0_u8; 1024]).unwrap();
        let result = inspect_image(path.to_string_lossy().to_string()).unwrap();
        assert!(!result.udif_signature);
        assert!(result.detected_format.contains("not detected"));
        fs::remove_file(path).unwrap();
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn safe_preflight_rechecks_real_usb_identity_without_writing() {
        let installed_path =
            install_drive_helper().expect("helper should install for the integration test");
        assert!(std::path::Path::new(&installed_path).is_file());
        assert!(drive_helper_installed());
        let drives = list_destination_drives().expect("USB inventory should be readable");
        for drive in &drives {
            assert!(drive.bus_type.eq_ignore_ascii_case("USB"));
            assert!(!drive.is_boot && !drive.is_system);
        }
        if let Some(drive) = drives.first() {
            let path = std::env::temp_dir().join(format!(
                "allboot-preflight-test-{}.img",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::write(&path, vec![0x5A_u8; 1024]).unwrap();
            let report = preflight_write(
                drive.disk_number,
                drive.unique_id.clone(),
                path.to_string_lossy().to_string(),
                inspect_image(path.to_string_lossy().to_string())
                    .unwrap()
                    .sha256,
            )
            .expect("matching USB identity should pass read-only preflight");
            assert_eq!(report.disk_number, drive.disk_number);
            assert_eq!(
                report.confirmation_phrase,
                format!("ERASE DISK {}", drive.disk_number)
            );
            let mismatch = preflight_write(
                drive.disk_number,
                "not-the-real-device-id".into(),
                path.to_string_lossy().to_string(),
                inspect_image(path.to_string_lossy().to_string())
                    .unwrap()
                    .sha256,
            );
            assert!(mismatch.is_err(), "changed device identity must be blocked");
            fs::remove_file(path).unwrap();
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_helper_installs_and_returns_read_only_external_disk_inventory() {
        let installed_path = install_drive_helper().expect("macOS helper should install");
        let helper = std::path::Path::new(&installed_path);
        assert!(helper.is_file());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(helper).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let output = Command::new("sh")
            .arg(helper)
            .arg("list")
            .output()
            .expect("helper should execute");
        assert!(output.status.success(), "helper list action should succeed");
        let _: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("diskutil plist JSON should parse");
        let drives =
            list_destination_drives().expect("macOS external disk discovery should succeed");
        for drive in drives {
            assert!(
                !drive.is_boot && !drive.is_system,
                "startup disk must not be selectable"
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_drive_helper_is_versioned_and_discovery_only() {
        let helper = drive_helper_source();
        assert!(helper.contains("# ALLBOOT_DRIVE_HELPER_VERSION=1"));
        assert!(helper.contains("Get-Disk"));
        assert!(helper.contains("ConvertTo-Json"));
        for forbidden in [
            "Clear-Disk",
            "Format-Volume",
            "Initialize-Disk",
            "Remove-Partition",
            "Set-Disk",
            "Remove-Item",
        ] {
            assert!(
                !helper.contains(forbidden),
                "discovery helper must not contain {forbidden}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_drive_helper_is_versioned_and_discovery_only() {
        let helper = drive_helper_source();
        assert!(helper.contains("# ALLBOOT_DRIVE_HELPER_VERSION=1"));
        assert!(helper.contains("diskutil list -plist external physical"));
        assert!(helper.contains("diskutil info -plist"));
        for forbidden in [
            "diskutil eraseDisk",
            "diskutil partitionDisk",
            "diskutil apfs deleteContainer",
            "diskutil unmountDisk",
            "diskutil eject",
        ] {
            assert!(
                !helper.contains(forbidden),
                "discovery helper must not contain {forbidden}"
            );
        }
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            list_destination_drives,
            drive_helper_installed,
            install_drive_helper,
            inspect_image,
            preflight_write
        ])
        .run(tauri::generate_context!())
        .expect("error while running AllBoot ISO Maker");
}
