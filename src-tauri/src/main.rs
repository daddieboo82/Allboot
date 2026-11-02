#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
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
    apple_partition_map_signature: bool,
    hfs_plus_signature: bool,
    udif_signature: bool,
    macos_candidate: bool,
    macos_installer_validated: bool,
    macos_boot_architecture: String,
    macos_boot_evidence: Vec<String>,
    macos_supported_models: Vec<String>,
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
#[cfg(any(target_os = "windows", test))]
fn windows_disk_identity_matches(actual_unique_id: &str, expected_unique_id: &str) -> bool {
    !actual_unique_id.trim().is_empty()
        && !expected_unique_id.trim().is_empty()
        && actual_unique_id
            .trim()
            .eq_ignore_ascii_case(expected_unique_id.trim())
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

#[allow(dead_code)]
fn stream_image<R, W, C, P>(
    reader: &mut R,
    writer: &mut W,
    expected_size: u64,
    mut is_cancelled: C,
    mut report_progress: P,
) -> Result<u64, String>
where
    R: Read,
    W: Write,
    C: FnMut() -> bool,
    P: FnMut(u64),
{
    const CHUNK_SIZE: usize = 1024 * 1024;
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    let mut written = 0_u64;
    while written < expected_size {
        if is_cancelled() {
            return Err(format!("Image streaming cancelled after {written} bytes."));
        }
        let remaining = expected_size - written;
        let requested = usize::try_from(remaining.min(CHUNK_SIZE as u64))
            .map_err(|_| "Image chunk size is not representable on this platform.".to_string())?;
        let count = reader
            .read(&mut buffer[..requested])
            .map_err(|e| format!("Could not read source image: {e}"))?;
        if count == 0 {
            return Err(format!(
                "Source image ended early: expected {expected_size} bytes, read {written}."
            ));
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|e| format!("Could not write image chunk: {e}"))?;
        written = written
            .checked_add(count as u64)
            .ok_or_else(|| "Image byte counter overflowed.".to_string())?;
        report_progress(written);
    }
    let mut extra = [0_u8; 1];
    if reader
        .read(&mut extra)
        .map_err(|e| format!("Could not verify source image length: {e}"))?
        != 0
    {
        return Err("Source image grew after its expected size was recorded.".into());
    }
    writer
        .flush()
        .map_err(|e| format!("Could not flush image output: {e}"))?;
    Ok(written)
}

struct HashingReader<'a, R> {
    inner: &'a mut R,
    hasher: Sha256,
}
impl<'a, R: Read> HashingReader<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }
    fn finish(self) -> String {
        format!("{:x}", self.hasher.finalize())
    }
}
impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        if count > 0 {
            self.hasher.update(&buffer[..count]);
        }
        Ok(count)
    }
}

#[allow(dead_code)]
fn write_verified_stream<R, D, C, P>(
    source: &mut R,
    destination: &mut D,
    image_size: u64,
    destination_size: u64,
    disk_number: u32,
    stable_identity: &str,
    image_sha256: &str,
    supplied_confirmation: &str,
    is_cancelled: C,
    report_progress: P,
) -> Result<String, String>
where
    R: Read,
    D: Read + Write + Seek,
    C: FnMut() -> bool,
    P: FnMut(u64),
{
    validate_erase_confirmation(
        disk_number,
        stable_identity,
        image_sha256,
        supplied_confirmation,
    )?;
    if image_size == 0 || destination_size < image_size {
        return Err(format!("Destination capacity is insufficient or invalid ({} bytes available, {} bytes required). Nothing was written.", destination_size, image_size));
    }
    if image_sha256.len() != 64 || !image_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("The expected image SHA-256 is invalid. Nothing was written.".into());
    }
    destination
        .seek(SeekFrom::Start(0))
        .map_err(|e| format!("Could not position the destination: {e}"))?;
    let mut hashing_source = HashingReader::new(source);
    let written = stream_image(
        &mut hashing_source,
        destination,
        image_size,
        is_cancelled,
        report_progress,
    )?;
    let streamed_sha256 = hashing_source.finish();
    if !streamed_sha256.eq_ignore_ascii_case(image_sha256.trim()) {
        return Err(format!(
            "The source image changed between preflight and streaming (expected {}, streamed {}). The destination was not verified; do not boot from it.",
            image_sha256.trim(), streamed_sha256
        ));
    }
    if written != image_size {
        return Err("The destination write did not complete the expected image length.".into());
    }
    destination
        .flush()
        .map_err(|e| format!("Could not flush the destination: {e}"))?;
    destination
        .seek(SeekFrom::Start(0))
        .map_err(|e| format!("Could not rewind the destination for verification: {e}"))?;
    verify_device_readback_prefix(destination, image_size, image_sha256)
}

fn verify_image_readback<R: Read>(
    reader: &mut R,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<String, String> {
    const CHUNK_SIZE: usize = 1024 * 1024;
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    let mut verified = 0_u64;
    let mut hasher = Sha256::new();
    while verified < expected_size {
        let remaining = expected_size - verified;
        let requested = usize::try_from(remaining.min(CHUNK_SIZE as u64))
            .map_err(|_| "Read-back chunk size is not representable.".to_string())?;
        let count = reader
            .read(&mut buffer[..requested])
            .map_err(|e| format!("Could not read destination for verification: {e}"))?;
        if count == 0 {
            return Err(format!(
                "Destination read-back ended early: expected {expected_size}, verified {verified}."
            ));
        }
        hasher.update(&buffer[..count]);
        verified = verified
            .checked_add(count as u64)
            .ok_or_else(|| "Read-back byte counter overflowed.".to_string())?;
    }
    let mut extra = [0_u8; 1];
    if reader
        .read(&mut extra)
        .map_err(|e| format!("Could not verify destination length: {e}"))?
        != 0
    {
        return Err("Destination contains more data than the source image.".into());
    }
    let actual = format!("{:x}", hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected_sha256.trim()) {
        return Err(format!(
            "Destination SHA-256 mismatch: expected {}, read back {actual}.",
            expected_sha256.trim()
        ));
    }
    Ok(actual)
}

fn verify_device_readback_prefix<R: Read>(
    reader: &mut R,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<String, String> {
    if expected_size == 0
        || expected_sha256.trim().len() != 64
        || !expected_sha256
            .trim()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("The device read-back size or expected SHA-256 is invalid.".into());
    }
    const CHUNK_SIZE: usize = 1024 * 1024;
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    let mut verified = 0_u64;
    let mut hasher = Sha256::new();
    while verified < expected_size {
        let remaining = expected_size - verified;
        let requested = usize::try_from(remaining.min(CHUNK_SIZE as u64))
            .map_err(|_| "Device read-back chunk size is not representable.".to_string())?;
        let count = reader
            .read(&mut buffer[..requested])
            .map_err(|e| format!("Could not read USB device for verification: {e}"))?;
        if count == 0 {
            return Err(format!(
                "USB device read-back ended early: expected {expected_size}, verified {verified}."
            ));
        }
        hasher.update(&buffer[..count]);
        verified = verified
            .checked_add(count as u64)
            .ok_or_else(|| "USB read-back byte counter overflowed.".to_string())?;
    }
    let actual = format!("{:x}", hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected_sha256.trim()) {
        return Err(format!(
            "USB device image-region SHA-256 mismatch: expected {}, read back {actual}.",
            expected_sha256.trim()
        ));
    }
    Ok(actual)
}

fn erase_confirmation_phrase(
    disk_number: u32,
    stable_identity: &str,
    image_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ALLBOOT-ERASE-CONFIRMATION-V1\0");
    hasher.update(disk_number.to_le_bytes());
    hasher.update(stable_identity.trim().as_bytes());
    hasher.update([0]);
    hasher.update(image_sha256.trim().to_ascii_lowercase().as_bytes());
    let digest = hasher.finalize();
    let challenge = digest[..4]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    format!("ERASE DISK {disk_number} {challenge}")
}
fn validate_erase_confirmation(
    disk_number: u32,
    stable_identity: &str,
    image_sha256: &str,
    supplied_phrase: &str,
) -> Result<(), String> {
    if stable_identity.trim().is_empty()
        || image_sha256.trim().len() != 64
        || !image_sha256
            .trim()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(
            "The selected device identity or image hash is invalid. Run preflight again.".into(),
        );
    }
    let expected = erase_confirmation_phrase(disk_number, stable_identity, image_sha256);
    if supplied_phrase != expected {
        return Err("Erase confirmation does not match this exact USB device and image. Nothing was written.".into());
    }
    Ok(())
}

fn open_verified_source_image(
    path: &str,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<File, String> {
    if expected_sha256.trim().len() != 64
        || !expected_sha256
            .trim()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("The expected image SHA-256 is invalid. Inspect the image again.".into());
    }
    let mut file =
        File::open(path).map_err(|e| format!("Could not reopen the selected image: {e}"))?;
    let before = file
        .metadata()
        .map_err(|e| format!("Could not inspect the selected image file: {e}"))?;
    if !before.is_file() || before.len() != expected_size {
        return Err("The selected image is no longer a regular file of the inspected size. Nothing was written.".into());
    }
    const CHUNK_SIZE: usize = 1024 * 1024;
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    let mut remaining = expected_size;
    let mut hasher = Sha256::new();
    while remaining > 0 {
        let requested = remaining.min(CHUNK_SIZE as u64) as usize;
        let count = file
            .read(&mut buffer[..requested])
            .map_err(|e| format!("Could not verify the selected image: {e}"))?;
        if count == 0 {
            return Err(
                "The selected image ended during its integrity check. Nothing was written.".into(),
            );
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|e| format!("Could not finish image integrity check: {e}"))?
        != 0
    {
        return Err(
            "The selected image grew during its integrity check. Nothing was written.".into(),
        );
    }
    let after = file
        .metadata()
        .map_err(|e| format!("Could not re-check the selected image: {e}"))?;
    if !file_metadata_unchanged(&before, &after) {
        return Err(
            "The selected image changed during its integrity check. Nothing was written.".into(),
        );
    }
    let actual = format!("{:x}", hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected_sha256.trim()) {
        return Err("The selected image SHA-256 changed since inspection. Inspect it again. Nothing was written.".into());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Could not rewind the verified image: {e}"))?;
    Ok(file)
}
fn file_metadata_unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

fn inspect_apple_partitioned_hfs(file: &mut File, image_size: u64) -> (bool, bool) {
    if image_size < 1024 || file.seek(SeekFrom::Start(512)).is_err() {
        return (false, false);
    }
    let mut entry = [0_u8; 512];
    if file.read_exact(&mut entry).is_err() || &entry[..2] != b"PM" {
        return (false, false);
    }
    let map_count = u32::from_be_bytes(entry[4..8].try_into().unwrap()) as u64;
    if map_count == 0 || map_count > 128 {
        return (false, false);
    }
    let mut has_hfs_plus = false;
    for index in 0..map_count {
        let Some(offset) = (index + 1).checked_mul(512) else {
            break;
        };
        if offset.checked_add(512).is_none_or(|end| end > image_size)
            || file.seek(SeekFrom::Start(offset)).is_err()
            || file.read_exact(&mut entry).is_err()
        {
            break;
        }
        if &entry[..2] != b"PM" {
            break;
        }
        let start = u32::from_be_bytes(entry[8..12].try_into().unwrap()) as u64;
        let blocks = u32::from_be_bytes(entry[12..16].try_into().unwrap()) as u64;
        let partition_type = String::from_utf8_lossy(&entry[48..80]);
        if (partition_type.trim_end_matches('\0') == "Apple_HFS"
            || partition_type.trim_end_matches('\0') == "Apple_HFSX")
            && start > 0
            && blocks > 0
        {
            let Some(partition_start) = start.checked_mul(512) else {
                continue;
            };
            let Some(header_offset) = partition_start.checked_add(1024) else {
                continue;
            };
            let Some(partition_end) = start.checked_add(blocks).and_then(|v| v.checked_mul(512))
            else {
                continue;
            };
            if partition_end <= image_size
                && header_offset
                    .checked_add(2)
                    .is_some_and(|end| end <= partition_end)
                && file.seek(SeekFrom::Start(header_offset)).is_ok()
            {
                let mut signature = [0_u8; 2];
                if file.read_exact(&mut signature).is_ok()
                    && (&signature == b"H+" || &signature == b"HX")
                {
                    has_hfs_plus = true;
                    break;
                }
            }
        }
    }
    (true, has_hfs_plus)
}

#[derive(Default)]
struct MacOsBootEvidence {
    validated: bool,
    architecture: String,
    checks: Vec<String>,
    supported_models: Vec<String>,
}

#[derive(Clone)]
struct HfsFork {
    logical_size: u64,
    extents: Vec<(u32, u32)>,
}

fn be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}
fn be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}
fn be_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}
fn read_image_at(file: &mut File, offset: u64, output: &mut [u8], image_size: u64) -> bool {
    offset
        .checked_add(output.len() as u64)
        .is_some_and(|end| end <= image_size)
        && file.seek(SeekFrom::Start(offset)).is_ok()
        && file.read_exact(output).is_ok()
}
fn parse_hfs_fork(header: &[u8], offset: usize) -> Option<HfsFork> {
    let logical_size = be_u64(header, offset)?;
    let mut extents = Vec::new();
    for index in 0..8 {
        let start = be_u32(header, offset + 16 + index * 8)?;
        let blocks = be_u32(header, offset + 20 + index * 8)?;
        if blocks > 0 {
            extents.push((start, blocks));
        }
    }
    Some(HfsFork {
        logical_size,
        extents,
    })
}
fn btree_leaf_records(
    file: &mut File,
    base: u64,
    logical_size: u64,
    image_size: u64,
) -> Option<Vec<Vec<u8>>> {
    let mut descriptor = [0_u8; 14];
    if !read_image_at(file, base, &mut descriptor, image_size) || descriptor[8] as i8 != 1 {
        return None;
    }
    let mut header_record = [0_u8; 30];
    if !read_image_at(file, base.checked_add(14)?, &mut header_record, image_size) {
        return None;
    }
    let first_leaf = be_u32(&header_record, 10)? as u64;
    let node_size = be_u16(&header_record, 18)? as usize;
    let total_nodes = be_u32(&header_record, 22)? as u64;
    let tree_bytes = (node_size as u64).checked_mul(total_nodes)?;
    // Treat filesystem metadata as untrusted input. A malformed image can claim
    // enormous B-trees and otherwise force excessive allocation or CPU use while
    // the user is only trying to inspect an image.
    const MAX_BTREE_SCAN_BYTES: u64 = 128 * 1024 * 1024;
    const MAX_BTREE_RECORDS: usize = 250_000;
    if node_size < 512
        || node_size > 65_536
        || total_nodes == 0
        || total_nodes > 1_000_000
        || tree_bytes > logical_size
        || tree_bytes > MAX_BTREE_SCAN_BYTES
        || base.checked_add(tree_bytes)? > image_size
        || first_leaf >= total_nodes
    {
        return None;
    }
    let mut records = Vec::new();
    let mut visited = vec![false; total_nodes as usize];
    let mut node = first_leaf;
    for _ in 0..total_nodes {
        if node == 0 {
            return Some(records);
        }
        let slot = visited.get_mut(node as usize)?;
        if *slot {
            return None;
        }
        *slot = true;
        let node_offset = base.checked_add(node.checked_mul(node_size as u64)?)?;
        let mut raw = vec![0_u8; node_size];
        if !read_image_at(file, node_offset, &mut raw, image_size) {
            return None;
        }
        let forward_link = be_u32(&raw, 0)? as u64;
        if raw[8] as i8 != -1 {
            return None;
        }
        let record_count = be_u16(&raw, 10)? as usize;
        let table_start = node_size.checked_sub(2usize.checked_mul(record_count + 1)?)?;
        let mut offsets = Vec::with_capacity(record_count + 1);
        for index in 0..=record_count {
            offsets.push(be_u16(&raw, node_size.checked_sub(2 * (index + 1))?)? as usize);
        }
        for index in 0..record_count {
            let start = offsets[index];
            let end = offsets[index + 1];
            if start < 14 || start >= end || end > table_start {
                return None;
            }
            if records.len() >= MAX_BTREE_RECORDS {
                return None;
            }
            records.push(raw[start..end].to_vec());
        }
        node = forward_link;
        if node >= total_nodes {
            return None;
        }
    }
    None
}
fn hfs_folder_path(folders: &HashMap<u32, (u32, String)>, folder_id: u32) -> Option<String> {
    if folder_id == 2 {
        return Some(String::new());
    }
    let mut components = Vec::new();
    let mut current = folder_id;
    let mut visited = Vec::new();
    for _ in 0..64 {
        if current == 2 {
            components.reverse();
            return Some(components.join("/"));
        }
        if current == 1 || visited.contains(&current) {
            return None;
        }
        visited.push(current);
        let (parent, name) = folders.get(&current)?;
        components.push(name.clone());
        current = *parent;
    }
    None
}
fn read_hfs_fork_range(
    file: &mut File,
    partition_start: u64,
    block_size: u64,
    extents: &[(u32, u32)],
    logical_size: u64,
    offset: u64,
    output: &mut [u8],
    image_size: u64,
) -> bool {
    let Some(end) = offset.checked_add(output.len() as u64) else {
        return false;
    };
    if end > logical_size || block_size == 0 {
        return false;
    }
    let mut logical_position = offset;
    let mut written = 0_usize;
    while written < output.len() {
        let logical_block = logical_position / block_size;
        let within_block = logical_position % block_size;
        let mut blocks_before = 0_u64;
        let mut physical_block = None;
        for (start, count) in extents {
            let count = *count as u64;
            if logical_block >= blocks_before && logical_block < blocks_before + count {
                physical_block = Some(*start as u64 + logical_block - blocks_before);
                break;
            }
            blocks_before = blocks_before.saturating_add(count);
        }
        let Some(physical_block) = physical_block else {
            return false;
        };
        let physical_offset = partition_start
            .checked_add(physical_block.checked_mul(block_size).unwrap_or(u64::MAX))
            .and_then(|value| value.checked_add(within_block));
        let Some(physical_offset) = physical_offset else {
            return false;
        };
        let count = (block_size - within_block).min((output.len() - written) as u64) as usize;
        if !read_image_at(
            file,
            physical_offset,
            &mut output[written..written + count],
            image_size,
        ) {
            return false;
        }
        written += count;
        logical_position += count as u64;
    }
    true
}
fn hfs_fork_extents_complete(
    file: &mut File,
    partition_start: u64,
    block_size: u64,
    total_blocks: u64,
    extents_fork: &HfsFork,
    file_id: u32,
    fork_type: u8,
    initial_extents: &[(u32, u32)],
    logical_size: u64,
    image_size: u64,
) -> Option<Vec<(u32, u32)>> {
    let first_extent = extents_fork.extents.first()?;
    let extents_base =
        partition_start.checked_add((first_extent.0 as u64).checked_mul(block_size)?)?;
    let records = btree_leaf_records(file, extents_base, extents_fork.logical_size, image_size)?;
    let mut overflow = Vec::new();
    for record in records {
        if record.len() < 76 || record[2] != fork_type || be_u32(&record, 4)? != file_id {
            continue;
        }
        let start_block = be_u32(&record, 8)?;
        let mut extents = Vec::new();
        for index in 0..8 {
            let start = be_u32(&record, 12 + index * 8)?;
            let count = be_u32(&record, 16 + index * 8)?;
            if count > 0 {
                extents.push((start, count));
            }
        }
        overflow.push((start_block, extents));
    }
    overflow.sort_by_key(|(start, _)| *start);
    let mut result = initial_extents.to_vec();
    let mut expected_start: u64 = result.iter().map(|(_, count)| *count as u64).sum();
    for (start, additional) in overflow {
        if start as u64 != expected_start {
            return None;
        }
        expected_start = expected_start.checked_add(
            additional
                .iter()
                .map(|(_, count)| *count as u64)
                .sum::<u64>(),
        )?;
        result.extend(additional);
    }
    if result.iter().any(|(start, count)| {
        (*start as u64)
            .checked_add(*count as u64)
            .is_none_or(|end| end > total_blocks)
    }) {
        return None;
    }
    let required_blocks = logical_size.checked_add(block_size.checked_sub(1)?)? / block_size;
    let mapped_blocks: u64 = result.iter().map(|(_, count)| *count as u64).sum();
    if mapped_blocks < required_blocks {
        return None;
    }
    Some(result)
}
fn hfs_fork_has_udif_trailer(
    file: &mut File,
    partition_start: u64,
    block_size: u64,
    total_blocks: u64,
    extents_fork: &HfsFork,
    file_id: u32,
    fork: &HfsFork,
    image_size: u64,
) -> bool {
    let Some(extents) = hfs_fork_extents_complete(
        file,
        partition_start,
        block_size,
        total_blocks,
        extents_fork,
        file_id,
        0,
        &fork.extents,
        fork.logical_size,
        image_size,
    ) else {
        return false;
    };
    if fork.logical_size < 512 {
        return false;
    }
    let mut trailer = [0_u8; 512];
    read_hfs_fork_range(
        file,
        partition_start,
        block_size,
        &extents,
        fork.logical_size,
        fork.logical_size - 512,
        &mut trailer,
        image_size,
    ) && &trailer[..4] == b"koly"
}

fn hfs_pe_architecture(
    file: &mut File,
    partition_start: u64,
    block_size: u64,
    fork: &HfsFork,
    image_size: u64,
) -> Option<String> {
    let mut header = [0_u8; 64];
    if !read_hfs_fork_range(
        file,
        partition_start,
        block_size,
        &fork.extents,
        fork.logical_size,
        0,
        &mut header,
        image_size,
    ) || &header[..2] != b"MZ"
    {
        return None;
    }
    let pe_offset = u32::from_le_bytes(header[0x3c..0x40].try_into().ok()?) as u64;
    if pe_offset.checked_add(6)? > fork.logical_size {
        return None;
    }
    let mut pe = [0_u8; 6];
    if !read_hfs_fork_range(
        file,
        partition_start,
        block_size,
        &fork.extents,
        fork.logical_size,
        pe_offset,
        &mut pe,
        image_size,
    ) || &pe[..4] != b"PE\0\0"
    {
        return None;
    }
    match u16::from_le_bytes(pe[4..6].try_into().ok()?) {
        0x8664 => Some("x86_64".into()),
        0xaa64 => Some("ARM64".into()),
        _ => None,
    }
}
fn plist_string_array(bytes: &[u8], key: &str) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let key_tag = format!("<key>{key}</key>");
    let Some(after_key) = text.split_once(&key_tag).map(|(_, rest)| rest) else {
        return Vec::new();
    };
    let Some(after_array) = after_key.split_once("<array>").map(|(_, rest)| rest) else {
        return Vec::new();
    };
    let Some(array) = after_array
        .split_once("</array>")
        .map(|(content, _)| content)
    else {
        return Vec::new();
    };
    array
        .split("<string>")
        .skip(1)
        .filter_map(|part| {
            part.split_once("</string>")
                .map(|(value, _)| value.trim().to_string())
        })
        .filter(|value| !value.is_empty())
        .collect()
}

fn inspect_macos_boot_structure(file: &mut File, image_size: u64) -> MacOsBootEvidence {
    let mut evidence = MacOsBootEvidence::default();
    let mut map_entry = [0_u8; 512];
    if !read_image_at(file, 512, &mut map_entry, image_size) || &map_entry[..2] != b"PM" {
        return evidence;
    }
    let map_count = match be_u32(&map_entry, 4) {
        Some(value) if value > 0 && value <= 128 => value as u64,
        _ => return evidence,
    };
    for index in 0..map_count {
        let Some(map_offset) = (index + 1).checked_mul(512) else {
            return evidence;
        };
        if !read_image_at(file, map_offset, &mut map_entry, image_size) || &map_entry[..2] != b"PM"
        {
            return evidence;
        }
        let start = match be_u32(&map_entry, 8) {
            Some(value) => value as u64,
            None => continue,
        };
        let blocks = match be_u32(&map_entry, 12) {
            Some(value) => value as u64,
            None => continue,
        };
        let partition_type = String::from_utf8_lossy(&map_entry[48..80]);
        if !matches!(
            partition_type.trim_end_matches('\0'),
            "Apple_HFS" | "Apple_HFSX"
        ) || start == 0
            || blocks == 0
        {
            continue;
        }
        let Some(partition_start) = start.checked_mul(512) else {
            continue;
        };
        let Some(partition_bytes) = blocks.checked_mul(512) else {
            continue;
        };
        let Some(partition_end) = partition_start.checked_add(partition_bytes) else {
            continue;
        };
        if partition_end > image_size {
            continue;
        }
        let mut volume_header = [0_u8; 512];
        if !read_image_at(
            file,
            partition_start.saturating_add(1024),
            &mut volume_header,
            image_size,
        ) || !matches!(&volume_header[..2], b"H+" | b"HX")
        {
            continue;
        }
        let Some(block_size) = be_u32(&volume_header, 40).map(|value| value as u64) else {
            continue;
        };
        let Some(total_blocks) = be_u32(&volume_header, 44).map(|value| value as u64) else {
            continue;
        };
        if block_size < 512
            || block_size > 65_536
            || !block_size.is_power_of_two()
            || total_blocks == 0
            || total_blocks
                .checked_mul(block_size)
                .is_none_or(|bytes| bytes > partition_bytes)
        {
            continue;
        }
        let blessed_folder_id = be_u32(&volume_header, 80).unwrap_or(0);
        let Some(extents_fork) = parse_hfs_fork(&volume_header, 192) else {
            continue;
        };
        let Some(catalog_fork) = parse_hfs_fork(&volume_header, 272) else {
            continue;
        };
        let Some(catalog_first) = catalog_fork.extents.first() else {
            continue;
        };
        let Some(catalog_base) =
            partition_start.checked_add((catalog_first.0 as u64).saturating_mul(block_size))
        else {
            continue;
        };
        let Some(catalog_records) =
            btree_leaf_records(file, catalog_base, catalog_fork.logical_size, image_size)
        else {
            continue;
        };
        let mut folders: Vec<(u32, u32, String)> = Vec::new();
        let mut files: Vec<(u32, String, u32, HfsFork)> = Vec::new();
        for record in catalog_records {
            if record.len() < 10 {
                continue;
            }
            let Some(key_length) = be_u16(&record, 0).map(|value| value as usize) else {
                continue;
            };
            let key_end = 2usize.saturating_add(key_length);
            let Some(name_length) = be_u16(&record, 6).map(|value| value as usize) else {
                continue;
            };
            let name_end = 8usize.saturating_add(name_length.saturating_mul(2));
            if key_end != name_end || name_end.saturating_add(2) > record.len() {
                continue;
            }
            let Some(parent_id) = be_u32(&record, 2) else {
                continue;
            };
            let name_units: Vec<u16> = record[8..name_end]
                .chunks_exact(2)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                .collect();
            let name = String::from_utf16(&name_units).unwrap_or_default();
            let Some(record_type) = be_u16(&record, name_end) else {
                continue;
            };
            match record_type {
                1 if record.len() >= name_end + 12 => {
                    if let Some(folder_id) = be_u32(&record, name_end + 8) {
                        folders.push((folder_id, parent_id, name));
                    }
                }
                2 if record.len() >= name_end + 168 => {
                    let Some(file_id) = be_u32(&record, name_end + 8) else {
                        continue;
                    };
                    let Some(fork) = parse_hfs_fork(&record, name_end + 88) else {
                        continue;
                    };
                    files.push((parent_id, name, file_id, fork));
                }
                _ => {}
            }
        }
        // Resolve HFS catalog parent IDs through a hash map. Searching the full
        // folder vector for every file made large installer catalogs quadratic.
        let mut folder_lookup = HashMap::with_capacity(folders.len());
        for (id, parent, name) in &folders {
            folder_lookup.entry(*id).or_insert((*parent, name.clone()));
        }
        let folder_path = |folder_id: u32| hfs_folder_path(&folder_lookup, folder_id);
        let blessed_path = folder_path(blessed_folder_id);
        let blessed_core_services = blessed_path
            .as_deref()
            .is_some_and(|path| path == "System/Library/CoreServices");
        let installer_bundle = folders.iter().any(|(id, parent, name)| {
            *parent == 2
                && name == "Install macOS Ventura.app"
                && folder_path(*id).as_deref() == Some("Install macOS Ventura.app")
        });
        let mut boot_architecture = None;
        let mut platform_support = false;
        let mut platform_models = Vec::new();
        let mut base_system = false;
        let mut base_system_id = None;
        let mut base_system_fork = None;
        let mut base_system_udif = false;
        let mut shared_support = false;
        let mut shared_support_udif = false;
        let mut shared_support_id = None;
        let mut shared_support_fork = None;
        for (parent, name, file_id, fork) in &files {
            // Only four catalog entries can contribute to the boot evidence.
            // Avoid resolving parent paths for every unrelated file in a large
            // installer volume.
            if !matches!(
                name.as_str(),
                "boot.efi" | "PlatformSupport.plist" | "BaseSystem.dmg" | "SharedSupport.dmg"
            ) {
                continue;
            }
            let Some(parent_path) = folder_path(*parent) else {
                continue;
            };
            let path = if parent_path.is_empty() {
                name.clone()
            } else {
                format!("{parent_path}/{name}")
            };
            match path.as_str() {
                "System/Library/CoreServices/boot.efi" if blessed_core_services => {
                    boot_architecture =
                        hfs_pe_architecture(file, partition_start, block_size, fork, image_size);
                }
                "System/Library/CoreServices/PlatformSupport.plist" => {
                    let read_length = fork.logical_size.min(16_384) as usize;
                    let mut plist = vec![0_u8; read_length];
                    let read_ok = read_length > 0
                        && read_hfs_fork_range(
                            file,
                            partition_start,
                            block_size,
                            &fork.extents,
                            fork.logical_size,
                            0,
                            &mut plist,
                            image_size,
                        );
                    if read_ok {
                        platform_models = plist_string_array(&plist, "SupportedModelProperties");
                        platform_support = plist
                            .windows(b"SupportedBoardIds".len())
                            .any(|w| w == b"SupportedBoardIds")
                            && !platform_models.is_empty();
                    }
                }
                "BaseSystem/BaseSystem.dmg" => {
                    base_system = fork.logical_size > 0;
                    base_system_id = Some(*file_id);
                    base_system_fork = Some(fork.clone());
                }
                "Install macOS Ventura.app/Contents/SharedSupport/SharedSupport.dmg" => {
                    shared_support = fork.logical_size > 0;
                    shared_support_id = Some(*file_id);
                    shared_support_fork = Some(fork.clone());
                }
                _ => {}
            }
        }
        let architecture = boot_architecture.unwrap_or_default();
        let Some(shared_id) = shared_support_id else {
            if blessed_core_services {
                evidence
                    .checks
                    .push("Blessed CoreServices folder verified".into());
            }
            if !architecture.is_empty() {
                evidence
                    .checks
                    .push(format!("EFI boot.efi verified ({architecture})"));
            }
            if platform_support {
                evidence.checks.push("PlatformSupport.plist found".into());
            }
            if base_system {
                evidence.checks.push("BaseSystem.dmg found".into());
            }
            if installer_bundle {
                evidence
                    .checks
                    .push("Ventura installer application found".into());
            }
            evidence.architecture = architecture;
            evidence.supported_models = platform_models;
            return evidence;
        };
        if let (Some(file_id), Some(fork)) = (base_system_id, base_system_fork) {
            base_system_udif = hfs_fork_has_udif_trailer(
                file,
                partition_start,
                block_size,
                total_blocks,
                &extents_fork,
                file_id,
                &fork,
                image_size,
            );
        }
        if let Some(fork) = shared_support_fork {
            shared_support_udif = hfs_fork_has_udif_trailer(
                file,
                partition_start,
                block_size,
                total_blocks,
                &extents_fork,
                shared_id,
                &fork,
                image_size,
            );
        }
        if blessed_core_services {
            evidence
                .checks
                .push("Blessed CoreServices folder verified".into());
        }
        if !architecture.is_empty() {
            evidence
                .checks
                .push(format!("EFI boot.efi verified ({architecture})"));
        }
        if platform_support {
            evidence.checks.push("PlatformSupport.plist found".into());
        }
        if base_system {
            evidence.checks.push("BaseSystem.dmg found".into());
        }
        if base_system_udif {
            evidence
                .checks
                .push("BaseSystem.dmg extent map and UDIF trailer verified".into());
        }
        if installer_bundle {
            evidence
                .checks
                .push("Ventura installer application found".into());
        }
        if shared_support {
            evidence.checks.push("SharedSupport.dmg found".into());
        }
        if shared_support_udif {
            evidence
                .checks
                .push("SharedSupport.dmg extent map and UDIF trailer verified".into());
        }
        evidence.architecture = architecture;
        evidence.supported_models = platform_models;
        evidence.validated = blessed_core_services
            && !evidence.architecture.is_empty()
            && platform_support
            && base_system
            && base_system_udif
            && installer_bundle
            && shared_support
            && shared_support_udif;
        return evidence;
    }
    evidence
}

fn target_model_is_supported(supported_models: &[String], selected_model: Option<&str>) -> bool {
    selected_model
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .is_some_and(|model| {
            supported_models
                .iter()
                .any(|supported| supported.eq_ignore_ascii_case(model))
        })
}

fn image_write_readiness(
    extension: &str,
    el_torito_boot_record: bool,
    udif_signature: bool,
    apple_partition_map_signature: bool,
    hfs_plus_signature: bool,
    macos_installer_validated: bool,
    target_model_supported: bool,
) -> &'static str {
    if udif_signature || extension.eq_ignore_ascii_case("dmg") {
        "Not ready: macOS DMG requires Apple's installer-specific workflow, which is not implemented."
    } else if matches!(
        extension.to_ascii_lowercase().as_str(),
        "wim" | "esd" | "vhd" | "vhdx"
    ) {
        "Not ready: this is a container format, not a directly writable boot image."
    } else if apple_partition_map_signature
        && hfs_plus_signature
        && macos_installer_validated
        && target_model_supported
    {
        "macOS installer structure verified and the selected Mac model is listed in PlatformSupport.plist. Firmware startup policy and the safe writing method still require confirmation; writing remains disabled."
    } else if apple_partition_map_signature && hfs_plus_signature && macos_installer_validated {
        "macOS installer structure verified, but a supported target Mac model has not been selected. Choose a model from the detected compatibility list before any write; writing remains disabled."
    } else if apple_partition_map_signature && hfs_plus_signature {
        "Not ready: Apple Partition Map and HFS+ volume detected, but the complete macOS boot files and installer payload could not be validated; writing remains disabled."
    } else if apple_partition_map_signature {
        "Not ready: Apple Partition Map detected, but a valid HFS+ volume and macOS boot structure were not confirmed."
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

const WINDOWS_DRIVE_HELPER_SOURCE: &str = r#"# ALLBOOT_DRIVE_HELPER_VERSION=1
$ErrorActionPreference = 'Stop'
$disks = @(Get-Disk | Select-Object Number,FriendlyName,BusType,Size,SerialNumber,UniqueId,PartitionStyle,IsBoot,IsSystem)
ConvertTo-Json -InputObject $disks -Compress
"#;

const MACOS_DRIVE_HELPER_SOURCE: &str = r#"#!/bin/sh
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
"#;

#[cfg(target_os = "windows")]
fn drive_helper_source() -> &'static str {
    WINDOWS_DRIVE_HELPER_SOURCE
}

#[cfg(target_os = "macos")]
fn drive_helper_source() -> &'static str {
    MACOS_DRIVE_HELPER_SOURCE
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn drive_helper_source() -> &'static str {
    ""
}

fn helper_version_supported(contents: &str) -> bool {
    contents == drive_helper_source()
}
fn valid_mac_model_identifier(model: &str) -> bool {
    let model = model.trim();
    !model.is_empty()
        && model.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == ',' || character == '.'
        })
}

#[tauri::command]
fn detect_target_mac_model() -> Result<Option<String>, String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("sysctl")
            .args(["-n", "hw.model"])
            .output()
            .map_err(|e| format!("Could not query this Mac's hardware model: {e}"))?;
        if !output.status.success() {
            return Err("macOS did not provide this Mac's hardware model.".into());
        }
        let model = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !valid_mac_model_identifier(&model) {
            return Err("macOS returned an invalid hardware model identifier.".into());
        }
        return Ok(Some(model));
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(None)
    }
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

    let source = drive_helper_source();
    if source.is_empty() {
        return Err("AllBoot Drive Helper currently supports Windows and macOS.".into());
    }
    if std::fs::read_to_string(&path)
        .map(|contents| helper_version_supported(&contents))
        .unwrap_or(false)
    {
        return Ok(path.to_string_lossy().to_string());
    }

    let temporary = path.with_extension(format!("install-{}.tmp", std::process::id()));
    let backup = path.with_extension(format!("backup-{}", std::process::id()));
    let mut staged = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| format!("Could not create a staged helper installer file: {e}"))?;
    use std::io::Write as _;
    staged
        .write_all(source.as_bytes())
        .and_then(|_| staged.sync_all())
        .map_err(|e| {
            let _ = std::fs::remove_file(&temporary);
            format!("Could not write the staged drive helper: {e}")
        })?;
    drop(staged);

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) =
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o700))
        {
            let _ = std::fs::remove_file(&temporary);
            return Err(format!("Could not secure the staged macOS helper: {error}"));
        }
    }

    let staged_contents = std::fs::read_to_string(&temporary)
        .map_err(|e| format!("Could not verify the staged helper: {e}"))?;
    if !helper_version_supported(&staged_contents) {
        let _ = std::fs::remove_file(&temporary);
        return Err("The staged helper failed its exact source and version check.".into());
    }

    let had_previous = path.exists();
    if had_previous {
        if backup.exists() {
            let _ = std::fs::remove_file(&temporary);
            return Err("A previous helper-install recovery file already exists. Resolve it before reinstalling.".into());
        }
        std::fs::rename(&path, &backup).map_err(|e| {
            let _ = std::fs::remove_file(&temporary);
            format!("Could not safely stage the previous helper for replacement: {e}")
        })?;
    }

    if let Err(error) = std::fs::rename(&temporary, &path) {
        if had_previous {
            let _ = std::fs::rename(&backup, &path);
        }
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("Could not activate the verified helper. The previous helper was restored when possible: {error}"));
    }

    let installed_contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Could not verify the installed helper contents: {e}"))?;
    if !helper_version_supported(&installed_contents) || !path.is_file() {
        let _ = std::fs::remove_file(&path);
        if had_previous {
            let _ = std::fs::rename(&backup, &path);
        }
        return Err("The activated helper failed verification. The previous helper was restored when possible.".into());
    }

    if had_previous {
        std::fs::remove_file(&backup)
            .map_err(|e| format!("The new helper is installed and verified, but the old recovery copy could not be removed: {e}"))?;
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

#[cfg(any(target_os = "windows", target_os = "macos", test))]
fn raw_device_path(disk_number: u32) -> Result<String, String> {
    if disk_number == 0 {
        return Err("Disk zero is blocked from raw-device access by AllBoot safety policy.".into());
    }
    #[cfg(target_os = "windows")]
    {
        return Ok(format!(r"\\.\PhysicalDrive{disk_number}"));
    }
    #[cfg(target_os = "macos")]
    {
        return Ok(format!("/dev/rdisk{disk_number}"));
    }
    #[cfg(all(test, not(any(target_os = "windows", target_os = "macos"))))]
    {
        Err("Raw physical-device access is supported only on Windows and macOS.".into())
    }
}

#[cfg(target_os = "windows")]
#[allow(dead_code)] // Activated only by the future, separately confirmed physical-write command.
fn open_raw_device_exclusive(disk_number: u32) -> Result<File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    let path = raw_device_path(disk_number)?;
    std::fs::OpenOptions::new().read(true).write(true).share_mode(0).custom_flags(0x8000_0000).open(&path)
        .map_err(|e| format!("Could not open {path} exclusively. Close applications using the USB drive and ensure AllBoot has the required permissions: {e}"))
}

#[cfg(target_os = "macos")]
#[allow(dead_code)] // Activated only by the future, separately confirmed physical-write command.
fn open_raw_device_exclusive(disk_number: u32) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = raw_device_path(disk_number)?;
    std::fs::OpenOptions::new().read(true).write(true).custom_flags(0x880).open(&path)
        .map_err(|e| format!("Could not open {path} exclusively. Unmount the external disk and grant AllBoot the required permissions: {e}"))
}

#[tauri::command]
async fn inspect_image(app: tauri::AppHandle, path: String) -> Result<ImageInspection, String> {
    tauri::async_runtime::spawn_blocking(move || inspect_image_sync(path, Some(app)))
        .await
        .map_err(|e| format!("Image inspection task failed: {e}"))?
}

fn inspect_image_sync(
    path: String,
    progress_app: Option<tauri::AppHandle>,
) -> Result<ImageInspection, String> {
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
    // A larger sequential buffer reduces per-read overhead for multi-gigabyte
    // installers while keeping memory use bounded to a few MiB.
    let mut buffer = vec![0_u8; 4 * 1024 * 1024];
    let total_bytes = metadata.len().max(1);
    let mut processed_bytes = 0_u64;
    let mut last_percent = u8::MAX;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| format!("Could not hash image: {e}"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        processed_bytes += count as u64;
        let percent = ((processed_bytes as u128 * 100) / total_bytes as u128).min(100) as u8;
        if percent != last_percent {
            last_percent = percent;
            if let Some(app) = &progress_app {
                use tauri::Emitter;
                let _ = app.emit(
                    "image-inspection-progress",
                    format!("Hashing image: {percent}%"),
                );
            }
        }
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

    let (apple_partition_map_signature, hfs_plus_signature) =
        inspect_apple_partitioned_hfs(&mut file, metadata.len());
    if let Some(app) = &progress_app {
        use tauri::Emitter;
        let _ = app.emit(
            "image-inspection-progress",
            "Checking Apple boot metadata, EFI loader, and macOS installer payloads…",
        );
    }
    let macos_boot = inspect_macos_boot_structure(&mut file, metadata.len());

    let detected_format = if udif_signature {
        "Apple UDIF disk image (DMG)".to_string()
    } else if apple_partition_map_signature && hfs_plus_signature && macos_boot.validated {
        "Validated macOS installer (Apple Partition Map + HFS+)".to_string()
    } else if apple_partition_map_signature && hfs_plus_signature {
        "Apple Partition Map with HFS+ volume".to_string()
    } else if apple_partition_map_signature {
        "Apple Partition Map disk image".to_string()
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
    } else if apple_partition_map_signature && hfs_plus_signature && macos_boot.validated {
        format!("macOS installer boot structures validated, including the blessed CoreServices folder, {} EFI bootloader, BaseSystem and SharedSupport DMG payloads. Exact target-Mac compatibility still needs confirmation.", macos_boot.architecture)
    } else if apple_partition_map_signature && hfs_plus_signature {
        "Apple Partition Map and HFS+ volume detected, but the complete macOS boot and installer payload structure could not be validated.".into()
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

    // Hash once during inspection. The read-only preflight reopens the source and
    // recalculates SHA-256 immediately before any future write, avoiding a second
    // full pass over very large images here while preserving the write-time integrity gate.
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

    let write_compatibility = if apple_partition_map_signature && hfs_plus_signature && macos_boot.validated {
        "macOS installer structure verified; target Mac model and safe USB writing method still need confirmation"
    } else if apple_partition_map_signature && hfs_plus_signature {
        "Apple partition map and HFS+ detected; full macOS installer boot structure is not verified"
    } else {
        image_write_compatibility(
            &extension,
            iso9660_signature,
            el_torito_boot_record,
            udif_signature,
        )
    }
    .to_string();

    Ok(ImageInspection {
        name,
        path,
        size_bytes: metadata.len(),
        extension,
        detected_format,
        iso9660_signature,
        el_torito_boot_record,
        apple_partition_map_signature,
        hfs_plus_signature,
        udif_signature,
        macos_candidate,
        macos_installer_validated: macos_boot.validated,
        macos_boot_architecture: macos_boot.architecture,
        macos_boot_evidence: macos_boot.checks,
        macos_supported_models: macos_boot.supported_models,
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
    target_mac_model: Option<String>,
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
        if !windows_disk_identity_matches(&actual_id, &expected_unique_id) {
            return Err("The selected USB device identity changed since selection. Scan again and re-select the intended drive. Nothing was written.".into());
        }
        let disk_size = disk.size.unwrap_or(0);
        let image = inspect_image_sync(image_path, None)?;
        if !image.sha256.eq_ignore_ascii_case(expected_sha256.trim()) {
            return Err("The selected image changed after inspection. Re-select the image and run preflight again. Nothing was written.".into());
        }
        if image.size_bytes > disk_size {
            return Err(format!("The image is larger than the selected USB drive ({} bytes available, {} bytes required). Nothing was written.", disk_size, image.size_bytes));
        }
        let target_model_supported =
            target_model_is_supported(&image.macos_supported_models, target_mac_model.as_deref());
        let write_readiness = image_write_readiness(
            &image.extension,
            image.el_torito_boot_record,
            image.udif_signature,
            image.apple_partition_map_signature,
            image.hfs_plus_signature,
            image.macos_installer_validated,
            target_model_supported,
        )
        .to_string();
        let confirmation_phrase = erase_confirmation_phrase(disk_number, &actual_id, &image.sha256);
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
            confirmation_phrase,
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
        let image = inspect_image_sync(image_path, None)?;

        if !image.sha256.eq_ignore_ascii_case(expected_sha256.trim()) {
            return Err("The selected image changed after inspection. Re-select the image and run preflight again. Nothing was written.".into());
        }
        if image.size_bytes > disk_size {
            return Err(format!("The image is larger than the selected external disk ({} bytes available, {} bytes required). Nothing was written.", disk_size, image.size_bytes));
        }
        let target_model_supported =
            target_model_is_supported(&image.macos_supported_models, target_mac_model.as_deref());
        let write_readiness = image_write_readiness(
            &image.extension,
            image.el_torito_boot_record,
            image.udif_signature,
            image.apple_partition_map_signature,
            image.hfs_plus_signature,
            image.macos_installer_validated,
            target_model_supported,
        )
        .to_string();
        let confirmation_phrase = erase_confirmation_phrase(disk_number, &stable_id, &image.sha256);
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
            confirmation_phrase,
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
    fn resolves_hfs_catalog_paths_with_parent_lookup_and_rejects_cycles() {
        let folders = HashMap::from([
            (10, (2, "System".to_string())),
            (11, (10, "Library".to_string())),
            (12, (11, "CoreServices".to_string())),
        ]);
        assert_eq!(
            hfs_folder_path(&folders, 12).as_deref(),
            Some("System/Library/CoreServices")
        );
        assert_eq!(hfs_folder_path(&folders, 2).as_deref(), Some(""));
        assert_eq!(hfs_folder_path(&folders, 999), None);

        let cyclic = HashMap::from([
            (10, (11, "First".to_string())),
            (11, (10, "Second".to_string())),
        ]);
        assert_eq!(hfs_folder_path(&cyclic, 10), None);
    }

    #[test]
    fn rejects_oversized_hfs_btree_before_scanning_or_allocating_records() {
        let path = std::env::temp_dir().join(format!(
            "allboot-oversized-btree-{}-{}.img",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let node_size = 65_536_u64;
        let total_nodes = 2_049_u64;
        let tree_bytes = node_size * total_nodes;
        let file = fs::File::create(&path).expect("create sparse B-tree fixture");
        file.set_len(tree_bytes)
            .expect("size sparse B-tree fixture");
        drop(file);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open B-tree fixture");
        let mut descriptor = [0_u8; 14];
        descriptor[8] = 1;
        file.write_all(&descriptor)
            .expect("write B-tree descriptor");
        let mut header = [0_u8; 30];
        header[10..14].copy_from_slice(&1_u32.to_be_bytes());
        header[18..20].copy_from_slice(&(node_size as u16).to_be_bytes());
        header[22..26].copy_from_slice(&(total_nodes as u32).to_be_bytes());
        file.seek(SeekFrom::Start(14))
            .expect("seek to B-tree header");
        file.write_all(&header).expect("write B-tree header");
        drop(file);

        let mut file = fs::File::open(&path).expect("open sparse B-tree fixture for inspection");
        assert!(btree_leaf_records(&mut file, 0, tree_bytes, tree_bytes).is_none());
        fs::remove_file(path).expect("remove sparse B-tree fixture");
    }

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
    fn mac_model_identifier_validation_rejects_malformed_values() {
        assert!(valid_mac_model_identifier("MacBookPro18,3"));
        assert!(valid_mac_model_identifier("Mac14.7"));
        assert!(!valid_mac_model_identifier(""));
        assert!(!valid_mac_model_identifier("   "));
        assert!(!valid_mac_model_identifier("MacBook Pro"));
        assert!(!valid_mac_model_identifier("../MacBookPro18,3"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_mac_host_does_not_guess_a_target_mac_model() {
        assert_eq!(detect_target_mac_model().unwrap(), None);
    }

    #[test]
    fn target_mac_model_must_match_installer_platform_support() {
        let models = vec!["MacBookPro14,2".to_string(), "MacBookAir9,1".to_string()];
        assert!(target_model_is_supported(&models, Some("MacBookPro14,2")));
        assert!(target_model_is_supported(&models, Some("macbookair9,1")));
        assert!(!target_model_is_supported(&models, None));
        assert!(!target_model_is_supported(&models, Some("MacBookPro99,9")));
        assert!(!target_model_is_supported(&models, Some("  ")));
    }

    #[test]
    fn write_readiness_never_confuses_preflight_with_write_support() {
        assert!(
            image_write_readiness("iso", true, false, false, false, false, false)
                .starts_with("Candidate only")
        );
        assert!(
            image_write_readiness("iso", false, false, false, false, false, false)
                .contains("no El Torito")
        );
        assert!(
            image_write_readiness("dmg", false, true, false, false, false, false)
                .contains("Apple's installer")
        );
        assert!(
            image_write_readiness("wim", false, false, false, false, false, false)
                .contains("container format")
        );
        assert!(
            image_write_readiness("vhdx", false, false, false, false, false, false)
                .contains("container format")
        );
        assert!(
            image_write_readiness("img", false, false, false, false, false, false)
                .contains("partition layout")
        );
        assert!(
            image_write_readiness("unknown", false, false, false, false, false, false)
                .contains("not supported")
        );
        assert!(
            image_write_readiness("iso", false, false, true, true, false, false)
                .contains("could not be validated")
        );
        assert!(
            image_write_readiness("iso", false, false, true, true, true, false)
                .contains("supported target Mac model has not been selected")
        );
        assert!(
            image_write_readiness("iso", false, false, true, true, true, true)
                .contains("selected Mac model is listed")
        );
        assert!(
            image_write_readiness("iso", false, false, true, false, false, false)
                .contains("valid HFS+")
        );
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
    fn windows_disk_identity_requires_exact_nonempty_stable_match() {
        assert!(windows_disk_identity_matches(
            "USB-SERIAL-1",
            "USB-SERIAL-1"
        ));
        assert!(windows_disk_identity_matches(
            " usb-serial-1 ",
            "USB-SERIAL-1"
        ));
        assert!(!windows_disk_identity_matches(
            "USB-SERIAL-2",
            "USB-SERIAL-1"
        ));
        assert!(!windows_disk_identity_matches("", "USB-SERIAL-1"));
        assert!(!windows_disk_identity_matches("USB-SERIAL-1", ""));
        assert!(!windows_disk_identity_matches("   ", "USB-SERIAL-1"));
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
        let result = inspect_image_sync(path.to_string_lossy().to_string(), None).unwrap();
        assert!(result.iso9660_signature);
        assert!(result.el_torito_boot_record);
        assert!(!result.udif_signature);
        assert_eq!(result.sha256.len(), 64);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn detects_apple_partition_map_and_hfs_plus_volume_without_claiming_bootability() {
        let path = std::env::temp_dir().join(format!(
            "allboot-apm-{}-test.img",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut bytes = vec![0_u8; 1024 * 1024];
        let entry = |start: u32, blocks: u32, name: &str, kind: &str| {
            let mut data = [0_u8; 512];
            data[..2].copy_from_slice(b"PM");
            data[4..8].copy_from_slice(&3_u32.to_be_bytes());
            data[8..12].copy_from_slice(&start.to_be_bytes());
            data[12..16].copy_from_slice(&blocks.to_be_bytes());
            data[16..16 + name.len()].copy_from_slice(name.as_bytes());
            data[48..48 + kind.len()].copy_from_slice(kind.as_bytes());
            data
        };
        bytes[512..1024].copy_from_slice(&entry(1, 63, "Apple", "Apple_partition_map"));
        bytes[1024..1536].copy_from_slice(&entry(64, 100, "Free", "Apple_Free"));
        bytes[1536..2048].copy_from_slice(&entry(256, 1792, "disk image", "Apple_HFS"));
        let hfs_header = 256 * 512 + 1024;
        bytes[hfs_header..hfs_header + 2].copy_from_slice(b"H+");
        fs::write(&path, &bytes).unwrap();
        let mut file = File::open(&path).unwrap();
        assert_eq!(
            inspect_apple_partitioned_hfs(&mut file, bytes.len() as u64),
            (true, true)
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_malformed_apple_partition_maps_without_claiming_hfs_or_bootability() {
        let path = std::env::temp_dir().join(format!(
            "allboot-apm-malformed-{}-test.img",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut bytes = vec![0_u8; 4096];
        bytes[512..514].copy_from_slice(b"PM");
        bytes[516..520].copy_from_slice(&129_u32.to_be_bytes());
        fs::write(&path, &bytes).unwrap();
        let mut file = File::open(&path).unwrap();
        assert_eq!(
            inspect_apple_partitioned_hfs(&mut file, bytes.len() as u64),
            (false, false),
            "oversized partition maps must be rejected rather than treated as Apple partition maps"
        );

        bytes[516..520].copy_from_slice(&2_u32.to_be_bytes());
        fs::write(&path, &bytes).unwrap();
        let mut file = File::open(&path).unwrap();
        assert_eq!(
            inspect_apple_partitioned_hfs(&mut file, bytes.len() as u64),
            (true, false),
            "truncated partition maps must not be treated as HFS boot evidence"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn real_ventura_full_image_inspection_when_fixture_path_is_supplied() {
        let Some(path) = std::env::var_os("ALLBOOT_VENTURA_ISO_FIXTURE") else {
            return;
        };
        let image = inspect_image_sync(path.to_string_lossy().to_string(), None)
            .expect("full Ventura image inspection should complete without writing");
        assert!(image.macos_installer_validated);
        assert_eq!(image.macos_boot_architecture, "x86_64");
        assert!(!image.macos_supported_models.is_empty());
        println!(
            "Full read-only Ventura inspection: {} bytes, SHA-256 {}, {} supported models",
            image.size_bytes,
            image.sha256,
            image.macos_supported_models.len()
        );
    }

    #[test]
    fn validates_real_ventura_boot_structures_when_fixture_path_is_supplied() {
        let Some(path) = std::env::var_os("ALLBOOT_VENTURA_ISO_FIXTURE") else {
            return;
        };
        let metadata = fs::metadata(&path).expect("Ventura fixture metadata should be readable");
        let mut file = File::open(&path).expect("Ventura fixture should be readable");
        let evidence = inspect_macos_boot_structure(&mut file, metadata.len());
        assert!(evidence.validated, "macOS evidence: {:?}", evidence.checks);
        assert_eq!(evidence.architecture, "x86_64");
        println!(
            "Validated installer model identifiers ({}): {}",
            evidence.supported_models.len(),
            evidence.supported_models.join(", ")
        );
        assert!(
            !evidence.supported_models.is_empty(),
            "installer model list should be parsed"
        );
        assert!(evidence
            .checks
            .iter()
            .any(|item| item.contains("SharedSupport.dmg extent map")));
        assert!(evidence
            .checks
            .iter()
            .any(|item| item.contains("BaseSystem.dmg extent map")));
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
        let result = inspect_image_sync(path.to_string_lossy().to_string(), None).unwrap();
        assert!(!result.udif_signature);
        assert!(result.detected_format.contains("not detected"));
        fs::remove_file(path).unwrap();
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn real_ventura_usb_preflight_rechecks_identity_and_stays_read_only() {
        let (Some(image_path), Some(disk_number)) = (
            std::env::var_os("ALLBOOT_VENTURA_ISO_FIXTURE"),
            std::env::var("ALLBOOT_TARGET_USB_DISK").ok(),
        ) else {
            return;
        };
        let disk_number: u32 = disk_number
            .parse()
            .expect("target disk number must be numeric");
        let drives = list_destination_drives().expect("USB inventory should be readable");
        let drive = drives
            .iter()
            .find(|drive| drive.disk_number == disk_number)
            .expect("selected SanDisk USB should remain eligible");
        assert!(drive.name.to_ascii_lowercase().contains("sandisk"));
        assert_eq!(drive.bus_type, "USB");
        let image = inspect_image_sync(image_path.to_string_lossy().to_string(), None)
            .expect("Ventura ISO should pass read-only inspection");
        assert!(image.macos_installer_validated);
        let report = preflight_write(
            drive.disk_number,
            drive.unique_id.clone(),
            image.path,
            image.sha256,
            None,
        )
        .expect("real USB identity and image hash should pass read-only preflight");
        assert_eq!(report.disk_number, disk_number);
        assert!(report
            .write_readiness
            .contains("supported target Mac model has not been selected"));
        assert_eq!(report.checks.len(), 6);
        println!(
            "Real Ventura USB preflight: {} (Disk {}, {} bytes); readiness: {}",
            report.drive_name, report.disk_number, report.disk_size_bytes, report.write_readiness
        );
        println!("Read-only checks: {}", report.checks.join("; "));
        println!(
            "Future erase challenge generated but not accepted: {}",
            report.confirmation_phrase
        );
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
                inspect_image_sync(path.to_string_lossy().to_string(), None)
                    .unwrap()
                    .sha256,
                None,
            )
            .expect("matching USB identity should pass read-only preflight");
            assert_eq!(report.disk_number, drive.disk_number);
            assert!(report
                .confirmation_phrase
                .starts_with(&format!("ERASE DISK {} ", drive.disk_number)));
            assert_eq!(report.confirmation_phrase.split_whitespace().count(), 4);
            let mismatch = preflight_write(
                drive.disk_number,
                "not-the-real-device-id".into(),
                path.to_string_lossy().to_string(),
                inspect_image_sync(path.to_string_lossy().to_string(), None)
                    .unwrap()
                    .sha256,
                None,
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

    #[test]
    fn erase_confirmation_validator_requires_exact_current_challenge() {
        let identity = "USB-SERIAL-123";
        let hash = "a".repeat(64);
        let phrase = erase_confirmation_phrase(4, identity, &hash);
        assert!(validate_erase_confirmation(4, identity, &hash, &phrase).is_ok());
        assert!(validate_erase_confirmation(4, identity, &hash, "ERASE DISK 4").is_err());
        assert!(validate_erase_confirmation(5, identity, &hash, &phrase).is_err());
        assert!(validate_erase_confirmation(4, "USB-SERIAL-456", &hash, &phrase).is_err());
        assert!(validate_erase_confirmation(4, identity, &"b".repeat(64), &phrase).is_err());
        assert!(validate_erase_confirmation(4, identity, "not-a-hash", &phrase).is_err());
        assert!(validate_erase_confirmation(4, " ", &hash, &phrase).is_err());
    }

    #[test]
    fn erase_confirmation_is_bound_to_disk_identity_and_image_hash() {
        let identity = "USB-SERIAL-123";
        let image_hash = "a".repeat(64);
        let phrase = erase_confirmation_phrase(4, identity, &image_hash);
        assert!(phrase.starts_with("ERASE DISK 4 "));
        assert_eq!(phrase, erase_confirmation_phrase(4, identity, &image_hash));
        assert_ne!(phrase, erase_confirmation_phrase(5, identity, &image_hash));
        assert_ne!(
            phrase,
            erase_confirmation_phrase(4, "USB-SERIAL-456", &image_hash)
        );
        assert_ne!(
            phrase,
            erase_confirmation_phrase(4, identity, &"b".repeat(64))
        );
        assert_ne!(
            phrase,
            erase_confirmation_phrase(4, "usb-serial-123", &image_hash)
        );
    }

    #[test]
    fn source_image_gate_reopens_verifies_and_rewinds_exact_file() {
        let path =
            std::env::temp_dir().join(format!("allboot-source-{}-test.img", std::process::id()));
        let bytes = b"AllBoot source image verification fixture";
        std::fs::write(&path, bytes).expect("write temporary image");
        let hash = format!("{:x}", Sha256::digest(bytes));
        let mut file =
            open_verified_source_image(path.to_str().unwrap(), bytes.len() as u64, &hash)
                .expect("matching image should verify");
        let mut first = [0_u8; 7];
        file.read_exact(&mut first)
            .expect("verified handle should be rewound");
        assert_eq!(&first, b"AllBoot");
        assert!(open_verified_source_image(
            path.to_str().unwrap(),
            bytes.len() as u64,
            &"0".repeat(64)
        )
        .is_err());
        assert!(open_verified_source_image(
            path.to_str().unwrap(),
            (bytes.len() + 1) as u64,
            &hash
        )
        .is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn source_image_gate_rejects_non_file_paths() {
        let path = std::env::temp_dir();
        assert!(open_verified_source_image(path.to_str().unwrap(), 0, &"0".repeat(64)).is_err());
    }

    #[test]
    fn readback_verification_accepts_exact_matching_image() {
        let bytes = b"AllBoot read-back verification test image";
        let expected = format!("{:x}", Sha256::digest(bytes));
        let mut reader = std::io::Cursor::new(bytes.to_vec());
        assert_eq!(
            verify_image_readback(&mut reader, bytes.len() as u64, &expected).unwrap(),
            expected
        );
    }

    #[test]
    fn readback_verification_rejects_corruption_and_wrong_length() {
        let bytes = b"AllBoot read-back verification test image";
        let expected = format!("{:x}", Sha256::digest(bytes));
        let mut corrupted = bytes.to_vec();
        corrupted[5] ^= 0xFF;
        let mut reader = std::io::Cursor::new(corrupted);
        assert!(
            verify_image_readback(&mut reader, bytes.len() as u64, &expected)
                .unwrap_err()
                .contains("SHA-256 mismatch")
        );
        let mut truncated = std::io::Cursor::new(bytes[..8].to_vec());
        assert!(
            verify_image_readback(&mut truncated, bytes.len() as u64, &expected)
                .unwrap_err()
                .contains("ended early")
        );
        let mut extended = std::io::Cursor::new([bytes.as_slice(), b"x"].concat());
        assert!(
            verify_image_readback(&mut extended, bytes.len() as u64, &expected)
                .unwrap_err()
                .contains("more data")
        );
    }

    #[test]
    fn physical_device_readback_accepts_image_prefix_and_ignores_remaining_capacity() {
        let image = b"boot image bytes";
        let hash = format!("{:x}", Sha256::digest(image));
        let mut disk_bytes = image.to_vec();
        disk_bytes.extend_from_slice(&vec![0xD3; 8192]);
        let mut reader = std::io::Cursor::new(disk_bytes);
        assert_eq!(
            verify_device_readback_prefix(&mut reader, image.len() as u64, &hash).unwrap(),
            hash
        );
        assert_eq!(reader.position(), image.len() as u64);
    }

    #[test]
    fn physical_device_readback_rejects_truncated_image_and_corrupt_image_region() {
        let image = b"boot image bytes";
        let hash = format!("{:x}", Sha256::digest(image));
        let mut truncated = std::io::Cursor::new(image[..5].to_vec());
        assert!(
            verify_device_readback_prefix(&mut truncated, image.len() as u64, &hash)
                .unwrap_err()
                .contains("ended early")
        );

        let mut corrupted = image.to_vec();
        corrupted[3] ^= 0x80;
        corrupted.extend_from_slice(&vec![0xD3; 8192]);
        let mut reader = std::io::Cursor::new(corrupted);
        assert!(
            verify_device_readback_prefix(&mut reader, image.len() as u64, &hash)
                .unwrap_err()
                .contains("SHA-256 mismatch")
        );
    }

    #[test]
    fn verified_write_pipeline_streams_and_reads_back_exact_image() {
        let bytes = b"AllBoot verified writer integration fixture";
        let hash = format!("{:x}", Sha256::digest(bytes));
        let phrase = erase_confirmation_phrase(7, "USB-TEST-7", &hash);
        let mut source = std::io::Cursor::new(bytes.to_vec());
        let mut destination = std::io::Cursor::new(vec![0_u8; bytes.len() + 4096]);
        let mut progress = Vec::new();
        let result = write_verified_stream(
            &mut source,
            &mut destination,
            bytes.len() as u64,
            (bytes.len() + 4096) as u64,
            7,
            "USB-TEST-7",
            &hash,
            &phrase,
            || false,
            |n| progress.push(n),
        )
        .expect("verified pipeline should complete");
        assert_eq!(result, hash);
        assert_eq!(&destination.get_ref()[..bytes.len()], bytes);
        assert!(destination.get_ref()[bytes.len()..]
            .iter()
            .all(|byte| *byte == 0));
        assert!(!progress.is_empty());
        assert_eq!(progress.last().copied(), Some(bytes.len() as u64));
    }

    #[test]
    fn verified_write_pipeline_detects_source_bytes_changed_after_preflight() {
        let expected_bytes = b"image bytes from preflight";
        let changed_bytes = b"image bytes from preflighX";
        assert_eq!(expected_bytes.len(), changed_bytes.len());
        let expected_hash = format!("{:x}", Sha256::digest(expected_bytes));
        let phrase = erase_confirmation_phrase(9, "USB-TEST-9", &expected_hash);
        let mut source = std::io::Cursor::new(changed_bytes.to_vec());
        let mut destination = std::io::Cursor::new(vec![0_u8; changed_bytes.len()]);
        let error = write_verified_stream(
            &mut source,
            &mut destination,
            changed_bytes.len() as u64,
            changed_bytes.len() as u64,
            9,
            "USB-TEST-9",
            &expected_hash,
            &phrase,
            || false,
            |_| {},
        )
        .expect_err("changed source bytes must not pass verification");
        assert!(error.contains("source image changed"));
    }

    #[test]
    fn verified_write_pipeline_rejects_wrong_confirmation_and_small_target_before_writing() {
        let bytes = b"must remain unchanged";
        let hash = format!("{:x}", Sha256::digest(bytes));
        let phrase = erase_confirmation_phrase(7, "USB-TEST-7", &hash);
        let mut source = std::io::Cursor::new(bytes.to_vec());
        let mut destination = std::io::Cursor::new(vec![0xA5_u8; bytes.len()]);
        assert!(write_verified_stream(
            &mut source,
            &mut destination,
            bytes.len() as u64,
            bytes.len() as u64 - 1,
            7,
            "USB-TEST-7",
            &hash,
            &phrase,
            || false,
            |_| {}
        )
        .is_err());
        assert_eq!(destination.get_ref(), &vec![0xA5_u8; bytes.len()]);
        assert!(write_verified_stream(
            &mut source,
            &mut destination,
            bytes.len() as u64,
            bytes.len() as u64,
            7,
            "USB-TEST-7",
            &hash,
            "STALE CONFIRMATION",
            || false,
            |_| {}
        )
        .is_err());
        assert_eq!(destination.get_ref(), &vec![0xA5_u8; bytes.len()]);
    }

    #[test]
    fn verified_write_pipeline_rejects_zero_length_and_malformed_hash_before_writing() {
        let bytes = b"keep destination unchanged";
        let hash = format!("{:x}", Sha256::digest(bytes));
        let phrase = erase_confirmation_phrase(11, "USB-TEST-11", &hash);

        let mut source = std::io::Cursor::new(bytes.to_vec());
        let mut destination = std::io::Cursor::new(vec![0xA5_u8; bytes.len()]);
        let zero_length = write_verified_stream(
            &mut source,
            &mut destination,
            0,
            bytes.len() as u64,
            11,
            "USB-TEST-11",
            &hash,
            &phrase,
            || false,
            |_| {},
        )
        .expect_err("zero-length image must be rejected");
        assert!(zero_length.contains("insufficient or invalid"));
        assert_eq!(destination.get_ref(), &vec![0xA5_u8; bytes.len()]);

        let malformed_hash = write_verified_stream(
            &mut source,
            &mut destination,
            bytes.len() as u64,
            bytes.len() as u64,
            11,
            "USB-TEST-11",
            "not-a-sha256",
            &erase_confirmation_phrase(11, "USB-TEST-11", "not-a-sha256"),
            || false,
            |_| {},
        )
        .expect_err("malformed image hash must be rejected");
        assert!(malformed_hash.contains("device identity or image hash is invalid"));
        assert_eq!(destination.get_ref(), &vec![0xA5_u8; bytes.len()]);
    }

    #[test]
    fn image_stream_rejects_short_source_without_claiming_completion() {
        let mut source = std::io::Cursor::new(b"short".to_vec());
        let mut destination = std::io::Cursor::new(Vec::new());
        let result = stream_image(&mut source, &mut destination, 10, || false, |_| {});
        assert!(result.unwrap_err().contains("ended early"));
        assert_eq!(destination.get_ref(), b"short");
    }

    #[test]
    fn image_stream_rejects_source_that_grows_past_inspected_size() {
        let mut source = std::io::Cursor::new(b"longer".to_vec());
        let mut destination = std::io::Cursor::new(Vec::new());
        let result = stream_image(&mut source, &mut destination, 5, || false, |_| {});
        assert!(result.unwrap_err().contains("grew"));
        assert_eq!(destination.get_ref(), b"longe");
    }

    #[test]
    fn verified_write_pipeline_propagates_cancellation() {
        let bytes = vec![0x5A_u8; 1024 * 1024 + 8];
        let hash = format!("{:x}", Sha256::digest(&bytes));
        let phrase = erase_confirmation_phrase(8, "USB-TEST-8", &hash);
        let mut source = std::io::Cursor::new(bytes.clone());
        let mut destination = std::io::Cursor::new(vec![0_u8; bytes.len()]);
        let result = write_verified_stream(
            &mut source,
            &mut destination,
            bytes.len() as u64,
            bytes.len() as u64,
            8,
            "USB-TEST-8",
            &hash,
            &phrase,
            || true,
            |_| {},
        );
        assert!(result.unwrap_err().contains("cancelled"));
        assert!(destination.get_ref().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn verified_write_pipeline_stops_after_midstream_cancellation() {
        let bytes = vec![0x6B_u8; 2 * 1024 * 1024];
        let hash = format!("{:x}", Sha256::digest(&bytes));
        let phrase = erase_confirmation_phrase(9, "USB-TEST-9", &hash);
        let mut source = std::io::Cursor::new(bytes.clone());
        let mut destination = std::io::Cursor::new(vec![0xA5_u8; bytes.len()]);
        let mut cancellation_checks = 0;
        let result = write_verified_stream(
            &mut source,
            &mut destination,
            bytes.len() as u64,
            bytes.len() as u64,
            9,
            "USB-TEST-9",
            &hash,
            &phrase,
            || {
                cancellation_checks += 1;
                cancellation_checks > 1
            },
            |_| {},
        );
        let error = result.expect_err("midstream cancellation must not report success");
        assert!(error.contains("cancelled"));
        assert_eq!(cancellation_checks, 2);
        assert_eq!(&destination.get_ref()[..1024 * 1024], &bytes[..1024 * 1024]);
        assert!(destination.get_ref()[1024 * 1024..]
            .iter()
            .all(|byte| *byte == 0xA5));
    }

    #[test]
    fn image_stream_copies_exact_bytes_and_reports_monotonic_progress() {
        let source = vec![0x5A_u8; 2 * 1024 * 1024 + 17];
        let mut reader = std::io::Cursor::new(source.clone());
        let mut output = Vec::new();
        let mut progress = Vec::new();
        let written = stream_image(
            &mut reader,
            &mut output,
            source.len() as u64,
            || false,
            |bytes| progress.push(bytes),
        )
        .expect("valid image stream should complete");
        assert_eq!(written, source.len() as u64);
        assert_eq!(output, source);
        assert!(!progress.is_empty());
        assert!(progress.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(*progress.last().unwrap(), written);
    }

    #[test]
    fn image_stream_rejects_truncated_or_growing_sources() {
        let mut short_reader = std::io::Cursor::new(vec![1_u8; 7]);
        let mut output = Vec::new();
        assert!(
            stream_image(&mut short_reader, &mut output, 8, || false, |_| {})
                .unwrap_err()
                .contains("ended early")
        );
        let mut long_reader = std::io::Cursor::new(vec![1_u8; 9]);
        let mut output = Vec::new();
        assert!(
            stream_image(&mut long_reader, &mut output, 8, || false, |_| {})
                .unwrap_err()
                .contains("grew")
        );
    }

    #[test]
    fn image_stream_cancellation_stops_before_the_next_chunk() {
        let source = vec![0xA5_u8; 2 * 1024 * 1024];
        let mut reader = std::io::Cursor::new(source);
        let mut output = Vec::new();
        let mut checks = 0;
        let result = stream_image(
            &mut reader,
            &mut output,
            2 * 1024 * 1024,
            || {
                checks += 1;
                checks > 1
            },
            |_| {},
        );
        assert!(result.unwrap_err().contains("cancelled"));
        assert_eq!(output.len(), 1024 * 1024);
    }

    #[test]
    fn both_platform_helpers_are_versioned_and_discovery_only() {
        assert!(WINDOWS_DRIVE_HELPER_SOURCE.contains("# ALLBOOT_DRIVE_HELPER_VERSION=1"));
        assert!(WINDOWS_DRIVE_HELPER_SOURCE.contains("Get-Disk"));
        assert!(WINDOWS_DRIVE_HELPER_SOURCE.contains("ConvertTo-Json"));
        for forbidden in [
            "Clear-Disk",
            "Format-Volume",
            "Initialize-Disk",
            "Remove-Partition",
            "Set-Disk",
            "Remove-Item",
        ] {
            assert!(
                !WINDOWS_DRIVE_HELPER_SOURCE.contains(forbidden),
                "Windows helper must not contain {forbidden}"
            );
        }
        assert!(MACOS_DRIVE_HELPER_SOURCE.contains("# ALLBOOT_DRIVE_HELPER_VERSION=1"));
        assert!(MACOS_DRIVE_HELPER_SOURCE.contains("diskutil list -plist external physical"));
        assert!(MACOS_DRIVE_HELPER_SOURCE.contains("diskutil info -plist"));
        assert!(MACOS_DRIVE_HELPER_SOURCE.contains("diskutil info -plist /"));
        for forbidden in [
            "diskutil eraseDisk",
            "diskutil partitionDisk",
            "diskutil apfs deleteContainer",
            "diskutil unmountDisk",
            "diskutil eject",
        ] {
            assert!(
                !MACOS_DRIVE_HELPER_SOURCE.contains(forbidden),
                "macOS helper must not contain {forbidden}"
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn raw_device_path_rejects_disk_zero() {
        assert!(raw_device_path(0).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_raw_device_path_uses_physical_drive_namespace() {
        assert_eq!(raw_device_path(12).unwrap(), r"\\.\PhysicalDrive12");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_raw_device_path_uses_raw_whole_disk_namespace() {
        assert_eq!(raw_device_path(12).unwrap(), "/dev/rdisk12");
    }

    #[test]
    fn windows_drive_helper_passes_powershell_parser() {
        let path =
            std::env::temp_dir().join(format!("allboot-helper-{}-test.ps1", std::process::id()));
        std::fs::write(&path, WINDOWS_DRIVE_HELPER_SOURCE).expect("write temporary helper");
        let parse = "$tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile($env:ALLBOOT_TEST_HELPER,[ref]$tokens,[ref]$errors) > $null; if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_ }; exit 1 }";
        let output = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                parse,
            ])
            .env("ALLBOOT_TEST_HELPER", &path)
            .output()
            .expect("PowerShell parser should be available on Windows CI");
        let _ = std::fs::remove_file(&path);
        assert!(
            output.status.success(),
            "PowerShell helper syntax error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_drive_helper_passes_posix_shell_parser() {
        let path =
            std::env::temp_dir().join(format!("allboot-helper-{}-test.sh", std::process::id()));
        std::fs::write(&path, MACOS_DRIVE_HELPER_SOURCE).expect("write temporary helper");
        let output = Command::new("/bin/sh")
            .args(["-n", path.to_str().expect("temporary path is UTF-8")])
            .output()
            .expect("POSIX shell parser should be available on macOS CI");
        let _ = std::fs::remove_file(&path);
        assert!(
            output.status.success(),
            "macOS helper syntax error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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
            detect_target_mac_model,
            drive_helper_installed,
            install_drive_helper,
            inspect_image,
            preflight_write
        ])
        .run(tauri::generate_context!())
        .expect("error while running AllBoot ISO Maker");
}
