//! Zero-allocation Rust native MAVLink CRC-16 and frame sanitizer.
//!
//! Provides sub-microsecond in-place packet filtering and coordinate sanitization.



/// Precomputed MAVLink X.25 / MCRF4XX CRC lookup table.
pub static X25_TABLE: [u16; 256] = {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let x = i as u16;
        let t = (x ^ (x << 4)) & 0xFF;
        table[i] = ((t << 8) ^ (t << 3) ^ (t >> 4)) & 0xFFFF;
        i += 1;
    }
    table
};

/// Accumulates MAVLink X.25 CRC-16 over bytes with a seed.
#[inline]
pub fn crc_x25_accumulate(data: &[u8], mut crc: u16) -> u16 {
    for &b in data {
        crc = (crc >> 8) ^ X25_TABLE[((b ^ (crc as u8)) & 0xFF) as usize];
    }
    crc
}

/// Computes complete MAVLink X.25 CRC with optional dialect crc_extra.
#[inline]
pub fn crc_x25(data: &[u8], crc_extra: u8) -> u16 {
    let crc = crc_x25_accumulate(data, 0xFFFF);
    crc_x25_accumulate(&[crc_extra], crc)
}

/// MAVLink v2 magic byte.
pub const V2_MAGIC: u8 = 0xFD;

/// Fast O(1) frame inspection: returns true if frame should be dropped.
#[inline]
pub fn should_drop_frame(frame: &[u8], quarantined_sysids: &[u8], flood_active: bool) -> bool {
    if frame.len() < 10 || frame[0] != V2_MAGIC {
        return false;
    }
    let sysid = frame[5];
    for &q in quarantined_sysids {
        if sysid == q {
            return true;
        }
    }
    if flood_active {
        let msgid = (frame[7] as u32) | ((frame[8] as u32) << 8) | ((frame[9] as u32) << 16);
        // Critical C2 messages allowed: 0 (HEARTBEAT), 30 (ATTITUDE), 33 (GLOBAL_POSITION_INT), 76 (COMMAND_LONG)
        match msgid {
            0 | 30 | 33 | 76 => false,
            _ => true,
        }
    } else {
        false
    }
}

/// In-place sanitization of MAVLink v2 GLOBAL_POSITION_INT (msgid 33).
///
/// Modifies lat (bytes 14..18), lon (bytes 18..22), alt (bytes 22..26) in place
/// and recomputes the trailing 2-byte CRC.
#[inline]
pub fn sanitize_global_position_int(
    frame: &mut [u8],
    dlat_e7: i32,
    dlon_e7: i32,
    dalt_mm: i32,
    crc_extra: u8,
) -> bool {
    if frame.len() < 38 || frame[0] != V2_MAGIC {
        return false;
    }
    let payload_len = frame[1] as usize;
    let msgid = (frame[7] as u32) | ((frame[8] as u32) << 8) | ((frame[9] as u32) << 16);
    if msgid != 33 || payload_len < 28 {
        return false;
    }

    // lat @ offset 14 (4 bytes, little-endian)
    if dlat_e7 != 0 {
        let cur_lat = i32::from_le_bytes([frame[14], frame[15], frame[16], frame[17]]);
        let new_lat = cur_lat.wrapping_sub(dlat_e7);
        frame[14..18].copy_from_slice(&new_lat.to_le_bytes());
    }

    // lon @ offset 18 (4 bytes, little-endian)
    if dlon_e7 != 0 {
        let cur_lon = i32::from_le_bytes([frame[18], frame[19], frame[20], frame[21]]);
        let new_lon = cur_lon.wrapping_sub(dlon_e7);
        frame[18..22].copy_from_slice(&new_lon.to_le_bytes());
    }

    // alt @ offset 22 (4 bytes, little-endian)
    if dalt_mm != 0 {
        let cur_alt = i32::from_le_bytes([frame[22], frame[23], frame[24], frame[25]]);
        let new_alt = cur_alt.wrapping_sub(dalt_mm);
        frame[22..26].copy_from_slice(&new_alt.to_le_bytes());
    }

    // Recompute CRC over header (without magic) + payload + crc_extra
    let header_and_payload_end = 10 + payload_len;
    let new_crc = crc_x25(&frame[1..header_and_payload_end], crc_extra);

    frame[header_and_payload_end] = (new_crc & 0xFF) as u8;
    frame[header_and_payload_end + 1] = ((new_crc >> 8) & 0xFF) as u8;

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc_table_deterministic() {
        assert_eq!(X25_TABLE[0], 0);
        let crc = crc_x25(b"TEST", 0);
        assert!(crc > 0);
    }
}
