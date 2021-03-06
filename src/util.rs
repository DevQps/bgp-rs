use byteorder::ReadBytesExt;

use std::io::{Cursor, Result};

// Attempt to detect whether the prefix has a path ID or not.
// Modelled heavily on the Wireshark code - https://github.com/wireshark/wireshark/blob/24e43bf542d65f5b802b65355caacfba2c7b00d0/epan/dissectors/packet-bgp.c#L2336
//
// This is used because whilst we *do* look at the OPEN messages, some BMP implementations
// don't send OPENs as part of the Peer Up messages. •`_´•  Looking at you XR 6.4.2
pub(crate) fn detect_add_path_prefix(cur: &mut Cursor<Vec<u8>>, max_bit_len: u32) -> Result<bool> {
    let cursor_init = cur.position();
    let cursor_end = cur.get_ref().len() as u64;

    let mut i = cur.position() + 4;
    while i < cursor_end {
        cur.set_position(i);
        let prefix_len = u32::from(cur.read_u8()?);

        if prefix_len > max_bit_len {
            cur.set_position(cursor_init);
            return Ok(false); // Not ADD PATH
        }

        let addr_len = (prefix_len + 7) / 8;
        // let addr_len = (f32::from(prefix_len) / 8.0).ceil() as u8;
        i += u64::from(1 + addr_len);

        if i > cursor_end {
            cur.set_position(cursor_init);
            return Ok(false);
        }

        if prefix_len % 8 > 0 {
            // detect bits set after the end of the prefix
            cur.set_position(i - 1);
            let v = cur.read_u8()?;
            if v & (0xFF >> (prefix_len % 8)) > 0 {
                cur.set_position(cursor_init);
                return Ok(false);
            }
        }

        i += 4;
    }

    cur.set_position(cursor_init);
    let mut j = cur.position();
    while j < cursor_end {
        cur.set_position(j);
        let prefix_len = u32::from(cur.read_u8()?);

        if prefix_len == 0 && (cursor_end - (j + 1)) > 0 {
            cur.set_position(cursor_init);
            return Ok(true);
        }

        if prefix_len > max_bit_len {
            cur.set_position(cursor_init);
            return Ok(true);
        }

        let addr_len = (prefix_len + 7) / 8;
        // let addr_len = (f32::from(prefix_len) / 8.0).ceil() as u8;
        j += u64::from(1 + addr_len);

        if j > cursor_end {
            cur.set_position(cursor_init);
            return Ok(true);
        }

        if prefix_len % 8 > 0 {
            // detect bits set after the end of the prefix
            cur.set_position(j - 1);
            let v = cur.read_u8()?;
            if v & (0xFF >> (prefix_len % 8)) > 0 {
                cur.set_position(cursor_init);
                return Ok(true);
            }
        }
    }

    cur.set_position(cursor_init);
    Ok(false)
}

#[test]
fn test_with_path_id() {
    #[rustfmt::skip]
    let nlri_data = vec![
        // 5.5.5.5/32 PathId 1
        0x00, 0x00, 0x00, 0x01, 0x20, 0x05, 0x05, 0x05, 0x05,
        // 192.168.1.5/32 PathId 1
        0x00, 0x00, 0x00, 0x01, 0x20, 0xc0, 0xa8, 0x01, 0x05,
    ];
    let mut buf = std::io::Cursor::new(nlri_data);
    let add_path = detect_add_path_prefix(&mut buf, 255).expect("detecting add_path");
    assert!(add_path);
}

#[test]
fn test_without_path_id1() {
    #[rustfmt::skip]
    let nlri_data = vec![
        // 172.17.2.0/24
        0x18, 0xac, 0x11, 0x02,
        // 172.17.1.0/24
        0x18, 0xac, 0x11, 0x01,
        // 172.17.0.0/24
        0x18, 0xac, 0x11, 0x00,

    ];
    let mut buf = std::io::Cursor::new(nlri_data);
    let add_path = detect_add_path_prefix(&mut buf, 255).expect("detecting add_path");
    assert!(!add_path);
}

#[test]
fn test_without_path_id2() {
    #[rustfmt::skip]
    let nlri_data = vec![
        // 172.17.2.0/24
        0x18, 0xac, 0x11, 0x02,
        // 172.17.1.0/24
        0x18, 0xac, 0x11, 0x01,

    ];
    let mut buf = std::io::Cursor::new(nlri_data);
    let add_path = detect_add_path_prefix(&mut buf, 16).expect("detecting add_path");
    assert!(!add_path);
}
