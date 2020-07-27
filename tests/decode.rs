use bgp_rs::*;
use maplit::hashset;
use std::net::Ipv4Addr;

#[test]
fn test_bad_bgp_type() {
    let mut data = vec![0xff; 16];
    data.extend_from_slice(&[0, 19, 11]);
    let buffer = std::io::Cursor::new(data);
    let mut reader = Reader::new(buffer);
    let res = reader.read();
    assert!(res.is_err());
}

#[test]
fn test_header_type() {
    let mut data = vec![0xff; 16];
    data.extend_from_slice(&[0, 19, 4]);
    let mut buffer = std::io::Cursor::new(data);
    let header = Header::parse(&mut buffer).unwrap();
    assert_eq!(header.marker.len(), 16);
    assert_eq!(header.length, 19);
    assert_eq!(header.record_type, 4);
}

#[test]
fn test_open_decode() {
    #[rustfmt::skip]
    let data = vec![
        0x4, // Version
        0xfd, 0xe8, // ASN
        0, 0x3c, // Hold Timer
        0x01, 0x01, 0x01, 0x01, // Identifier
        26, // Parameter Length
        0x02, 0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, // IPv6 - Unicast
        0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xfd, 0xe8, // 4-byte ASN
        0x02, 0x02, 0x02, 0x00, // Route Refresh
        0x02, 0x04, 0xf0, 0x00, 0x00, 0x00 // Unknown
    ];
    let mut buf = std::io::Cursor::new(data);
    let open = Open::parse(&mut buf).expect("Decoding OPEN");
    assert_eq!(open.version, 4);
    assert_eq!(open.peer_asn, 65000);
    assert_eq!(Ipv4Addr::from(open.identifier), Ipv4Addr::new(1, 1, 1, 1));
    match &open.parameters[0] {
        OpenParameter::Capabilities(caps) => match caps[0] {
            OpenCapability::MultiProtocol((afi, safi)) => {
                assert_eq!(afi, AFI::IPV6);
                assert_eq!(safi, SAFI::Unicast);
            }
            _ => unreachable!(),
        },
        _ => panic!("Should have MPBGP Parameter"),
    }
    match &open.parameters[1] {
        OpenParameter::Capabilities(caps) => match caps[0] {
            OpenCapability::FourByteASN(asn) => {
                assert_eq!(asn, 65000);
            }
            _ => unreachable!(),
        },
        _ => panic!("Should have FourByteASN Parameter"),
    }
    match &open.parameters[2] {
        OpenParameter::Capabilities(caps) => match caps[0] {
            OpenCapability::RouteRefresh => (),
            _ => unreachable!(),
        },
        _ => panic!("Should have FourByteASN Parameter"),
    }
    match &open.parameters[3] {
        OpenParameter::Capabilities(caps) => match caps[0] {
            OpenCapability::Unknown { cap_code, .. } => {
                assert_eq!(cap_code, 0xf0);
            }
            _ => unreachable!(),
        },
        _ => panic!("Should have Unknown Parameter"),
    }
}

#[test]
fn test_bad_open_length() {
    #[rustfmt::skip]
    let data = vec![
        0x4, // Version
        0xfd, 0xe8, // ASN
        0, 0x3c, // Hold Timer
        0x01, 0x01, 0x01, 0x01, // Identifier
        40, // Parameter Length (20 extra bytes)
        0x02, 0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, // IPv6 - Unicast
        0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xfd, 0xe8, // 4-byte ASN
        0x02, 0x02, 0x02, 0x00 // Route Refresh
    ];
    let mut buf = std::io::Cursor::new(data);
    let res = Open::parse(&mut buf);
    assert!(res.is_err());
}

#[test]
fn test_notification_parse_no_data() {
    let header = Header {
        marker: [0xff; 16],
        length: 19,
        record_type: 4,
    };
    let mut buf = std::io::Cursor::new(vec![6, 3]);
    let notification = Notification::parse(&header, &mut buf).expect("Parsing Notification");
    assert_eq!(notification.major_err_code, 6);
    assert_eq!(notification.minor_err_code, 3);
    assert!(notification.data.is_empty());
}

#[test]
fn test_notification_parse_with_data() {
    let mut data = vec![4, 0];
    data.extend_from_slice(b"Hold Timer Expired");
    let header = Header {
        marker: [0xff; 16],
        length: data.len() as u16 + 19,
        record_type: 4,
    };
    let mut buf = std::io::Cursor::new(data);
    let notification = Notification::parse(&header, &mut buf).expect("Parsing Notification");
    assert_eq!(notification.major_err_code, 4);
    assert_eq!(notification.minor_err_code, 0);
    assert_eq!(&notification.message().unwrap(), "Hold Timer Expired");
}

#[test]
fn test_update_bogus_withdraw_length() {
    #[rustfmt::skip]
    let update_data = vec![
        0, 80, // Withdrawn Routes Length (this is too many bytes)
        0, 46, // Path Attribute Length
        64, 1, 1, 0, // ORIGIN
        64, 2, 4, 2, 1, 251, 255, // AS_PATH
        64, 3, 4, 10, 0, 14, 1,  // NEXT_HOP
        128, 4, 4, 0, 0, 0, 0, // MED
        64, 5, 4, 0, 0, 0, 100, // LOCAL_PREF
        128, 10, 4, 10, 0, 34, 4, // CLUSTER LIST
        128, 9, 4, 10, 0, 15, 1, // ORIGINATOR_ID
        // NLRI
        0, 0, 0, 1, 32, 5, 5, 5, 5, // 5.5.5.5/32 w/ Path ID 1
        0, 0, 0, 1, 32, 192, 168, 1, 5   // 192.168.1.5/32 w/ Path ID 1
    ];
    let header_length = 19 + update_data.len();
    let mut buf = std::io::Cursor::new(update_data);
    let header = Header {
        marker: [0xff; 16],
        length: header_length as u16,
        record_type: 2,
    };
    let res = Update::parse(&header, &mut buf, &Capabilities::default());
    assert!(res.is_err());
}

#[test]
fn test_update_bogus_attributes_length() {
    #[rustfmt::skip]
    let update_data = vec![
        0, 0, // Withdrawn Routes Length
        0, 80, // Path Attribute Length (too many bytes)
        64, 1, 1, 0, // ORIGIN
        64, 2, 4, 2, 1, 251, 255, // AS_PATH
        64, 3, 4, 10, 0, 14, 1,  // NEXT_HOP
        128, 4, 4, 0, 0, 0, 0, // MED
        64, 5, 4, 0, 0, 0, 100, // LOCAL_PREF
        128, 10, 4, 10, 0, 34, 4, // CLUSTER LIST
        128, 9, 4, 10, 0, 15, 1, // ORIGINATOR_ID
    ];
    let header_length = 19 + update_data.len();
    let mut buf = std::io::Cursor::new(update_data);
    let header = Header {
        marker: [0xff; 16],
        length: header_length as u16,
        record_type: 2,
    };
    let res = Update::parse(&header, &mut buf, &Capabilities::default());
    assert!(res.is_err());
}

#[test]
fn test_update_extended_path_support() {
    #[rustfmt::skip]
    let update_data = vec![
        0, 18, // Withdrawn Routes Length
        // NLRI
        0, 0, 0, 1, 32, 5, 5, 5, 5, // 5.5.5.5/32 w/ Path ID 1
        0, 0, 0, 1, 32, 192, 168, 1, 5,   // 192.168.1.5/32 w/ Path ID 1
        0, 46, // Path Attribute Length
        64, 1, 1, 0, // ORIGIN
        64, 2, 4, 2, 1, 251, 255, // AS_PATH
        64, 3, 4, 10, 0, 14, 1,  // NEXT_HOP
        128, 4, 4, 0, 0, 0, 0, // MED
        64, 5, 4, 0, 0, 0, 100, // LOCAL_PREF
        128, 10, 4, 10, 0, 34, 4, // CLUSTER LIST
        128, 9, 4, 10, 0, 15, 1, // ORIGINATOR_ID
    ];
    let header_length = 19 + update_data.len();
    let mut buf = std::io::Cursor::new(update_data);
    let header = Header {
        marker: [0xff; 16],
        length: header_length as u16,
        record_type: 2,
    };
    let capabilities = Capabilities::from_parameters(vec![OpenParameter::Capabilities(vec![
        OpenCapability::AddPath(hashset! {
            (AFI::IPV4, SAFI::Unicast, AddPathDirection::SendReceivePaths)
        }),
    ])]);
    let update = Update::parse(&header, &mut buf, &capabilities).unwrap();
    assert_eq!(update.withdrawn_routes.len(), 2);
    for route in &update.withdrawn_routes {
        match route {
            NLRIEncoding::IP_WITH_PATH_ID(_) => (),
            _ => panic!("Expected Path ID"),
        }
    }
}
