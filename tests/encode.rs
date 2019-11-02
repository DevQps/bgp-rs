use bgp_rs::*;

#[test]
fn test_encode_open() {
    let capabilities: Vec<OpenCapability> = vec![
        OpenCapability::MultiProtocol((AFI::IPV6, SAFI::Unicast)),
        OpenCapability::MultiProtocol((AFI::IPV4, SAFI::Flowspec)),
        OpenCapability::FourByteASN(65000),
    ];
    let open = Open {
        version: 4,
        peer_asn: 65000,
        hold_timer: 60,
        identifier: 16843008, // 1.1.1.1
        parameters: vec![OpenParameter::Capabilities(capabilities)],
    };
    let mut data: Vec<u8> = vec![];
    open.encode(&mut data).expect("Encoding OPEN");
    assert_eq!(
        data,
        vec![
            4, 253, 232, 0, 60, 1, 1, 1, 0, 20, 2, 18, 1, 4, 0, 2, 0, 1, 1, 4, 0, 1, 0, 133, 65, 4,
            0, 0, 253, 232
        ]
    );
}

#[test]
fn test_encode_nlri() {
    let nlri = NLRIEncoding::IP(Prefix {
        protocol: AFI::IPV6,
        length: 17,
        prefix: vec![0x0a, 0x0a, 0x80, 0x00],
    });
    let mut data: Vec<u8> = vec![];
    nlri.encode(&mut data).expect("Encoding NLRI");
    assert_eq!(data, vec![17, 10, 10, 128]);

    let nlri = NLRIEncoding::IP(Prefix {
        protocol: AFI::IPV6,
        length: 64,
        prefix: vec![
            0x20, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
    });
    let mut data: Vec<u8> = vec![];
    nlri.encode(&mut data).expect("Encoding NLRI");
    assert_eq!(data, vec![64, 32, 1, 0, 16, 0, 0, 0, 0]);
}

#[test]
fn test_encode_keepalive() {
    let keepalive = Message::KeepAlive;
    let mut data: Vec<u8> = vec![];
    keepalive.encode(&mut data).expect("Encoding KeepAlive");
    assert_eq!(
        data,
        vec![
            // preamble
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0,
            19, // length
            4,  // type
        ]
    );
}

#[test]
fn test_encode_notification() {
    let notification = Notification {
        major_err_code: 6,
        minor_err_code: 3,
        data: vec![],
    };
    let mut data: Vec<u8> = vec![];
    notification
        .encode(&mut data)
        .expect("Encoding Notification");
    assert_eq!(data, vec![6, 3]);

    let msg = "Peer De-Configured".to_string();
    let notification = Notification {
        major_err_code: 6,
        minor_err_code: 3,
        data: msg.into_bytes(),
    };
    let mut data: Vec<u8> = vec![];
    notification
        .encode(&mut data)
        .expect("Encoding Notification");
    assert_eq!(
        data,
        vec![
            6, 3, 80, 101, 101, 114, 32, 68, 101, 45, 67, 111, 110, 102, 105, 103, 117, 114, 101,
            100
        ]
    );
}
