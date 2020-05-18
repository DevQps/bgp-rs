use etherparse::PacketHeaders;

mod common;
use common::parse::{
    parse_pcap_message_bytes, parse_u16, parse_u32, parse_u32_with_path_id, test_message_roundtrip,
    test_pcap_roundtrip,
};

#[test]
fn pcap1() {
    parse_pcap("res/pcap/bgp-add-path.cap");
    // parse_pcap("res/pcap/bgplu.cap");
    parse_pcap("res/pcap/16-bit-asn.cap");
    parse_pcap("res/pcap/4-byte_AS_numbers_Full_Support.cap");
    parse_pcap("res/pcap/4-byte_AS_numbers_Mixed_Scenario.cap");
    parse_pcap("res/pcap/BGP_AS_set.cap");
    parse_pcap("res/pcap/BGP_hard_reset.cap");
    parse_pcap("res/pcap/BGP_MD5.cap");
    parse_pcap("res/pcap/BGP_MP_NLRI.cap");
    parse_pcap("res/pcap/BGP_notification.cap");
    parse_pcap("res/pcap/BGP_notification_msg.cap");
    parse_pcap("res/pcap/BGP_redist.cap");
    parse_pcap("res/pcap/BGP_soft_reset.cap");
    parse_pcap("res/pcap/BGP_flowspec_v6.cap");
    parse_pcap("res/pcap/EBGP_adjacency.cap");
    parse_pcap("res/pcap/IBGP_adjacency.cap");
}

#[test]
fn pcap_roundtrip1() {
    test_pcap_roundtrip("res/pcap/16-bit-asn.cap").unwrap();
    test_pcap_roundtrip("res/pcap/4-byte_AS_numbers_Full_Support.cap").unwrap();

    parse_pcap_message_bytes("res/pcap/4-byte_AS_numbers_Mixed_Scenario.cap")
        .unwrap()
        .into_iter()
        .take(1) // Only the first message
        .try_for_each(|message_bytes| test_message_roundtrip(&message_bytes))
        .unwrap();

    parse_pcap_message_bytes("res/pcap/bgp-add-path.cap")
        .unwrap()
        .into_iter()
        // Only the first 5 messages, message 6 uses 4-byte AS_PATH even when AS < 65535
        .take(5)
        .try_for_each(|message_bytes| test_message_roundtrip(&message_bytes))
        .unwrap();

    test_pcap_roundtrip("res/pcap/BGP_AS_set.cap").unwrap();
    test_pcap_roundtrip("res/pcap/BGP_hard_reset.cap").unwrap();
    test_pcap_roundtrip("res/pcap/BGP_MD5.cap").unwrap();
    test_pcap_roundtrip("res/pcap/BGP_MP_NLRI.cap").unwrap();
    test_pcap_roundtrip("res/pcap/BGP_notification.cap").unwrap();
    test_pcap_roundtrip("res/pcap/BGP_notification_msg.cap").unwrap();
    // test_pcap_roundtrip("res/pcap/BGP_redist.cap").unwrap();
    test_pcap_roundtrip("res/pcap/BGP_soft_reset.cap").unwrap();
    test_pcap_roundtrip("res/pcap/BGP_flowspec_v4.cap").unwrap();
    parse_pcap_message_bytes("res/pcap/BGP_flowspec_v6.cap")
        .unwrap()
        .into_iter()
        .take(1) // Only the first message
        .try_for_each(|message_bytes| test_message_roundtrip(&message_bytes))
        .unwrap();
    test_pcap_roundtrip("res/pcap/EBGP_adjacency.cap").unwrap();
    test_pcap_roundtrip("res/pcap/IBGP_adjacency.cap").unwrap();
    test_pcap_roundtrip("res/pcap/bgp_withdraw.cap").unwrap();
}

fn parse_pcap(filename: &str) {
    use pcap_file::PcapReader;
    use std::fs::File;

    println!("Testing: {}", filename);
    let file_in = File::open(filename).expect("Error opening file");
    let pcap_reader = PcapReader::new(file_in).unwrap();

    // Read test.pcap
    for pcap in pcap_reader {
        //Check if there is no error
        let pcap = pcap.unwrap();

        match PacketHeaders::from_ethernet_slice(&pcap.data) {
            Err(value) => println!("Err {:?}", value),
            Ok(value) => {
                if let Some(x) = value.transport {
                    if let Some(_) = x.tcp() {
                        if value.payload.len() > 10 {
                            let mut result = parse_u32(value.payload);

                            if let Err(_) = result {
                                result = parse_u16(value.payload);
                                if let Err(_) = result {
                                    result = parse_u32_with_path_id(value.payload);
                                    result.unwrap();
                                } else {
                                    result.unwrap();
                                }
                            } else {
                                result.unwrap();
                            }
                        }
                    }
                }
            }
        }
    }
}
