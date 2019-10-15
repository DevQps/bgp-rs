use bgp_rs::{
    Capabilities, FlowspecFilter, Identifier, Message, NLRIEncoding, PathAttribute, Reader, Update,
    AFI,
};
use etherparse::PacketHeaders;
use std::io;
use std::io::Cursor;

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
fn test_flowspec_v6() {
    let updates = parse_flowspec("res/pcap/BGP_flowspec_v6.cap").unwrap();
    assert_eq!(updates.len(), 2);
    let update_announce = &updates[0];
    match update_announce.get(Identifier::EXTENDED_COMMUNITIES) {
        Some(PathAttribute::EXTENDED_COMMUNITIES(communities)) => {
            assert_eq!(
                transform_u64_to_bytes(communities[0]),
                [0x80, 0x06, 0, 0, 0, 0, 0, 0],
                // ^------^ FlowSpec Traffic Rate
            );
        }
        _ => panic!("Extended Communities not present"),
    }
    match update_announce.get(Identifier::MP_REACH_NLRI) {
        Some(PathAttribute::MP_REACH_NLRI(reach_nlri)) => {
            assert_eq!(reach_nlri.afi, AFI::IPV6);
            assert_eq!(reach_nlri.safi, 133);
            assert_eq!(reach_nlri.announced_routes.len(), 1);
            match &reach_nlri.announced_routes[0] {
                NLRIEncoding::FLOWSPEC(filters) => {
                    assert_eq!(filters.len(), 1);
                    match &filters[0] {
                        FlowspecFilter::DestinationPrefix(prefix) => {
                            assert_eq!(&prefix.to_string(), "2100::/16");
                        }
                        _ => panic!("Destination Prefix not present"),
                    }
                }
                _ => panic!("FLOWSPEC NLRI not present"),
            }
        }
        _ => panic!("MP_REACH_NLRI not present"),
    }
    let update_withdraw = &updates[1];
    match update_withdraw.get(Identifier::MP_UNREACH_NLRI) {
        Some(PathAttribute::MP_UNREACH_NLRI(unreach_nlri)) => {
            assert_eq!(unreach_nlri.afi, AFI::IPV6);
            assert_eq!(unreach_nlri.safi, 133);
            assert_eq!(unreach_nlri.withdrawn_routes.len(), 0);
        }
        _ => panic!("MP_UNREACH_NLRI not present"),
    }
}

#[test]
fn test_flowspec_v6_redirect() {
    let updates = parse_flowspec("res/pcap/BGP_flowspec_redirect.cap").unwrap();
    let update = &updates[2];
    match update.get(Identifier::EXTENDED_COMMUNITIES) {
        Some(PathAttribute::EXTENDED_COMMUNITIES(communities)) => {
            assert_eq!(
                transform_u64_to_bytes(communities[0]),
                [0x80, 0x08, 0, 6, 0, 0, 0x01, 0x2e],
                //                       ^--------^ 4-oct AN
                //              ^-- 2-oct AS
                // ^------^ FlowSpec Redirect
            );
        }
        _ => panic!("Extended Communities not present"),
    }
    match update.get(Identifier::MP_REACH_NLRI) {
        Some(PathAttribute::MP_REACH_NLRI(reach_nlri)) => {
            assert_eq!(reach_nlri.afi, AFI::IPV6);
            assert_eq!(reach_nlri.safi, 133);
            assert_eq!(reach_nlri.announced_routes.len(), 1);
            match &reach_nlri.announced_routes[0] {
                NLRIEncoding::FLOWSPEC(filters) => {
                    assert_eq!(filters.len(), 2);
                    match &filters[0] {
                        FlowspecFilter::DestinationPrefix(prefix) => {
                            assert_eq!(&prefix.to_string(), "3001:99:b::10/128");
                        }
                        _ => panic!("Destination Prefix not present"),
                    }
                    match &filters[1] {
                        FlowspecFilter::SourcePrefix(prefix) => {
                            assert_eq!(&prefix.to_string(), "3001:99:a::10/128");
                        }
                        _ => panic!("Source Prefix not present"),
                    }
                }
                _ => panic!("FLOWSPEC NLRI not present"),
            }
        }
        _ => panic!("MP_REACH_NLRI not present"),
    }
}

#[test]
fn test_flowspec_dscp() {
    let updates = parse_flowspec("res/pcap/BGP_flowspec_dscp.cap").unwrap();
    let update = &updates[0];
    match update.get(Identifier::MP_REACH_NLRI) {
        Some(PathAttribute::MP_REACH_NLRI(reach_nlri)) => {
            assert_eq!(reach_nlri.afi, AFI::IPV6);
            assert_eq!(reach_nlri.safi, 133);
            match &reach_nlri.announced_routes[0] {
                NLRIEncoding::FLOWSPEC(filters) => {
                    assert_eq!(filters.len(), 1);
                    match &filters[0] {
                        FlowspecFilter::DSCP(values) => {
                            assert_eq!(values.len(), 4);
                        }
                        _ => panic!("DSCP Markers not present"),
                    }
                }
                _ => panic!("FLOWSPEC NLRI not present"),
            }
        }
        _ => panic!("MP_REACH_NLRI not present"),
    }
}

#[test]
fn test_flowspec_v4() {
    let updates = parse_flowspec("res/pcap/BGP_flowspec_v4.cap").unwrap();
    let update = &updates[0];
    match update.get(Identifier::EXTENDED_COMMUNITIES) {
        Some(PathAttribute::EXTENDED_COMMUNITIES(communities)) => {
            assert_eq!(
                transform_u64_to_bytes(communities[0]),
                [0x80, 0x06, 0, 0, 0, 0, 0, 0],
                // ^------^ FlowSpec Traffic Rate
            );
        }
        _ => panic!("Extended Communities not present"),
    }
    match update.get(Identifier::MP_REACH_NLRI) {
        Some(PathAttribute::MP_REACH_NLRI(reach_nlri)) => {
            assert_eq!(reach_nlri.afi, AFI::IPV4);
            assert_eq!(reach_nlri.safi, 133);
            match &reach_nlri.announced_routes[0] {
                NLRIEncoding::FLOWSPEC(filters) => {
                    assert_eq!(filters.len(), 6);
                    match &filters[0] {
                        FlowspecFilter::DestinationPrefix(prefix) => {
                            assert_eq!(&prefix.to_string(), "192.168.0.1/32");
                        }
                        _ => panic!("Destination Prefix not present"),
                    }
                    match &filters[1] {
                        FlowspecFilter::SourcePrefix(prefix) => {
                            assert_eq!(&prefix.to_string(), "10.0.0.9/32");
                        }
                        _ => panic!("Source Prefix not present"),
                    }
                    match &filters[2] {
                        FlowspecFilter::IpProtocol(protocols) => {
                            assert_eq!(protocols[0], (1u8, 17u32));
                            assert_eq!(protocols[1], (129u8, 6u32));
                        }
                        _ => panic!("IpProtocol not present"),
                    }
                    match &filters[3] {
                        FlowspecFilter::Port(protocols) => {
                            assert_eq!(protocols[0], (1u8, 80u32));
                            assert_eq!(protocols[1], (145u8, 8080u32));
                        }
                        _ => panic!("Port not present"),
                    }
                    match &filters[4] {
                        FlowspecFilter::DestinationPort(protocols) => {
                            assert_eq!(protocols[0], (18u8, 8080u32));
                            assert_eq!(protocols[1], (84u8, 8088u32));
                            assert_eq!(protocols[2], (145u8, 3128u32));
                        }
                        _ => panic!("DestinationPort not present"),
                    }
                    match &filters[5] {
                        FlowspecFilter::SourcePort(protocols) => {
                            assert_eq!(protocols[0], (146u8, 1024u32));
                        }
                        _ => panic!("DestinationPort not present"),
                    }
                }
                _ => panic!("FLOWSPEC NLRI not present"),
            }
        }
        _ => panic!("MP_REACH_NLRI not present"),
    }
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

fn parse_flowspec(filename: &str) -> Result<Vec<Update>, io::Error> {
    use pcap_file::PcapReader;
    use std::fs::File;
    use twoway::find_bytes;

    println!("Testing: {}", filename);
    let file_in = File::open(filename).expect("Error opening file");
    let pcap_reader = PcapReader::new(file_in).unwrap();

    let mut updates: Vec<Update> = vec![];
    for packet in pcap_reader {
        let packet = packet.unwrap();

        match PacketHeaders::from_ethernet_slice(&packet.data) {
            Err(value) => println!("Err {:?}", value),
            Ok(value) => {
                let mut pos: usize = 0;
                loop {
                    if let Some(i) = find_bytes(&value.payload[pos..], &[255; 16]) {
                        pos += i;
                        let length: usize = *&value.payload[pos + 17] as usize;
                        let stream = &value.payload[pos..pos + length];
                        let mut reader = Reader {
                            stream,
                            capabilities: Capabilities::default(),
                        };
                        let (_header, message) = reader.read()?;
                        if let Message::Update(update) = message {
                            updates.push(update);
                        }
                        pos += length as usize;
                    } else {
                        break;
                    }
                    if pos >= value.payload.len() {
                        break;
                    }
                }
            }
        }
    }
    Ok(updates)
}

fn parse_u16(packet: &[u8]) -> Result<Message, io::Error> {
    // Construct a reader.
    let cursor = Cursor::new(packet);
    let mut reader = bgp_rs::Reader::new(cursor);
    reader.capabilities.FOUR_OCTET_ASN_SUPPORT = false;

    // Read and return the message.
    let (_, message) = reader.read()?;
    Ok(message)
}

fn parse_u32(packet: &[u8]) -> Result<Message, io::Error> {
    // Construct a reader.
    let cursor = Cursor::new(packet);
    let mut reader = bgp_rs::Reader::new(cursor);
    reader.capabilities.FOUR_OCTET_ASN_SUPPORT = true;

    // Read and return the message.
    let (_, message) = reader.read()?;
    Ok(message)
}

fn parse_u32_with_path_id(packet: &[u8]) -> Result<Message, io::Error> {
    // Construct a reader.
    let cursor = Cursor::new(packet);
    let mut reader = bgp_rs::Reader::new(cursor);
    reader.capabilities.FOUR_OCTET_ASN_SUPPORT = true;

    // Read and return the message.
    let (_, message) = reader.read()?;
    Ok(message)
}

pub fn transform_u64_to_bytes(x: u64) -> [u8; 8] {
    let b1: u8 = ((x >> 56) & 0xff) as u8;
    let b2: u8 = ((x >> 48) & 0xff) as u8;
    let b3: u8 = ((x >> 40) & 0xff) as u8;
    let b4: u8 = ((x >> 32) & 0xff) as u8;
    let b5: u8 = ((x >> 24) & 0xff) as u8;
    let b6: u8 = ((x >> 16) & 0xff) as u8;
    let b7: u8 = ((x >> 8) & 0xff) as u8;
    let b8: u8 = (x & 0xff) as u8;
    [b1, b2, b3, b4, b5, b6, b7, b8]
}
