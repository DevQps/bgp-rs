use bgp_rs::Message;
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
    parse_pcap("res/pcap/BGP_notification_msg.cap");
    parse_pcap("res/pcap/BGP_notification.cap");
    parse_pcap("res/pcap/BGP_redist.cap");
    parse_pcap("res/pcap/BGP_soft_reset.cap");
    parse_pcap("res/pcap/EBGP_adjacency.cap");
    parse_pcap("res/pcap/IBGP_adjacency.cap");
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
    reader.capabilities.EXTENDED_PATH_NLRI_SUPPORT = true;

    // Read and return the message.
    let (_, message) = reader.read()?;
    Ok(message)
}
