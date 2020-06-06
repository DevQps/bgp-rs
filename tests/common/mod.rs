#[allow(dead_code)]
#[cfg(test)]
pub mod parse {
    use bgp_rs::{Capabilities, Message, Reader};
    use etherparse::PacketHeaders;
    use pcap_file::PcapReader;
    use std::fs::File;
    use std::io::{self, Cursor};
    use twoway::find_bytes;

    /// Parse and return messages as bytes from a given pcap file
    pub fn parse_pcap_message_bytes(filename: &str) -> Result<Vec<Vec<u8>>, io::Error> {
        let file_in = File::open(filename)
            .map(|file| {
                println!("Testing: {}", filename);
                file
            })
            .map_err(|e| {
                eprintln!("Error opening file: {}", filename);
                e
            })
            .unwrap();
        let pcap_reader = PcapReader::new(file_in).unwrap();

        let mut message_chunks: Vec<Vec<u8>> = vec![];
        for packet in pcap_reader {
            let packet = packet.unwrap();

            match PacketHeaders::from_ethernet_slice(&packet.data) {
                Err(value) => println!("Err {:?}", value),
                Ok(value) => {
                    let mut pos: usize = 0;
                    loop {
                        if let Some(i) = find_bytes(&value.payload[pos..], &[255; 16]) {
                            pos += i;
                            let length: usize = value.payload[pos + 17] as usize;
                            let stream = &value.payload[pos..pos + length];
                            message_chunks.push(stream.to_owned());
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
        Ok(message_chunks)
    }

    /// Parse and return Messages from a given pcap file
    pub fn parse_pcap_messages(filename: &str) -> Result<Vec<Message>, io::Error> {
        let message_bytes = parse_pcap_message_bytes(&filename)?;

        let mut messages: Vec<Message> = vec![];
        for message_chunk in message_bytes {
            let mut reader = Reader {
                stream: Cursor::new(message_chunk),
                capabilities: Capabilities::default(),
            };
            let (_header, message) = reader.read()?;
            messages.push(message);
        }
        Ok(messages)
    }

    /// For a given message as bytes,
    /// make sure that the parsed and re-encoded message is the same
    pub fn test_message_roundtrip(message_bytes: &[u8]) -> Result<(), io::Error> {
        let mut reader = Reader {
            stream: Cursor::new(message_bytes),
            capabilities: Capabilities::default(),
        };
        let (_header, message) = reader.read()?;
        let mut encoded: Vec<u8> = vec![];
        message.encode(&mut encoded)?;
        assert_eq!(
            message_bytes.to_vec(),
            encoded,
            "Parsed message: {:?}",
            &message
        );
        Ok(())
    }

    pub fn test_pcap_roundtrip(filename: &str) -> Result<(), io::Error> {
        let messages = parse_pcap_message_bytes(&filename)?;
        for message in messages {
            test_message_roundtrip(&message)?;
        }
        Ok(())
    }

    pub fn parse_u16(packet: &[u8]) -> Result<Message, io::Error> {
        // Construct a reader.
        let cursor = Cursor::new(packet);
        let mut reader = bgp_rs::Reader::new(cursor);
        reader.capabilities.FOUR_OCTET_ASN_SUPPORT = false;

        // Read and return the message.
        let (_, message) = reader.read()?;
        Ok(message)
    }

    pub fn parse_u32(packet: &[u8]) -> Result<Message, io::Error> {
        // Construct a reader.
        let cursor = Cursor::new(packet);
        let mut reader = bgp_rs::Reader::new(cursor);
        reader.capabilities.FOUR_OCTET_ASN_SUPPORT = true;

        // Read and return the message.
        let (_, message) = reader.read()?;
        Ok(message)
    }

    pub fn parse_u32_with_path_id(packet: &[u8]) -> Result<Message, io::Error> {
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
}
