use bgp_rs::attributes::{Identifier, PathAttribute};
use libflate::gzip::Decoder;
use mrt_rs::bgp4mp::BGP4MP;
use mrt_rs::Record;
use std::fs::File;
use std::io::BufReader;
use std::io::Cursor;

// Tests if it is able to parse a stream of BGP4MP messages.
#[test]
fn parse_updates() {
    // Download an update message.
    let file = File::open("res/updates.20190101.0000.gz").unwrap();

    // Decode the GZIP stream.
    let decoder = Decoder::new(BufReader::new(file)).unwrap();

    // Create a new MRTReader with a Cursor such that we can keep track of the position.
    let mut reader = mrt_rs::Reader { stream: decoder };

    // Keep reading (Header, Record) tuples till the end of the file has been reached.
    while let Ok(Some((_, record))) = reader.read() {
        // Extract BGP4MP::MESSAGE_AS4 entries.
        if let Record::BGP4MP(BGP4MP::MESSAGE_AS4(x)) = record {
            // Read each BGP message
            let cursor = Cursor::new(x.message);
            let mut reader = bgp_rs::Reader { stream: cursor };
            let (_, message) = reader.read().unwrap();

            // If this is an UPDATE message that contains announcements, extract its origin.
            if let bgp_rs::Message::Update(mut x) = message {

                // Test the normalize function.
                x.normalize();

                if x.is_announcement() {
                    if let PathAttribute::AS_PATH(path) = x.get(Identifier::AS_PATH).unwrap() {

                        // Test the path.origin() method.
                        let _ = path.origin();
                    }
                }
            }
        }
    }
}

// Tests if it is able to parse a stream of TABLE_DUMP_V2 messages.
#[test]
fn parse_rib() {
    use bgp_rs::PathAttribute;
    use mrt_rs::tabledump::TABLE_DUMP_V2;

    // Download an update message.
    let file = File::open("res/bview.20100101.0759.gz").unwrap();

    // Decode the GZIP stream.
    let decoder = Decoder::new(BufReader::new(file)).unwrap();

    // Create a new MRTReader
    let mut reader = mrt_rs::Reader { stream: decoder };

    // Read an MRT (Header, Record) tuple.
    while let Ok(Some((_, record))) = reader.read() {
        // Extract TABLE_DUMP_V2::RIB_IPV4_UNICAST entries.
        if let Record::TABLE_DUMP_V2(TABLE_DUMP_V2::RIB_IPV4_UNICAST(x)) = record {
            // Loop over each route for this particular prefix.
            for entry in x.entries {
                let length = entry.attributes.len() as u64;
                let mut cursor = Cursor::new(entry.attributes);

                // Parse each PathAttribute in each route.
                while cursor.position() < length {
                    PathAttribute::parse(&mut cursor).unwrap();
                }
            }
        }
    }
}
