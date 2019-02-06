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
        match record {
            Record::BGP4MP(x) => match x {
                BGP4MP::MESSAGE(x) => {
                    let cursor = Cursor::new(x.message);
                    let mut reader = bgp_rs::Reader { stream: cursor };
                    reader.read().unwrap();
                }
                BGP4MP::MESSAGE_AS4(x) => {
                    let cursor = Cursor::new(x.message);
                    let mut reader = bgp_rs::Reader { stream: cursor };
                    match reader.read() {
                        Err(x) => println!("Error: {}", x),
                        Ok(_) => continue,
                    }
                }

                _ => continue,
            },
            _ => continue,
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
        match record {
            Record::TABLE_DUMP_V2(x) => match x {
                TABLE_DUMP_V2::RIB_IPV4_UNICAST(x) => {
                    for entry in x.entries {
                        let length = entry.attributes.len() as u64;
                        let mut cursor = Cursor::new(entry.attributes);

                        while cursor.position() < length {
                            let result = PathAttribute::parse(&mut cursor);
                            match result {
                                Err(x) => println!("Error: {}", x),
                                Ok(_) => continue,
                            }
                        }
                    }
                }
                TABLE_DUMP_V2::RIB_IPV6_UNICAST(x) => {
                    for entry in x.entries {
                        let length = entry.attributes.len() as u64;
                        let mut cursor = Cursor::new(entry.attributes);

                        while cursor.position() < length {
                            let result = PathAttribute::parse(&mut cursor);
                            match result {
                                Err(x) => println!("Error: {}", x),
                                Ok(_) => continue,
                            }
                        }
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }
}
