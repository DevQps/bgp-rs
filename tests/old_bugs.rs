use bgp_rs::Message;
use std::io;
use std::io::Cursor;

#[test]
fn unknown_attributes() {
    // A route with bogus route attributes curtsey of CT Education Network
    let unknown_attributes = [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 147, 2, 0, 0, 0, 112, 64, 1, 1, 0, 64, 2, 22, 2, 5, 0, 6, 10, 77, 0, 0, 214, 41, 0, 0, 89, 38, 0, 0, 43, 156, 0, 0, 88, 214, 64, 3, 4, 10, 70, 71, 34, 128, 4, 4, 0, 0, 3, 52, 64, 5, 4, 0, 0, 0, 50, 192, 8, 24, 10, 77, 11, 184, 89, 38, 8, 82, 214, 41, 1, 244, 252, 38, 4, 149, 252, 39, 11, 135, 252, 40, 43, 156, 128, 9, 4, 69, 59, 18, 1, 192, 16, 8, 0, 2, 88, 214, 0, 0, 3, 9, 224, 20, 14, 0, 1, 0, 0, 88, 214, 0, 0, 2, 142, 207, 210, 141, 181, 23, 72, 10, 118, 24, 72, 10, 114, 20, 149, 152, 64];

    // Construct a reader.
    let cursor = Cursor::new(&unknown_attributes[..]);
    let mut reader = bgp_rs::Reader::new(cursor);
    reader.capabilities.FOUR_OCTET_ASN_SUPPORT = true;

    // Read the message.
    reader.read().unwrap();
}
