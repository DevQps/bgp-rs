#![warn(missing_docs)]

//! The `bgp-rs` crate provides functionality to parse BGP-formatted streams.
//!
//! # Examples
//!
//! ## Reading a MRT file containing BPG messages
//! ```
//! use std::fs::File;
//! use std::io::Cursor;
//! use std::io::Read;
//! use std::io::BufReader;
//! use mrt_rs::MRTReader;
//! use mrt_rs::MRTRecord;
//! use mrt_rs::BGP4MP;
//! use libflate::gzip::Decoder;
//!
//! fn main() {
//!     // Open an MRT-formatted file.
//!     let file = File::open("res/updates.20190101.0000.gz").unwrap();
//!
//!     // Decode the GZIP stream using BufReader for better performance.
//!     let mut decoder = Decoder::new(BufReader::new(file)).unwrap();
//!
//!     // Create a new MRTReader with a Cursor such that we can keep track of the position.
//!     let mut reader = MRTReader { stream: decoder };
//!
//!     // Keep reading entries till the end of the file has been reached.
//!     while let Ok(Some(record)) = reader.read() {
//!         match record {
//!            MRTRecord::BGP4MP(x) => match x {
//!                BGP4MP::MESSAGE(x) => {
//!                    let cursor = Cursor::new(x.message);
//!                    let mut reader = bgp_rs::Reader { stream: cursor };
//!                    reader.read().unwrap();
//!                }
//!                BGP4MP::MESSAGE_AS4(x) => {
//!                    let cursor = Cursor::new(x.message);
//!                    let mut reader = bgp_rs::Reader { stream: cursor };
//!                    match reader.read() {
//!                        Err(x) => println!("Error: {}", x),
//!                        Ok(x) => continue
//!                    }
//!                }
//!
//!                _ => continue,
//!            },
//!            _ => continue,
//!        }
//!     }
//! }
//! ```

mod attributes;
mod utility;

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Error, ErrorKind, Read};

pub use crate::attributes::*;
pub use crate::utility::normalize;

/// Represents an Address Family Idenfitier. Currently only IPv4 and IPv6 are supported.
#[derive(Debug)]
#[repr(u16)]
pub enum AFI {
    /// Internet Protocol version 4 (32 bits)
    IPV4 = 1,
    /// Internet Protocol version 6 (128 bits)
    IPV6 = 2,
}

impl AFI {
    fn from(value: u16) -> Result<AFI, Error> {
        match value {
            1 => Ok(AFI::IPV4),
            2 => Ok(AFI::IPV6),
            _ => {
                let msg = format!(
                    "Number {} does not represent a valid address family.",
                    value
                );
                Err(std::io::Error::new(std::io::ErrorKind::Other, msg))
            }
        }
    }

    pub fn size(&self) -> u32 {
        match self {
            AFI::IPV4 => 4,
            AFI::IPV6 => 16,
        }
    }
}

/// Represents the BGP header accompanying every BGP message.
#[derive(Debug)]
pub struct Header {
    /// Predefined marker, must be set to all ones.
    pub marker: [u8; 16],

    /// Indicates the total length of the message, including the header in bytes.
    pub length: u16,

    /// Indicates the type of message that follows the header.
    pub record_type: u8,
}

/// Represents a single BGP message.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Message {
    Open(Open),
    Update(Update),
    Notification,
    KeepAlive,
    RouteRefresh,
}

/// Represents a BGP Open message.
#[derive(Debug)]
pub struct Open {
    /// Indicates the protocol version number of the message. The current BGP version number is 4.
    version: u8,

    /// Indicates the Autonomous System number of the sender.
    peer_asn: u16,

    /// Indicates the number of seconds the sender proposes for the value of the Hold Timer.
    hold_timer: u16,

    /// Indicates the BGP Identifier of the sender.
    identifier: u32,

    /// Optional Parameters
    parameters: Vec<OpenParameter>,
}

impl Open {
    fn parse(stream: &mut Read) -> Result<Open, Error> {
        let version = stream.read_u8()?;
        let peer_asn = stream.read_u16::<BigEndian>()?;
        let hold_timer = stream.read_u16::<BigEndian>()?;
        let identifier = stream.read_u32::<BigEndian>()?;
        let length = stream.read_u8()?;
        let mut parameters: Vec<OpenParameter> = Vec::with_capacity(length as usize);
        for _ in 0..length {
            parameters.push(OpenParameter::parse(stream)?);
        }

        Ok(Open {
            version,
            peer_asn,
            hold_timer,
            identifier,
            parameters,
        })
    }
}

/// Represents a parameter in the optional parameter section of an Open message.
#[derive(Debug)]
pub struct OpenParameter {
    /// The type of the parameter.
    pub param_type: u8,

    /// The length of the data that this parameter holds in bytes.
    pub length: u8,

    /// The value that is set for this parameter.
    pub value: Vec<u8>,
}

impl OpenParameter {
    fn parse(stream: &mut Read) -> Result<OpenParameter, Error> {
        let param_type = stream.read_u8()?;
        let length = stream.read_u8()?;
        let mut value = vec![0; length as usize];
        stream.read_exact(&mut value);
        Ok(OpenParameter {
            param_type,
            length,
            value,
        })
    }
}

/// Represents a BGP Update message.
#[derive(Debug)]
pub struct Update {
    /// A collection of routes that have been withdrawn.
    withdrawn_routes: Vec<Prefix>,

    /// A collection of attributes associated with the announced routes.
    attributes: Vec<Attribute>,

    /// A collection of routes that are announced by the peer.
    announced_routes: Vec<Prefix>,
}

impl Update {
    fn parse(stream: &mut Read, header: &Header) -> Result<Update, Error> {
        let mut nlri_length: usize = header.length as usize - 23;

        // ----------------------------
        // Read withdrawn routes.
        // ----------------------------
        let length = stream.read_u16::<BigEndian>()? as usize;
        let mut buffer = vec![0; length];
        stream.read_exact(&mut buffer);
        nlri_length -= length;

        let mut withdrawn_routes: Vec<Prefix> = Vec::with_capacity(0);
        let mut cursor = Cursor::new(buffer);
        while cursor.position() < length as u64 {
            withdrawn_routes.push(Prefix::parse(&mut cursor)?);
        }

        // ----------------------------
        // Read path attributes
        // ----------------------------
        let length = stream.read_u16::<BigEndian>()? as usize;
        let mut buffer = vec![0; length];
        stream.read_exact(&mut buffer);
        nlri_length -= length;

        let mut attributes: Vec<Attribute> = Vec::with_capacity(8);
        let mut cursor = Cursor::new(buffer);
        while cursor.position() < length as u64 {
            let attribute = Attribute::parse(&mut cursor)?;
            attributes.push(attribute);
        }

        // ----------------------------
        // Read NLRI
        // ----------------------------
        let mut buffer = vec![0; nlri_length as usize];
        stream.read_exact(&mut buffer);
        let mut cursor = Cursor::new(buffer);
        let mut announced_routes: Vec<Prefix> = Vec::with_capacity(4);

        while cursor.position() < nlri_length as u64 {
            announced_routes.push(Prefix::parse(&mut cursor)?);
        }

        Ok(Update {
            withdrawn_routes,
            attributes,
            announced_routes,
        })
    }
}

#[derive(Debug)]
pub struct Prefix {
    length: u8,
    prefix: Vec<u8>,
}

impl Prefix {
    fn parse(stream: &mut Read) -> Result<Prefix, Error> {
        let length = stream.read_u8()?;
        let mut prefix: Vec<u8> = vec![0; ((length + 7) / 8) as usize];
        stream.read_exact(&mut prefix)?;
        Ok(Prefix { length, prefix })
    }
}

/// Represents a BGP Notification message.
#[derive(Debug)]
pub struct Notification {}

/// The BGPReader can read BGP messages from a BGP-formatted stream.
pub struct Reader<T>
where
    T: Read,
{
    /// The stream from which BGP messages will be read.
    pub stream: T,
}

impl<T> Reader<T>
where
    T: Read,
{
    ///
    /// Reads the next BGP message in the stream.
    ///
    /// # Panics
    /// This function does not panic.
    ///
    /// # Errors
    /// Any IO error will be returned while reading from the stream.
    /// If an ill-formatted stream provided behavior will be undefined.
    ///
    /// # Safety
    /// This function does not make use of unsafe code.
    ///
    pub fn read(&mut self) -> Result<(Header, Message), Error> {
        // Parse the header.
        let mut marker: [u8; 16] = [0; 16];
        self.stream.read_exact(&mut marker)?;

        let header = Header {
            marker,
            length: self.stream.read_u16::<BigEndian>()?,
            record_type: self.stream.read_u8()?,
        };

        match header.record_type {
            1 => Ok((header, Message::Open(Open::parse(&mut self.stream)?))),
            2 => {
                let attribute = Message::Update(Update::parse(&mut self.stream, &header)?);
                Ok((header, attribute))
            }
            3 => Ok((header, Message::Notification)),
            4 => Ok((header, Message::KeepAlive)),
            5 => unimplemented!("ROUTE-REFRESH messages are not yet implemented."),
            _ => Err(Error::new(
                ErrorKind::Other,
                "Unknown BGP message type found in BGPHeader",
            )),
        }
    }
}
