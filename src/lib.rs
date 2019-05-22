#![deny(missing_docs)]

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
//! use mrt_rs::Record;
//! use mrt_rs::bgp4mp::BGP4MP;
//! use libflate::gzip::Decoder;
//! use bgp_rs::{Identifier, PathAttribute};
//!
//! fn main() {
//!    // Download an update message.
//!    let file = File::open("res/mrt/updates.20190101.0000.gz").unwrap();
//!
//!    // Decode the GZIP stream.
//!    let decoder = Decoder::new(BufReader::new(file)).unwrap();
//!
//!    // Create a new MRTReader with a Cursor such that we can keep track of the position.
//!    let mut reader = mrt_rs::Reader { stream: decoder };
//!
//!    // Keep reading MRT (Header, Record) tuples till the end of the file has been reached.
//!    while let Ok(Some((_, record))) = reader.read() {
//!
//!        // Extract BGP4MP::MESSAGE_AS4 entries.
//!        if let Record::BGP4MP(BGP4MP::MESSAGE_AS4(x)) = record {
//!
//!            // Read each BGP (Header, Message)
//!            let cursor = Cursor::new(x.message);
//!            let mut reader = bgp_rs::Reader::new(cursor);
//!            let (_, message) = reader.read().unwrap();
//!
//!            // If this is an UPDATE message that contains announcements, extract its origin.
//!            if let bgp_rs::Message::Update(x) = message {
//!                if x.is_announcement() {
//!                    if let PathAttribute::AS_PATH(path) = x.get(Identifier::AS_PATH).unwrap()
//!                    {
//!                        // Test the path.origin() method.
//!                        let origin = path.origin();
//!
//!                        // Do other stuff ...
//!                    }
//!                }
//!            }
//!        }
//!    }
//! }
//! ```

/// Contains the implementation of all BGP path attributes.
pub mod attributes;

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Error, ErrorKind, Read};

pub use crate::attributes::*;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::net::IpAddr;

/// Represents an Address Family Idenfitier. Currently only IPv4 and IPv6 are supported.
#[derive(Debug, Copy, Clone)]
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
#[derive(Debug)]
pub enum Message {
    /// Represent a BGP OPEN message.
    Open(Open),

    /// Represent a BGP UPDATE message.
    Update(Update),

    /// Represent a BGP NOTIFICATION message.
    Notification,

    /// Represent a BGP KEEPALIVE message.
    KeepAlive,

    /// Represent a BGP ROUTE_REFRESH message.
    RouteRefresh(RouteRefresh),
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
        let mut length = stream.read_u8()?;

        let mut parameters: Vec<OpenParameter> = Vec::with_capacity(length as usize);

        while length > 0 {
            let (bytes_read, parameter) = OpenParameter::parse(stream)?;
            parameters.push(parameter);
            length -= bytes_read;
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
    pub param_length: u8,

    /// The value that is set for this parameter.
    pub value: Vec<u8>,
}

impl OpenParameter {
    fn parse(stream: &mut Read) -> Result<(u8, OpenParameter), Error> {
        let param_type = stream.read_u8()?;
        let param_length = stream.read_u8()?;

        let mut value = vec![0; param_length as usize];
        stream.read_exact(&mut value)?;

        Ok((
            2 + param_length,
            OpenParameter {
                param_type,
                param_length,
                value,
            },
        ))
    }
}

/// Represents a BGP Update message.
#[derive(Debug)]
pub struct Update {
    /// A collection of routes that have been withdrawn.
    withdrawn_routes: Vec<Prefix>,

    /// A collection of attributes associated with the announced routes.
    attributes: Vec<PathAttribute>,

    /// A collection of routes that are announced by the peer.
    announced_routes: Vec<NLRIEncoding>,
}

impl Update {
    fn parse(
        header: &Header,
        stream: &mut Read,
        capabilities: &Capabilities,
    ) -> Result<Update, Error> {
        let mut nlri_length: usize = header.length as usize - 23;

        // ----------------------------
        // Read withdrawn routes.
        // ----------------------------
        let length = stream.read_u16::<BigEndian>()? as usize;
        let mut buffer = vec![0; length];
        stream.read_exact(&mut buffer)?;
        nlri_length -= length;

        let mut withdrawn_routes: Vec<Prefix> = Vec::with_capacity(0);
        let mut cursor = Cursor::new(buffer);
        while cursor.position() < length as u64 {
            withdrawn_routes.push(Prefix::parse(&mut cursor, AFI::IPV4)?);
        }

        // ----------------------------
        // Read path attributes
        // ----------------------------
        let length = stream.read_u16::<BigEndian>()? as usize;
        let mut buffer = vec![0; length];
        stream.read_exact(&mut buffer)?;
        nlri_length -= length;

        let mut attributes: Vec<PathAttribute> = Vec::with_capacity(8);
        let mut cursor = Cursor::new(buffer);
        while cursor.position() < length as u64 {
            let attribute = PathAttribute::parse(&mut cursor, capabilities)?;
            attributes.push(attribute);
        }

        // ----------------------------
        // Read NLRI
        // ----------------------------
        let mut buffer = vec![0; nlri_length as usize];

        stream.read_exact(&mut buffer)?;
        let mut cursor = Cursor::new(buffer);
        let mut announced_routes: Vec<NLRIEncoding> = Vec::with_capacity(4);

        if capabilities.EXTENDED_PATH_NLRI_SUPPORT {
            while cursor.position() < nlri_length as u64 {
                let path_id = cursor.read_u32::<BigEndian>()?;
                let prefix = Prefix::parse(&mut cursor, AFI::IPV4)?;
                announced_routes.push(NLRIEncoding::IP_WITH_PATH_ID((prefix, path_id)));
            }
        } else {
            while cursor.position() < nlri_length as u64 {
                announced_routes.push(NLRIEncoding::IP(Prefix::parse(&mut cursor, AFI::IPV4)?));
            }
        }

        Ok(Update {
            withdrawn_routes,
            attributes,
            announced_routes,
        })
    }

    /// Retrieves the first PathAttribute that matches the given identifier.
    pub fn get(&self, identifier: Identifier) -> Option<&PathAttribute> {
        for a in &self.attributes {
            if a.id() == identifier {
                return Some(a);
            }
        }
        None
    }

    /// Checks if this UPDATE message contains announced prefixes.
    pub fn is_announcement(&self) -> bool {
        if !self.announced_routes.is_empty() || self.get(Identifier::MP_REACH_NLRI).is_some() {
            return true;
        }
        false
    }

    /// Checks if this UPDATE message contains withdrawn routes..
    pub fn is_withdrawal(&self) -> bool {
        if !self.withdrawn_routes.is_empty() || self.get(Identifier::MP_UNREACH_NLRI).is_some() {
            return true;
        }
        false
    }

    /// Moves the MP_REACH and MP_UNREACH NLRI into the NLRI.
    pub fn normalize(&mut self) {
        // Move the MP_REACH_NLRI attribute in the NLRI.
        if let Some(PathAttribute::MP_REACH_NLRI(routes)) = self.get(Identifier::MP_REACH_NLRI) {
            self.announced_routes
                .extend(routes.announced_routes.clone())
        }

        // Move the MP_REACH_NLRI attribute in the NLRI.
        if let Some(PathAttribute::MP_UNREACH_NLRI(routes)) = self.get(Identifier::MP_UNREACH_NLRI)
        {
            self.withdrawn_routes
                .extend(routes.withdrawn_routes.clone())
        }
    }
}

/// Represents NLRIEncodings present in the NRLI section of an UPDATE message.
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub enum NLRIEncoding {
    /// Encodings that specify only an IP present, either IPv4 or IPv6
    IP(Prefix),

    /// Encodings that specify a Path Identifier as specified in RFC7911. (Prefix, Label)
    IP_WITH_PATH_ID((Prefix, u32)),

    /// Encodings that specify a Path Identifier as specified in RFC8277. (Prefix, MPLS Label)
    IP_MPLS((Prefix, u32)),
}

/// Represents a generic prefix. For example an IPv4 prefix or IPv6 prefix.
#[derive(Clone)]
pub struct Prefix {
    protocol: AFI,
    length: u8,
    prefix: Vec<u8>,
}

impl From<&Prefix> for IpAddr {
    fn from(prefix: &Prefix) -> Self {
        match prefix.protocol {
            AFI::IPV4 => {
                let mut buffer: [u8; 4] = [0; 4];
                buffer[..prefix.prefix.len()].clone_from_slice(&prefix.prefix[..]);
                IpAddr::from(buffer)
            }
            AFI::IPV6 => {
                let mut buffer: [u8; 16] = [0; 16];
                buffer[..prefix.prefix.len()].clone_from_slice(&prefix.prefix[..]);
                IpAddr::from(buffer)
            }
        }
    }
}

impl Display for Prefix {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}/{}", IpAddr::from(self), self.length)
    }
}

impl Debug for Prefix {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}/{}", IpAddr::from(self), self.length)
    }
}

impl Prefix {
    fn parse(stream: &mut Read, protocol: AFI) -> Result<Prefix, Error> {
        let length = stream.read_u8()?;
        let mut prefix: Vec<u8> = vec![0; ((length + 7) / 8) as usize];
        stream.read_exact(&mut prefix)?;

        Ok(Prefix {
            protocol,
            length,
            prefix,
        })
    }
}

/// Represents a BGP Notification message.
#[derive(Debug)]
pub struct Notification {}

/// Represents a BGP Route Refresh message.
#[derive(Debug)]
pub struct RouteRefresh {
    afi: AFI,
    safi: u8,
}

impl RouteRefresh {
    fn parse(stream: &mut Read) -> Result<RouteRefresh, Error> {
        let afi = AFI::from(stream.read_u16::<BigEndian>()?)?;
        let _ = stream.read_u8()?;
        let safi = stream.read_u8()?;

        Ok(RouteRefresh { afi, safi })
    }
}

/// Contains the BGP session parameters that distinguish how BGP messages should be parsed.
#[allow(non_snake_case)]
pub struct Capabilities {
    /// Support for 4-octet AS number capability.
    pub FOUR_OCTET_ASN_SUPPORT: bool,

    /// Support for reading NLRI extended with a Path Identifier
    pub EXTENDED_PATH_NLRI_SUPPORT: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        Capabilities {
            // Parse ASN as 32-bit ASN by default.
            FOUR_OCTET_ASN_SUPPORT: true,

            // Do not use Extended Path NLRI by default
            EXTENDED_PATH_NLRI_SUPPORT: false,
        }
    }
}

/// The BGPReader can read BGP messages from a BGP-formatted stream.
pub struct Reader<T>
where
    T: Read,
{
    /// The stream from which BGP messages will be read.
    pub stream: T,

    /// Capability parameters that distinguish how BGP messages should be parsed.
    pub capabilities: Capabilities,
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
                let attribute = Message::Update(Update::parse(
                    &header,
                    &mut self.stream,
                    &self.capabilities,
                )?);
                Ok((header, attribute))
            }
            3 => Ok((header, Message::Notification)),
            4 => Ok((header, Message::KeepAlive)),
            5 => Ok((
                header,
                Message::RouteRefresh(RouteRefresh::parse(&mut self.stream)?),
            )),
            _ => Err(Error::new(
                ErrorKind::Other,
                "Unknown BGP message type found in BGPHeader",
            )),
        }
    }

    ///
    /// Constructs a BGPReader with default parameters.
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
    ///
    pub fn new(stream: T) -> Reader<T>
    where
        T: Read,
    {
        Reader::<T> {
            stream,
            capabilities: Default::default(),
        }
    }
}
