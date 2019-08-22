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

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Error, ErrorKind, Read, Write};

pub use crate::attributes::*;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::net::IpAddr;

struct SizeCalcWriter(usize);
impl Write for SizeCalcWriter {
    fn write(&mut self, b: &[u8]) -> Result<usize, Error> {
        self.0 += b.len();
        Ok(b.len())
    }
    fn flush (&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Represents an Address Family Identifier. Currently only IPv4 and IPv6 are supported.
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

/// Represents an Subsequent Address Family Identifier. Currently only Unicast and Multicast are
/// supported.
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum SAFI {
    /// Unicast Forwarding
    Unicast = 1,
    /// Multicast Forwarding
    Multicast = 2,
}

impl SAFI {
    fn from(value: u8) -> Result<SAFI, Error> {
        match value {
            1 => Ok(SAFI::Unicast),
            2 => Ok(SAFI::Multicast),
            _ => {
                let msg = format!(
                    "Number {} does not represent a valid subsequent address family.",
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

impl Header {
    fn write(&self, write: &mut Write) -> Result<(), Error> {
        write.write_all(&self.marker)?;
        write.write_u16::<BigEndian>(self.length)?;
        write.write_u8(self.record_type)
    }
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
    pub version: u8,

    /// Indicates the Autonomous System number of the sender.
    pub peer_asn: u16,

    /// Indicates the number of seconds the sender proposes for the value of the Hold Timer.
    pub hold_timer: u16,

    /// Indicates the BGP Identifier of the sender.
    pub identifier: u32,

    /// Optional Parameters
    pub parameters: Vec<OpenParameter>,
}

impl Open {
    fn parse(stream: &mut Read) -> Result<Open, Error> {
        let version = stream.read_u8()?;
        let peer_asn = stream.read_u16::<BigEndian>()?;
        let hold_timer = stream.read_u16::<BigEndian>()?;
        let identifier = stream.read_u32::<BigEndian>()?;
        let mut length = stream.read_u8()? as i32;

        let mut parameters: Vec<OpenParameter> = Vec::with_capacity(length as usize);

        while length > 0 {
            let (bytes_read, parameter) = OpenParameter::parse(stream)?;
            parameters.push(parameter);
            length -= bytes_read as i32;
        }
        if length != 0 {
            return Err(Error::new(ErrorKind::InvalidData, "Open length does not match options length"));
        }

        Ok(Open {
            version,
            peer_asn,
            hold_timer,
            identifier,
            parameters,
        })
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        write.write_u8(self.version)?;
        write.write_u16::<BigEndian>(self.peer_asn)?;
        write.write_u16::<BigEndian>(self.hold_timer)?;
        write.write_u32::<BigEndian>(self.identifier)?;

        let mut len = SizeCalcWriter(0);
        for p in self.parameters.iter() {
            p.write(&mut len)?;
        }
        if len.0 > std::u8::MAX as usize {
            return Err(Error::new(ErrorKind::Other, format!("Cannot encode parameters with length {}", len.0)));
        }
        write.write_u8(len.0 as u8)?;

        for p in self.parameters.iter() {
            p.write(write)?;
        }
        Ok(())
    }
}

/// The direction which an ADD-PATH capabilty indicates a peer can provide additional paths.
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum AddPathDirection {
    /// Indiates a peer can recieve additional paths.
    ReceivePaths = 1,

    /// Indiates a peer can send additional paths.
    SendPaths = 2,

    /// Indiates a peer can both send and receive additional paths.
    SendReceivePaths = 3,
}

impl AddPathDirection {
    fn from(value: u8) -> Result<AddPathDirection, Error> {
        match value {
            1 => Ok(AddPathDirection::ReceivePaths),
            2 => Ok(AddPathDirection::SendPaths),
            3 => Ok(AddPathDirection::SendReceivePaths),
            _ => {
                let msg = format!(
                    "Number {} does not represent a valid ADD-PATH direction.",
                    value
                );
                Err(std::io::Error::new(std::io::ErrorKind::Other, msg))
            }
        }
    }
}

/// Represents a known capability held in an OpenParameter
#[derive(Debug)]
pub enum OpenCapability {
    /// Indicates the speaker is willing to exchange multiple protocols over this session.
    MultiProtocol((AFI, SAFI)),
    /// Indicates the speaker supports route refresh.
    RouteRefresh,
    /// Indicates the speaker supports 4 byte ASNs and includes the ASN of the speaker.
    FourByteASN(u32),
    /// Indicates the speaker supports sending/receiving multiple paths for a given prefix.
    AddPath(Vec<(AFI, SAFI, AddPathDirection)>),
    /// Unknown (or unsupported) capability
    Unknown {
        /// The type of the capability.
        cap_code: u8,

        /// The length of the data that this capability holds in bytes.
        cap_length: u8,

        /// The value that is set for this capability.
        value: Vec<u8>,
    },
}

impl OpenCapability {
    fn parse(stream: &mut Read) -> Result<(u16, OpenCapability), Error> {
        let cap_code = stream.read_u8()?;
        let cap_length = stream.read_u8()?;

        Ok((
            2 + (cap_length as u16),
            match cap_code {
                1 => {
                    if cap_length != 4 {
                        return Err(Error::new(ErrorKind::InvalidData, "Multi-Protocol capability must be 4 bytes in length"));
                    }
                    let afi = AFI::from(stream.read_u16::<BigEndian>()?)?;
                    let _ = stream.read_u8()?;
                    let safi = SAFI::from(stream.read_u8()?)?;
                    OpenCapability::MultiProtocol((afi, safi))
                },
                2 => {
                    if cap_length != 0 {
                        return Err(Error::new(ErrorKind::InvalidData, "Route-Refresh capability must be 0 bytes in length"));
                    }
                    OpenCapability::RouteRefresh
                },
                65 => {
                    if cap_length != 4 {
                        return Err(Error::new(ErrorKind::InvalidData, "4-byte ASN capability must be 4 bytes in length"));
                    }
                    OpenCapability::FourByteASN(stream.read_u32::<BigEndian>()?)
                },
                69 => {
                    if cap_length % 4 != 0 {
                        return Err(Error::new(ErrorKind::InvalidData, "ADD-PATH capability length must be divisble by 4"));
                    }
                    let mut add_paths = Vec::with_capacity(cap_length as usize / 4);
                    for _ in 0..(cap_length / 4) {
                        add_paths.push((
                            AFI::from(stream.read_u16::<BigEndian>()?)?,
                            SAFI::from(stream.read_u8()?)?,
                            AddPathDirection::from(stream.read_u8()?)?
                        ));
                    }
                    OpenCapability::AddPath(add_paths)
                },
                _ => {
                    let mut value = vec![0; cap_length as usize];
                    stream.read_exact(&mut value)?;
                    OpenCapability::Unknown {
                        cap_code,
                        cap_length,
                        value,
                    }
                },
            }
        ))
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        match self {
            OpenCapability::MultiProtocol((afi, safi)) => {
                write.write_u8(1)?;
                write.write_u8(4)?;
                write.write_u16::<BigEndian>(*afi as u16)?;
                write.write_u8(0)?;
                write.write_u8(*safi as u8)
            },
            OpenCapability::RouteRefresh => {
                write.write_u8(2)?;
                write.write_u8(0)
            },
            OpenCapability::FourByteASN(asn) => {
                write.write_u8(65)?;
                write.write_u8(4)?;
                write.write_u32::<BigEndian>(*asn)
            },
            OpenCapability::AddPath(add_paths) => {
                write.write_u8(69)?;
                if add_paths.len() * 4 > std::u8::MAX as usize {
                    return Err(Error::new(ErrorKind::Other, format!("Cannot encode ADD-PATH with too many AFIs {}", add_paths.len())));
                }
                write.write_u8(add_paths.len() as u8 * 4)?;
                for p in add_paths.iter() {
                    write.write_u16::<BigEndian>(p.0 as u16)?;
                    write.write_u8(p.1 as u8)?;
                    write.write_u8(p.2 as u8)?;
                }
                Ok(())
            },
            OpenCapability::Unknown { cap_code, cap_length, value } => {
                write.write_u8(*cap_code)?;
                write.write_u8(*cap_length)?;
                write.write_all(&value)
            },
        }
    }
}

/// Represents a parameter in the optional parameter section of an Open message.
#[derive(Debug)]
pub enum OpenParameter {
    /// A list of capabilities supported by the sender.
    Capabilities(Vec<OpenCapability>),

    /// Unknown (or unsupported) parameter
    Unknown {
        /// The type of the parameter.
        param_type: u8,

        /// The length of the data that this parameter holds in bytes.
        param_length: u8,

        /// The value that is set for this parameter.
        value: Vec<u8>,
    },
}

impl OpenParameter {
    fn parse(stream: &mut Read) -> Result<(u16, OpenParameter), Error> {
        let param_type = stream.read_u8()?;
        let param_length = stream.read_u8()?;

        Ok((
            2 + (param_length as u16),
            if param_type == 2 {
                let mut bytes_read: i32 = 0;
                let mut capabilities = Vec::with_capacity(param_length as usize / 2);
                while bytes_read < param_length as i32 {
                    let (cap_length, cap) = OpenCapability::parse(stream)?;
                    capabilities.push(cap);
                    bytes_read += cap_length as i32;
                }
                if bytes_read != param_length as i32 {
                    return Err(Error::new(ErrorKind::InvalidData,
                        format!("Capability length {} does not match parameter length {}", bytes_read, param_length)));
                } else {
                    OpenParameter::Capabilities(capabilities)
                }
            } else {
                let mut value = vec![0; param_length as usize];
                stream.read_exact(&mut value)?;
                OpenParameter::Unknown {
                    param_type,
                    param_length,
                    value,
                }
            }
        ))
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        match self {
            OpenParameter::Capabilities(caps) => {
                write.write_u8(2)?;

                let mut len = SizeCalcWriter(0);
                for c in caps.iter() {
                    c.write(&mut len)?;
                }
                if len.0 > std::u8::MAX as usize {
                    return Err(Error::new(ErrorKind::Other, format!("Cannot encode capabilities with length {}", len.0)));
                }
                write.write_u8(len.0 as u8)?;

                for c in caps.iter() {
                    c.write(write)?;
                }
                Ok(())
            },
            OpenParameter::Unknown { param_type, param_length, value } => {
                write.write_u8(*param_type)?;
                write.write_u8(*param_length)?;
                write.write_all(&value)
            },
        }
    }
}

/// Represents a BGP Update message.
#[derive(Debug)]
pub struct Update {
    /// A collection of routes that have been withdrawn.
    withdrawn_routes: Vec<NLRIEncoding>,

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

        let mut withdrawn_routes: Vec<NLRIEncoding> = Vec::with_capacity(0);
        let mut cursor = Cursor::new(buffer);

        if capabilities.EXTENDED_PATH_NLRI_SUPPORT {
            while cursor.position() < length as u64 {
                let path_id = cursor.read_u32::<BigEndian>()?;
                let prefix = Prefix::parse(&mut cursor, AFI::IPV4)?;
                withdrawn_routes.push(NLRIEncoding::IP_WITH_PATH_ID((prefix, path_id)));
            }
        } else {
            while cursor.position() < length as u64 {
                withdrawn_routes.push(NLRIEncoding::IP(Prefix::parse(&mut cursor, AFI::IPV4)?));
            }
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
            let attribute = match PathAttribute::parse(&mut cursor, capabilities) {
                Ok(a) => a,
                Err(e) => match e.kind() {
                    ErrorKind::UnexpectedEof => return Err(e),
                    _ => continue,
                },
            };
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

        if length > match protocol {
            AFI::IPV4 => 32,
            AFI::IPV6 => 128,
        } {
            return Err(Error::new(ErrorKind::Other, format!("Bogus prefix length {}", length)));
        }

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
    safi: SAFI,
}

impl RouteRefresh {
    fn parse(stream: &mut Read) -> Result<RouteRefresh, Error> {
        let afi = AFI::from(stream.read_u16::<BigEndian>()?)?;
        let _ = stream.read_u8()?;
        let safi = SAFI::from(stream.read_u8()?)?;

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



impl Message {
    fn write_noheader(&self, write: &mut Write) -> Result<(), Error> {
        match self {
            Message::Open(open) => open.write(write),
            Message::Update(_update) => unimplemented!(),
            Message::Notification => unimplemented!(),
            Message::KeepAlive => Ok(()),
            Message::RouteRefresh(_refresh) => unimplemented!(),
        }
    }

    /// Writes self into the stream, including the appropriate header.
    pub fn write(&self, write: &mut Write) -> Result<(), Error> {
        let mut len = SizeCalcWriter(0);
        self.write_noheader(&mut len)?;
        if len.0 + 16 + 2 + 1 > std::u16::MAX as usize {
            return Err(Error::new(ErrorKind::Other, format!("Cannot encode message of length {}", len.0)));
        }
        let header = Header {
            marker: [0xff; 16],
            length: (len.0 + 16 + 2 + 1) as u16,
            record_type: match self {
                Message::Open(_) => 1,
                Message::Update(_) => 2,
                Message::Notification => 3,
                Message::KeepAlive => 4,
                Message::RouteRefresh(_) => 5,
            },
        };
        header.write(write)?;
        self.write_noheader(write)
    }
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
