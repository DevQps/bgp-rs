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
pub use crate::attributes::*;

/// Contains the implementation of Flowspec attributes
pub mod flowspec;
pub use crate::flowspec::*;

mod util;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use std::io::{Cursor, Error, ErrorKind, Read, Write};
use std::net::IpAddr;

struct SizeCalcWriter(usize);
impl Write for SizeCalcWriter {
    fn write(&mut self, b: &[u8]) -> Result<usize, Error> {
        self.0 += b.len();
        Ok(b.len())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Represents an Address Family Identifier. Currently only IPv4 and IPv6 are supported.
/// Currently only IPv4, IPv6, and L2VPN are supported.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum AFI {
    /// Internet Protocol version 4 (32 bits)
    IPV4 = 1,
    /// Internet Protocol version 6 (128 bits)
    IPV6 = 2,
    /// L2VPN ()
    L2VPN = 25,
}

impl AFI {
    fn empty_buffer(&self) -> Vec<u8> {
        match self {
            AFI::IPV4 => vec![0u8; 4],
            AFI::IPV6 => vec![0u8; 16],
            _ => unimplemented!(),
        }
    }
}

impl TryFrom<u16> for AFI {
    type Error = Error;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(AFI::IPV4),
            2 => Ok(AFI::IPV6),
            25 => Ok(AFI::L2VPN),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!("Not a supported AFI: '{}'", v),
            )),
        }
    }
}

impl Display for AFI {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        use AFI::*;
        let s = match self {
            IPV4 => "IPv4",
            IPV6 => "IPv6",
            L2VPN => "L2VPN",
        };
        write!(f, "{}", s)
    }
}

/// Represents an Subsequent Address Family Identifier. Currently only Unicast and Multicast are
/// supported.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SAFI {
    /// Unicast Forwarding
    Unicast = 1,
    /// Multicast Forwarding
    Multicast = 2,
    /// MPLS Labels
    Mpls = 4,
    /// MPLS VPN
    MplsVpn = 128,
    /// Flowspec Unicast
    Flowspec = 133,
    /// Flowspec Unicast
    FlowspecVPN = 134,
}

impl TryFrom<u8> for SAFI {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(SAFI::Unicast),
            2 => Ok(SAFI::Multicast),
            4 => Ok(SAFI::Mpls),
            128 => Ok(SAFI::MplsVpn),
            133 => Ok(SAFI::Flowspec),
            134 => Ok(SAFI::FlowspecVPN),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Not a supported SAFI: '{}'", v),
            )),
        }
    }
}

impl Display for SAFI {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        use SAFI::*;
        let s = match self {
            Unicast => "Unicast",
            Multicast => "Multicast",
            Mpls => "MPLS",
            MplsVpn => "MPLS VPN",
            Flowspec => "Flowspec",
            FlowspecVPN => "Flowspec VPN",
        };
        write!(f, "{}", s)
    }
}

/// Represents the BGP header accompanying every BGP message.
#[derive(Clone, Debug)]
pub struct Header {
    /// Predefined marker, must be set to all ones.
    pub marker: [u8; 16],

    /// Indicates the total length of the message, including the header in bytes.
    pub length: u16,

    /// Indicates the type of message that follows the header.
    pub record_type: u8,
}

impl Header {
    /// parse
    pub fn parse(stream: &mut dyn Read) -> Result<Header, Error> {
        let mut marker = [0u8; 16];
        stream.read_exact(&mut marker)?;

        let length = stream.read_u16::<BigEndian>()?;
        let record_type = stream.read_u8()?;

        Ok(Header {
            marker,
            length,
            record_type,
        })
    }

    /// Writes self into the stream, including the length and record type.
    pub fn write(&self, write: &mut dyn Write) -> Result<(), Error> {
        write.write_all(&self.marker)?;
        write.write_u16::<BigEndian>(self.length)?;
        write.write_u8(self.record_type)
    }
}

/// Represents a single BGP message.
#[derive(Clone, Debug)]
pub enum Message {
    /// Represent a BGP OPEN message.
    Open(Open),

    /// Represent a BGP UPDATE message.
    Update(Update),

    /// Represent a BGP NOTIFICATION message.
    Notification(Notification),

    /// Represent a BGP KEEPALIVE message.
    KeepAlive,

    /// Represent a BGP ROUTE_REFRESH message.
    RouteRefresh(RouteRefresh),
}

/// Represents a BGP Open message.
#[derive(Clone, Debug)]
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
    /// parse
    pub fn parse(stream: &mut dyn Read) -> Result<Open, Error> {
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
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Open length does not match options length",
            ));
        }

        Ok(Open {
            version,
            peer_asn,
            hold_timer,
            identifier,
            parameters,
        })
    }

    /// Encode message to bytes
    pub fn write(&self, write: &mut dyn Write) -> Result<(), Error> {
        write.write_u8(self.version)?;
        write.write_u16::<BigEndian>(self.peer_asn)?;
        write.write_u16::<BigEndian>(self.hold_timer)?;
        write.write_u32::<BigEndian>(self.identifier)?;

        let mut len = SizeCalcWriter(0);
        for p in self.parameters.iter() {
            p.write(&mut len)?;
        }
        if len.0 > std::u8::MAX as usize {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Cannot encode parameters with length {}", len.0),
            ));
        }
        write.write_u8(len.0 as u8)?;

        for p in self.parameters.iter() {
            p.write(write)?;
        }
        Ok(())
    }
}

/// The direction which an ADD-PATH capabilty indicates a peer can provide additional paths.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum AddPathDirection {
    /// Indiates a peer can recieve additional paths.
    ReceivePaths = 1,

    /// Indiates a peer can send additional paths.
    SendPaths = 2,

    /// Indiates a peer can both send and receive additional paths.
    SendReceivePaths = 3,
}

impl TryFrom<u8> for AddPathDirection {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
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
#[derive(Clone, Debug)]
pub enum OpenCapability {
    /// 1 - Indicates the speaker is willing to exchange multiple protocols over this session.
    MultiProtocol((AFI, SAFI)),
    /// 2 - Indicates the speaker supports route refresh.
    RouteRefresh,
    /// 3 - Support for Outbound Route Filtering of specified AFI/SAFIs
    OutboundRouteFiltering(HashSet<(AFI, SAFI, u8, AddPathDirection)>),
    /// 65 - Indicates the speaker supports 4 byte ASNs and includes the ASN of the speaker.
    FourByteASN(u32),
    /// 69 - Indicates the speaker supports sending/receiving multiple paths for a given prefix.
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
    fn parse(stream: &mut dyn Read) -> Result<(u16, OpenCapability), Error> {
        let cap_code = stream.read_u8()?;
        let cap_length = stream.read_u8()?;

        Ok((
            2 + (cap_length as u16),
            match cap_code {
                // MP_BGP
                1 => {
                    if cap_length != 4 {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Multi-Protocol capability must be 4 bytes in length",
                        ));
                    }
                    let afi = AFI::try_from(stream.read_u16::<BigEndian>()?)?;
                    let _ = stream.read_u8()?;
                    let safi = SAFI::try_from(stream.read_u8()?)?;
                    OpenCapability::MultiProtocol((afi, safi))
                }
                // ROUTE_REFRESH
                2 => {
                    if cap_length != 0 {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Route-Refresh capability must be 0 bytes in length",
                        ));
                    }
                    OpenCapability::RouteRefresh
                }
                // OUTBOUND_ROUTE_FILTERING
                3 => {
                    if (cap_length - 5) % 2 != 0 {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Outbound Route Filtering capability has an invalid length",
                        ));
                    }
                    let afi = AFI::try_from(stream.read_u16::<BigEndian>()?)?;
                    let _ = stream.read_u8()?;
                    let safi = SAFI::try_from(stream.read_u8()?)?;
                    let count = stream.read_u8()?;
                    let mut types: HashSet<(AFI, SAFI, u8, AddPathDirection)> = HashSet::new();
                    for _ in 0..count {
                        types.insert((
                            afi,
                            safi,
                            stream.read_u8()?,
                            AddPathDirection::try_from(stream.read_u8()?)?,
                        ));
                    }
                    OpenCapability::OutboundRouteFiltering(types)
                }
                // 4_BYTE_ASN
                65 => {
                    if cap_length != 4 {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "4-byte ASN capability must be 4 bytes in length",
                        ));
                    }
                    OpenCapability::FourByteASN(stream.read_u32::<BigEndian>()?)
                }
                69 => {
                    if cap_length % 4 != 0 {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "ADD-PATH capability length must be divisble by 4",
                        ));
                    }
                    let mut add_paths = Vec::with_capacity(cap_length as usize / 4);
                    for _ in 0..(cap_length / 4) {
                        add_paths.push((
                            AFI::try_from(stream.read_u16::<BigEndian>()?)?,
                            SAFI::try_from(stream.read_u8()?)?,
                            AddPathDirection::try_from(stream.read_u8()?)?,
                        ));
                    }
                    OpenCapability::AddPath(add_paths)
                }
                _ => {
                    let mut value = vec![0; cap_length as usize];
                    stream.read_exact(&mut value)?;
                    OpenCapability::Unknown {
                        cap_code,
                        cap_length,
                        value,
                    }
                }
            },
        ))
    }

    fn write(&self, write: &mut dyn Write) -> Result<(), Error> {
        match self {
            OpenCapability::MultiProtocol((afi, safi)) => {
                write.write_u8(1)?;
                write.write_u8(4)?;
                write.write_u16::<BigEndian>(*afi as u16)?;
                write.write_u8(0)?;
                write.write_u8(*safi as u8)
            }
            OpenCapability::RouteRefresh => {
                write.write_u8(2)?;
                write.write_u8(0)
            }
            OpenCapability::OutboundRouteFiltering(orfs) => {
                let length = orfs.len();
                for (i, orf) in orfs.iter().enumerate() {
                    let (afi, safi, orf_type, orf_direction) = orf;
                    if i == 0 {
                        write.write_u16::<BigEndian>(*afi as u16)?;
                        write.write_u8(0)?; // Reserved
                        write.write_u8(*safi as u8)?;
                        write.write_u8(length as u8)?;
                    }
                    write.write_u8(*orf_type)?;
                    write.write_u8(*orf_direction as u8)?;
                }
                Ok(())
            }
            OpenCapability::FourByteASN(asn) => {
                write.write_u8(65)?;
                write.write_u8(4)?;
                write.write_u32::<BigEndian>(*asn)
            }
            OpenCapability::AddPath(add_paths) => {
                write.write_u8(69)?;
                if add_paths.len() * 4 > std::u8::MAX as usize {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Cannot encode ADD-PATH with too many AFIs {}",
                            add_paths.len()
                        ),
                    ));
                }
                write.write_u8(add_paths.len() as u8 * 4)?;
                for p in add_paths.iter() {
                    write.write_u16::<BigEndian>(p.0 as u16)?;
                    write.write_u8(p.1 as u8)?;
                    write.write_u8(p.2 as u8)?;
                }
                Ok(())
            }
            OpenCapability::Unknown {
                cap_code,
                cap_length,
                value,
            } => {
                write.write_u8(*cap_code)?;
                write.write_u8(*cap_length)?;
                write.write_all(&value)
            }
        }
    }
}

/// Represents a parameter in the optional parameter section of an Open message.
#[derive(Clone, Debug)]
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
    fn parse(stream: &mut dyn Read) -> Result<(u16, OpenParameter), Error> {
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
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "Capability length {} does not match parameter length {}",
                            bytes_read, param_length
                        ),
                    ));
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
            },
        ))
    }

    fn write(&self, write: &mut dyn Write) -> Result<(), Error> {
        match self {
            OpenParameter::Capabilities(caps) => {
                write.write_u8(2)?;

                let mut len = SizeCalcWriter(0);
                for c in caps.iter() {
                    c.write(&mut len)?;
                }
                if len.0 > std::u8::MAX as usize {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Cannot encode capabilities with length {}", len.0),
                    ));
                }
                write.write_u8(len.0 as u8)?;

                for c in caps.iter() {
                    c.write(write)?;
                }
                Ok(())
            }
            OpenParameter::Unknown {
                param_type,
                param_length,
                value,
            } => {
                write.write_u8(*param_type)?;
                write.write_u8(*param_length)?;
                write.write_all(&value)
            }
        }
    }
}

/// Contains the BGP session parameters that distinguish how BGP messages should be parsed.
#[allow(non_snake_case)]
#[derive(Clone, Debug, Default)]
pub struct Capabilities {
    /// Support for 4-octet AS number capability.
    /// 1 - Multiprotocol Extensions for BGP-4
    pub MP_BGP_SUPPORT: HashSet<(AFI, SAFI)>,
    /// 2 - Route Refresh Capability for BGP-4
    pub ROUTE_REFRESH_SUPPORT: bool,
    /// 3 - Outbound Route Filtering Capability
    pub OUTBOUND_ROUTE_FILTERING_SUPPORT: HashSet<(AFI, SAFI, u8, AddPathDirection)>,
    /// 5 - Support for reading NLRI extended with a Path Identifier
    pub EXTENDED_NEXT_HOP_ENCODING: HashMap<(AFI, SAFI), AFI>,
    /// 7 - BGPsec
    pub BGPSEC_SUPPORT: bool,
    /// 8 - Multiple Labels
    pub MULTIPLE_LABELS_SUPPORT: HashMap<(AFI, SAFI), u8>,
    /// 64 - Graceful Restart
    pub GRACEFUL_RESTART_SUPPORT: HashSet<(AFI, SAFI)>,
    /// 65 - Support for 4-octet AS number capability.
    pub FOUR_OCTET_ASN_SUPPORT: bool,
    /// 69 - ADD_PATH
    pub ADD_PATH_SUPPORT: HashMap<(AFI, SAFI), AddPathDirection>,
    /// Support for reading NLRI extended with a Path Identifier
    pub EXTENDED_PATH_NLRI_SUPPORT: bool,
    /// 70 - Enhanced Route Refresh
    pub ENHANCED_ROUTE_REFRESH_SUPPORT: bool,
    /// 71 - Long-Lived Graceful Restart
    pub LONG_LIVED_GRACEFUL_RESTART: bool,
}

impl Capabilities {
    /// Convert from a collection of Open Parameters
    pub fn from_parameters(parameters: Vec<OpenParameter>) -> Self {
        let mut capabilities = Capabilities::default();

        for parameter in parameters {
            match parameter {
                OpenParameter::Capabilities(caps) => {
                    for capability in caps {
                        match capability {
                            OpenCapability::MultiProtocol(family) => {
                                capabilities.MP_BGP_SUPPORT.insert(family);
                            }
                            OpenCapability::RouteRefresh => {
                                capabilities.ROUTE_REFRESH_SUPPORT = true;
                            }
                            OpenCapability::OutboundRouteFiltering(families) => {
                                capabilities.OUTBOUND_ROUTE_FILTERING_SUPPORT = families;
                            }
                            OpenCapability::FourByteASN(_) => {
                                capabilities.FOUR_OCTET_ASN_SUPPORT = true;
                            }
                            OpenCapability::AddPath(paths) => {
                                capabilities.EXTENDED_PATH_NLRI_SUPPORT = true;
                                for path in paths {
                                    capabilities
                                        .ADD_PATH_SUPPORT
                                        .insert((path.0, path.1), path.2);
                                }
                            }
                            _ => (),
                        }
                    }
                }
                _ => (),
            }
        }

        capabilities
    }

    /// Work out the common set of capabilities on a peering session
    pub fn common(&self, other: &Capabilities) -> Result<Self, Error> {
        // And (manually) build an intersection between the two
        let mut negotiated = Capabilities::default();

        negotiated.MP_BGP_SUPPORT = self
            .MP_BGP_SUPPORT
            .intersection(&other.MP_BGP_SUPPORT)
            .copied()
            .collect();
        negotiated.ROUTE_REFRESH_SUPPORT = self.ROUTE_REFRESH_SUPPORT & other.ROUTE_REFRESH_SUPPORT;
        negotiated.OUTBOUND_ROUTE_FILTERING_SUPPORT = self
            .OUTBOUND_ROUTE_FILTERING_SUPPORT
            .intersection(&other.OUTBOUND_ROUTE_FILTERING_SUPPORT)
            .copied()
            .collect();

        // Attempt at a HashMap intersection. We can be a bit lax here because this isn't a real BGP implementation
        // so we can not care too much about the values for now.
        negotiated.EXTENDED_NEXT_HOP_ENCODING = self
            .EXTENDED_NEXT_HOP_ENCODING
            .iter()
            // .filter(|((afi, safi), _)| other.EXTENDED_NEXT_HOP_ENCODING.contains_key(&(*afi, *safi)))
            .map(|((afi, safi), nexthop)| ((*afi, *safi), *nexthop))
            .collect();

        negotiated.BGPSEC_SUPPORT = self.BGPSEC_SUPPORT & other.BGPSEC_SUPPORT;

        negotiated.MULTIPLE_LABELS_SUPPORT = self
            .MULTIPLE_LABELS_SUPPORT
            .iter()
            .filter(|((afi, safi), _)| other.MULTIPLE_LABELS_SUPPORT.contains_key(&(*afi, *safi)))
            .map(|((afi, safi), val)| ((*afi, *safi), *val))
            .collect();

        negotiated.GRACEFUL_RESTART_SUPPORT = self
            .GRACEFUL_RESTART_SUPPORT
            .intersection(&other.GRACEFUL_RESTART_SUPPORT)
            .copied()
            .collect();
        negotiated.FOUR_OCTET_ASN_SUPPORT =
            self.FOUR_OCTET_ASN_SUPPORT & other.FOUR_OCTET_ASN_SUPPORT;

        negotiated.ADD_PATH_SUPPORT = self
            .ADD_PATH_SUPPORT
            .iter()
            .filter(|((afi, safi), _)| other.ADD_PATH_SUPPORT.contains_key(&(*afi, *safi)))
            .map(|((afi, safi), val)| ((*afi, *safi), *val))
            .collect();
        negotiated.EXTENDED_PATH_NLRI_SUPPORT = !negotiated.ADD_PATH_SUPPORT.is_empty();

        negotiated.ENHANCED_ROUTE_REFRESH_SUPPORT =
            self.ENHANCED_ROUTE_REFRESH_SUPPORT & other.ENHANCED_ROUTE_REFRESH_SUPPORT;
        negotiated.LONG_LIVED_GRACEFUL_RESTART =
            self.LONG_LIVED_GRACEFUL_RESTART & other.LONG_LIVED_GRACEFUL_RESTART;

        Ok(negotiated)
    }
}

/// Represents a BGP Update message.
#[derive(Clone, Debug)]
pub struct Update {
    /// A collection of routes that have been withdrawn.
    pub withdrawn_routes: Vec<NLRIEncoding>,

    /// A collection of attributes associated with the announced routes.
    pub attributes: Vec<PathAttribute>,

    /// A collection of routes that are announced by the peer.
    pub announced_routes: Vec<NLRIEncoding>,
}

impl Update {
    /// docs
    pub fn parse(
        header: &Header,
        stream: &mut dyn Read,
        capabilities: &Capabilities,
    ) -> Result<Update, Error> {
        if header.length < 23 {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Header had bogus length {} < 23", header.length),
            ));
        }
        let mut nlri_length: usize = header.length as usize - 23;

        // ----------------------------
        // Read withdrawn routes.
        // ----------------------------
        let withdraw_len = stream.read_u16::<BigEndian>()? as usize;
        if withdraw_len > nlri_length {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Got bogus withdraw length {} < msg len {}",
                    withdraw_len, nlri_length
                ),
            ));
        }
        let mut buffer = vec![0; withdraw_len];
        stream.read_exact(&mut buffer)?;
        nlri_length -= withdraw_len;

        let mut withdrawn_routes: Vec<NLRIEncoding> = Vec::with_capacity(0);
        let mut cursor = Cursor::new(buffer);

        if capabilities.EXTENDED_PATH_NLRI_SUPPORT {
            while cursor.position() < withdraw_len as u64 {
                let path_id = cursor.read_u32::<BigEndian>()?;
                let prefix = Prefix::parse(&mut cursor, AFI::IPV4)?;
                withdrawn_routes.push(NLRIEncoding::IP_WITH_PATH_ID((prefix, path_id)));
            }
        } else {
            while cursor.position() < withdraw_len as u64 {
                withdrawn_routes.push(NLRIEncoding::IP(Prefix::parse(&mut cursor, AFI::IPV4)?));
            }
        }

        // ----------------------------
        // Read path attributes
        // ----------------------------
        let length = stream.read_u16::<BigEndian>()? as usize;
        if length > nlri_length {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Got bogus attributes length {} < msg len {} - withdraw len {}",
                    length, nlri_length, withdraw_len
                ),
            ));
        }
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

        while cursor.position() < nlri_length as u64 {
            if util::detect_add_path_prefix(&mut cursor, 32)? {
                let path_id = cursor.read_u32::<BigEndian>()?;
                let prefix = Prefix::parse(&mut cursor, AFI::IPV4)?;
                announced_routes.push(NLRIEncoding::IP_WITH_PATH_ID((prefix, path_id)));
            } else {
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
        let identifier = match self.get(Identifier::MP_REACH_NLRI) {
            Some(PathAttribute::MP_REACH_NLRI(routes)) => Some(routes.announced_routes.clone()),
            _ => None,
        };
        if let Some(routes) = identifier {
            self.announced_routes.extend(routes)
        }

        // Move the MP_REACH_NLRI attribute in the NLRI.
        let identifier = match self.get(Identifier::MP_UNREACH_NLRI) {
            Some(PathAttribute::MP_UNREACH_NLRI(routes)) => Some(routes.withdrawn_routes.clone()),
            _ => None,
        };
        if let Some(routes) = identifier {
            self.withdrawn_routes.extend(routes)
        }
    }
}

/// Represents NLRIEncodings present in the NRLI section of an UPDATE message.
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub enum NLRIEncoding {
    /// Encodings that specify only an IP present, either IPv4 or IPv6
    IP(Prefix),

    /// Encodings that specify a Path Identifier as specified in RFC7911. (Prefix, Path ID)
    IP_WITH_PATH_ID((Prefix, u32)),

    /// Encodings with a labeled nexthop as specified in RFC8277. (Prefix, MPLS Label)
    IP_MPLS((Prefix, u32)),

    /// Encodings with a labeled nexthop as specified in RFC8277. (Prefix, MPLS Label, Path ID)
    IP_MPLS_WITH_PATH_ID((Prefix, u32, u32)),

    /// Encodings for VPNs with a labeled nexthop as specified in RFC8277. (Prefix, MPLS Label)
    IP_VPN_MPLS((u64, Prefix, u32)),

    /// Encodings that specify a VPLS endpoint as specified in RFC4761. (RD, VE ID, Label Block Offset, Label Block Size, Label Base)
    L2VPN((u64, u16, u16, u16, u32)),

    /// Flowspec Traffic Filter Specification - RFC5575
    FLOWSPEC(Vec<FlowspecFilter>),
}

/// Represents a generic prefix. For example an IPv4 prefix or IPv6 prefix.
#[derive(Clone)]
pub struct Prefix {
    /// IP version for prefix (v4|v6)
    pub protocol: AFI,
    /// Prefix Mask length in bits
    pub length: u8,
    /// Prefix Octets
    pub prefix: Vec<u8>,
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
            AFI::L2VPN => unimplemented!(),
        }
    }
}

impl From<&Prefix> for (IpAddr, u8) {
    fn from(prefix: &Prefix) -> (IpAddr, u8) {
        (IpAddr::from(prefix), prefix.length)
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
    fn new(protocol: AFI, length: u8, prefix: Vec<u8>) -> Self {
        Self {
            protocol,
            length,
            prefix,
        }
    }

    fn parse(stream: &mut dyn Read, protocol: AFI) -> Result<Prefix, Error> {
        let length = stream.read_u8()?;

        if length
            > match protocol {
                AFI::IPV4 => 32,
                AFI::IPV6 => 128,
                AFI::L2VPN => unimplemented!(),
            }
        {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Bogus prefix length {}", length),
            ));
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
#[derive(Clone, Debug)]
pub struct Notification {
    /// Major Error Code [RFC4271]
    pub major_err_code: u8,
    /// Minor Error Code [RFC4271]
    pub minor_err_code: u8,
    /// Notification message
    pub data: Vec<u8>,
}

impl Notification {
    fn parse(header: &Header, stream: &mut dyn Read) -> Result<Notification, Error> {
        let major_err_code = stream.read_u8()?;
        let minor_err_code = stream.read_u8()?;
        let remaining_length = header.length as usize - 21;
        let mut data = vec![0; remaining_length as usize];
        stream.read_exact(&mut data)?;

        Ok(Notification {
            major_err_code,
            minor_err_code,
            data,
        })
    }
}

/// Represents a BGP Route Refresh message.
#[derive(Clone, Debug)]
pub struct RouteRefresh {
    afi: AFI,
    safi: SAFI,
}

impl RouteRefresh {
    fn parse(stream: &mut dyn Read) -> Result<RouteRefresh, Error> {
        let afi = AFI::try_from(stream.read_u16::<BigEndian>()?)?;
        let _ = stream.read_u8()?;
        let safi = SAFI::try_from(stream.read_u8()?)?;

        Ok(RouteRefresh { afi, safi })
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
    fn write_noheader(&self, write: &mut dyn Write) -> Result<(), Error> {
        match self {
            Message::Open(open) => open.write(write),
            Message::Update(_update) => unimplemented!(),
            Message::Notification(_notification) => unimplemented!(),
            Message::KeepAlive => Ok(()),
            Message::RouteRefresh(_refresh) => unimplemented!(),
        }
    }

    /// Writes self into the stream, including the appropriate header.
    pub fn write(&self, write: &mut dyn Write) -> Result<(), Error> {
        let mut len = SizeCalcWriter(0);
        self.write_noheader(&mut len)?;
        if len.0 + 16 + 2 + 1 > std::u16::MAX as usize {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Cannot encode message of length {}", len.0),
            ));
        }
        let header = Header {
            marker: [0xff; 16],
            length: (len.0 + 16 + 2 + 1) as u16,
            record_type: match self {
                Message::Open(_) => 1,
                Message::Update(_) => 2,
                Message::Notification(_) => 3,
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
            3 => {
                let attribute =
                    Message::Notification(Notification::parse(&header, &mut self.stream)?);
                Ok((header, attribute))
            }
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
