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

mod util;

use byteorder::{BigEndian, ReadBytesExt};

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::{Cursor, Error, ErrorKind, Read};
use std::net::IpAddr;

/// Represents an Address Family Idenfitier. Currently only IPv4 and IPv6 are supported.
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
    fn from(value: u16) -> Result<AFI, Error> {
        match value {
            1 => Ok(AFI::IPV4),
            2 => Ok(AFI::IPV6),
            25 => Ok(AFI::L2VPN),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!("Number {} does not represent a vaid address family", value),
            )),
        }
    }

    fn empty_buffer(&self) -> Vec<u8> {
        match self {
            AFI::IPV4 => vec![0u8; 4],
            AFI::IPV6 => vec![0u8; 16],
            _ => unimplemented!(),
        }
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
}

/// Represents a single BGP message.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct OpenParameter {
    /// The type of the parameter.
    pub param_type: u8,

    /// The length of the data that this parameter holds in bytes.
    pub param_length: u8,

    /// The value that is set for this parameter.
    pub value: Vec<u8>,
}

impl OpenParameter {
    fn parse(stream: &mut dyn Read) -> Result<(u8, OpenParameter), Error> {
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
        let mut nlri_length: usize = header.length as usize - 23;

        // ----------------------------
        // Read withdrawn routes.
        // ----------------------------
        let length = stream.read_u16::<BigEndian>()? as usize;
        let mut buffer = vec![0; length];
        stream.read_exact(&mut buffer)?;
        nlri_length -= length;

        let mut cursor = Cursor::new(buffer);
        let mut withdrawn_routes: Vec<NLRIEncoding> = Vec::with_capacity(0);

        while cursor.position() < length as u64 {
            if util::detect_add_path_prefix(&mut cursor, 32)? {
                let path_id = cursor.read_u32::<BigEndian>()?;
                let prefix = Prefix::parse(&mut cursor, AFI::IPV4)?;
                withdrawn_routes.push(NLRIEncoding::IP_WITH_PATH_ID((prefix, path_id)));
            } else {
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

    /// Flowspec - unimplemented! RFC5575
    FLOWSPEC,
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
pub struct Notification {}

/// Represents a BGP Route Refresh message.
#[derive(Clone, Debug)]
pub struct RouteRefresh {
    afi: AFI,
    safi: u8,
}

impl RouteRefresh {
    fn parse(stream: &mut dyn Read) -> Result<RouteRefresh, Error> {
        let afi = AFI::from(stream.read_u16::<BigEndian>()?)?;
        let _ = stream.read_u8()?;
        let safi = stream.read_u8()?;

        Ok(RouteRefresh { afi, safi })
    }
}

/// Contains the BGP session parameters that distinguish how BGP messages should be parsed.
#[allow(non_snake_case)]
#[derive(Clone, Debug, Default)]
pub struct Capabilities {
    /// 1 - Multiprotocol Extensions for BGP-4
    pub MP_BGP_SUPPORT: HashSet<(AFI, u8)>,
    /// 2 - Route Refresh Capability for BGP-4
    pub ROUTE_REFRESH_SUPPORT: bool,
    /// 3 - Outbound Route Filtering Capability
    pub OUTBOUND_ROUTE_FILTERING_SUPPORT: HashSet<(AFI, u8)>,
    /// 5 - Support for reading NLRI extended with a Path Identifier
    pub EXTENDED_NEXT_HOP_ENCODING: HashMap<(AFI, u8), AFI>,
    /// 7 - BGPsec
    pub BGPSEC_SUPPORT: bool,
    /// 8 - Multiple Labels
    pub MULTIPLE_LABELS_SUPPORT: HashMap<(AFI, u8), u8>,
    /// 64 - Graceful Restart
    pub GRACEFUL_RESTART_SUPPORT: HashSet<(AFI, u8)>,
    /// 65 - Support for 4-octet AS number capability.
    pub FOUR_OCTET_ASN_SUPPORT: bool,
    /// 69 - ADD_PATH
    pub ADD_PATH_SUPPORT: HashMap<(AFI, u8), u8>,
    /// 70 - Enhanced Route Refresh
    pub ENHANCED_ROUTE_REFRESH_SUPPORT: bool,
    /// 71 - Long-Lived Graceful Restart
    pub LONG_LIVED_GRACEFUL_RESTART: bool,
}

impl Capabilities {
    /// Work out the common set of capabilities on a peering session
    pub fn common(sent: &Open, recv: &Open) -> Result<Self, Error> {
        // parse both the sent and received OPEN message
        let peer_local = Capabilities::parse(sent)?;
        let peer_remote = Capabilities::parse(recv)?;

        // And (manually) build an intersection between the two
        let mut negotiated = Capabilities::default();

        negotiated.MP_BGP_SUPPORT = peer_local
            .MP_BGP_SUPPORT
            .intersection(&peer_remote.MP_BGP_SUPPORT)
            .copied()
            .collect();
        negotiated.ROUTE_REFRESH_SUPPORT =
            peer_local.ROUTE_REFRESH_SUPPORT & peer_remote.ROUTE_REFRESH_SUPPORT;
        negotiated.OUTBOUND_ROUTE_FILTERING_SUPPORT = peer_local
            .OUTBOUND_ROUTE_FILTERING_SUPPORT
            .intersection(&peer_remote.OUTBOUND_ROUTE_FILTERING_SUPPORT)
            .copied()
            .collect();

        // Attempt at a HashMap intersection. We can be a bit lax here because this isn't a real BGP implementation
        // so we can not care too much about the values for now.
        negotiated.EXTENDED_NEXT_HOP_ENCODING = peer_local
            .EXTENDED_NEXT_HOP_ENCODING
            .iter()
            // .filter(|((afi, safi), _)| peer_remote.EXTENDED_NEXT_HOP_ENCODING.contains_key(&(*afi, *safi)))
            .map(|((afi, safi), nexthop)| ((*afi, *safi), *nexthop))
            .collect();

        negotiated.BGPSEC_SUPPORT = peer_local.BGPSEC_SUPPORT & peer_remote.BGPSEC_SUPPORT;

        negotiated.MULTIPLE_LABELS_SUPPORT = peer_local
            .MULTIPLE_LABELS_SUPPORT
            .iter()
            .filter(|((afi, safi), _)| {
                peer_remote
                    .MULTIPLE_LABELS_SUPPORT
                    .contains_key(&(*afi, *safi))
            })
            .map(|((afi, safi), val)| ((*afi, *safi), *val))
            .collect();

        negotiated.GRACEFUL_RESTART_SUPPORT = peer_local
            .GRACEFUL_RESTART_SUPPORT
            .intersection(&peer_remote.GRACEFUL_RESTART_SUPPORT)
            .copied()
            .collect();
        negotiated.FOUR_OCTET_ASN_SUPPORT =
            peer_local.FOUR_OCTET_ASN_SUPPORT & peer_remote.FOUR_OCTET_ASN_SUPPORT;

        negotiated.ADD_PATH_SUPPORT = peer_local
            .ADD_PATH_SUPPORT
            .iter()
            .filter(|((afi, safi), _)| peer_remote.ADD_PATH_SUPPORT.contains_key(&(*afi, *safi)))
            .map(|((afi, safi), val)| ((*afi, *safi), *val))
            .collect();

        negotiated.ENHANCED_ROUTE_REFRESH_SUPPORT =
            peer_local.ENHANCED_ROUTE_REFRESH_SUPPORT & peer_remote.ENHANCED_ROUTE_REFRESH_SUPPORT;
        negotiated.LONG_LIVED_GRACEFUL_RESTART =
            peer_local.LONG_LIVED_GRACEFUL_RESTART & peer_remote.LONG_LIVED_GRACEFUL_RESTART;

        Ok(negotiated)
    }

    /// Parse a BGP OPEN message and extract the advertised Capabilities described in RFC5492
    pub fn parse(open: &Open) -> Result<Self, Error> {
        let mut capabilities = Capabilities::default();

        for param in &open.parameters {
            let mut cur = Cursor::new(&param.value);
            while cur.position() < param.param_length.into() {
                // Capability Code
                let code = cur.read_u8()?;
                let length = cur.read_u8()? as usize;

                match code {
                    // MP_BGP
                    1 => {
                        let afi = AFI::from(cur.read_u16::<BigEndian>()?)?;
                        let _ = cur.read_u8()?;
                        let safi = cur.read_u8()?;

                        capabilities.MP_BGP_SUPPORT.insert((afi, safi));
                    }
                    // ROUTE_REFRESH
                    2 => {
                        // Throw away the details, we treat this as a bool
                        cur.read_exact(&mut vec![0u8; length])?;

                        capabilities.ROUTE_REFRESH_SUPPORT = true;
                    }
                    // OUTBOUND_ROUTE_FILTERING
                    3 | 130 => {
                        let afi = AFI::from(cur.read_u16::<BigEndian>()?)?;
                        let _ = cur.read_u8()?;
                        let safi = cur.read_u8()?;

                        // Throw away the rest since we don't handle it
                        cur.read_exact(&mut vec![0u8; length - 4])?;

                        capabilities
                            .OUTBOUND_ROUTE_FILTERING_SUPPORT
                            .insert((afi, safi));
                    }
                    // EXTENDED_NEXT_HOP_ENCODING
                    5 => {
                        let mut buf = vec![0u8; length];
                        cur.read_exact(&mut buf)?;

                        // This capability is variable length, so we need another Cursor
                        let mut inner = Cursor::new(buf);
                        while inner.position() < length as u64 {
                            let afi = AFI::from(inner.read_u16::<BigEndian>()?)?;
                            let safi = inner.read_u16::<BigEndian>()? as u8;
                            let nexthop_afi = AFI::from(inner.read_u16::<BigEndian>()?)?;

                            capabilities
                                .EXTENDED_NEXT_HOP_ENCODING
                                .entry((afi, safi))
                                .or_insert(nexthop_afi);
                        }
                    }
                    // BGPSEC
                    7 => {
                        // Unimplemented, throw away data
                        cur.read_exact(&mut vec![0u8; length])?;

                        capabilities.BGPSEC_SUPPORT = true;
                    }
                    // MULTIPLE_LABELS
                    8 => {
                        let mut buf = vec![0u8; length];
                        cur.read_exact(&mut buf)?;

                        // This capability is variable length, so we need another Cursor
                        let mut inner = Cursor::new(buf);
                        while inner.position() < length as u64 {
                            let afi = AFI::from(inner.read_u16::<BigEndian>()?)?;
                            let safi = inner.read_u8()?;
                            let count = inner.read_u8()?;

                            capabilities
                                .MULTIPLE_LABELS_SUPPORT
                                .entry((afi, safi))
                                .or_insert(count);
                        }
                    }
                    // GRACEFUL_RESTART
                    64 => {
                        // Restart flags = Restart time aren't relevant to a BMP peer
                        cur.read_exact(&mut [0u8; 2])?;

                        // If the peer didn't advertise any AFI/SAFI config we can bail here
                        if length - 2 == 0 {
                            continue;
                        }

                        let mut buf = vec![0u8; length - 2];
                        cur.read_exact(&mut buf)?;

                        // This capability is variable length, so we need another Cursor
                        let mut inner = Cursor::new(buf);
                        while inner.position() < inner.get_ref().len() as u64 {
                            let afi = AFI::from(inner.read_u16::<BigEndian>()?)?;
                            let safi = inner.read_u8()?;

                            // Also not relevant for a BMP peer
                            let _ = inner.read_u8()?;

                            capabilities.GRACEFUL_RESTART_SUPPORT.insert((afi, safi));
                        }
                    }
                    // FOUR_OCTET ASN_SUPPORT
                    65 => {
                        // Throw away the details, we treat this as a bool
                        cur.read_exact(&mut vec![0u8; length])?;

                        capabilities.FOUR_OCTET_ASN_SUPPORT = true;
                    }
                    // ADD_PATH_SUPPORT
                    69 => {
                        let mut buf = vec![0u8; length];
                        cur.read_exact(&mut buf)?;

                        // This capability is variable length, so we need another Cursor
                        let mut inner = Cursor::new(buf);
                        while inner.position() < length as u64 {
                            let afi = AFI::from(inner.read_u16::<BigEndian>()?)?;
                            let safi = inner.read_u8()?;
                            let send_recv = inner.read_u8()?;

                            capabilities
                                .ADD_PATH_SUPPORT
                                .entry((afi, safi))
                                .or_insert(send_recv);
                        }
                    }
                    // ENHANCED_ROUTE_REFRESH_SUPPORT (128 = Cisco)
                    70 | 128 => {
                        assert!(length == 0); // just testing, RFC says its true!
                        capabilities.ENHANCED_ROUTE_REFRESH_SUPPORT = true;
                    }
                    // 73 => {
                    //     // FQDN_SUPPORT
                    // },
                    // LONG_LIVED_GRACEFUL_RESTART
                    71 => {
                        // Throw away extra data, this can be treated as a boolean and while likely never
                        // be used as it's just an extension to Graceful Restart, no extra NLRI information
                        // exists
                        capabilities.LONG_LIVED_GRACEFUL_RESTART = true;
                    }
                    131 => {
                        cur.read_exact(&mut [0u8; 1])?;
                    }
                    _ => {
                        // Read whatever
                        cur.read_exact(&mut vec![0u8; length])?;
                    }
                };
            }
        }

        Ok(capabilities)
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
