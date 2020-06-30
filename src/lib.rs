#![deny(missing_docs)]

//! The `bgp-rs` crate provides functionality to parse BGP-formatted streams.
//!
//! # Examples
//!
//! ## Reading a MRT file containing BPG4MP messages
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::Cursor;
//! use std::io::Read;
//! use std::io::BufReader;
//! use libflate::gzip::Decoder;
//! use bgp_rs::{Identifier, PathAttribute};
//! use mrt_rs::Record;
//! use mrt_rs::bgp4mp::BGP4MP;
//!
//! // Download an update message.
//! let file = File::open("res/mrt/updates.20190101.0000.gz").unwrap();
//!
//! // Decode the GZIP stream.
//! let mut decoder = Decoder::new(BufReader::new(file)).unwrap();
//!
//! // Keep reading MRT (Header, Record) tuples till the end of the file has been reached.
//! while let Ok(Some((_, record))) = mrt_rs::read(&mut decoder) {
//!
//!     // Extract BGP4MP::MESSAGE_AS4 entries.
//!     if let Record::BGP4MP(BGP4MP::MESSAGE_AS4(x)) = record {
//!
//!         // Read each BGP (Header, Message)
//!         let cursor = Cursor::new(x.message);
//!         let mut reader = bgp_rs::Reader::new(cursor);
//!         let (_, message) = reader.read().unwrap();
//!
//!         // If this is an UPDATE message that contains announcements, extract its origin.
//!         if let bgp_rs::Message::Update(x) = message {
//!             if x.is_announcement() {
//!                 if let PathAttribute::AS_PATH(path) = x.get(Identifier::AS_PATH).unwrap()
//!                 {
//!                     // Test the path.origin() method.
//!                     let origin = path.origin();
//!
//!                     // Do other stuff ...
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! ## Reading a MRT file containing TABLE_DUMP_V2 messages
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::Cursor;
//! use std::io::Read;
//! use std::io::BufReader;
//! use libflate::gzip::Decoder;
//! use bgp_rs::{Identifier, PathAttribute, Capabilities};
//! use mrt_rs::records::tabledump::TABLE_DUMP_V2;
//! use mrt_rs::Record;
//! use mrt_rs::bgp4mp::BGP4MP;
//!
//! // Download an update message.
//! let file = File::open("res/mrt/bview.20100101.0759.gz").unwrap();
//!
//! // Decode the GZIP stream.
//! let mut decoder = Decoder::new(BufReader::new(file)).unwrap();
//!
//! // Keep reading MRT (Header, Record) tuples till the end of the file has been reached.
//! while let Ok(Some((_, record))) = mrt_rs::read(&mut decoder) {
//!
//!     // Extract TABLE_DUMP_V2::RIB_IPV4_UNICAST entries.
//!     if let Record::TABLE_DUMP_V2(TABLE_DUMP_V2::RIB_IPV4_UNICAST(x)) = record {
//!
//!         // Loop over each route for this particular prefix.
//!         for mut entry in x.entries {
//!             let length = entry.attributes.len() as u64;
//!             let mut cursor = Cursor::new(entry.attributes);
//!
//!             // Parse each PathAttribute in each route.
//!             while cursor.position() < length {
//!                 PathAttribute::parse(&mut cursor, &Default::default()).unwrap();
//!             }
//!         }
//!     }
//! }
//! ```
/// Contains the OPEN Message implementation
pub mod open;
pub use crate::open::*;
/// Contains the NOTIFICATION Message implementation
pub mod notification;
pub use crate::notification::*;
/// Contains the UPDATE Message implementation
pub mod update;
pub use crate::update::*;

mod util;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use std::io::{Error, ErrorKind, Read, Write};

// RFC 4271: 4.1
const BGP_MIN_MESSAGE_SIZE: usize = 19;
const BGP_MAX_MESSAGE_SIZE: usize = 4096;

/// Represents an Address Family Identifier. Currently only IPv4 and IPv6 are supported.
/// Currently only IPv4, IPv6, and L2VPN are supported.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum AFI {
    /// Internet Protocol version 4 (32 bits)
    IPV4 = 0x01,
    /// Internet Protocol version 6 (128 bits)
    IPV6 = 0x02,
    /// L2VPN
    L2VPN = 0x19,
    /// BGPLS
    BGPLS = 0x4004,
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

/// Convert u16 to AFI
/// ```
/// use std::convert::TryFrom;
/// use bgp_rs::AFI;
///
/// let val = 2u16;
/// let afi = AFI::try_from(val).unwrap();
/// assert_eq!(afi, AFI::IPV6);
///
/// let bad_afi = AFI::try_from(404);
/// assert!(bad_afi.is_err());
/// ```
impl TryFrom<u16> for AFI {
    type Error = Error;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(AFI::IPV4),
            0x02 => Ok(AFI::IPV6),
            0x19 => Ok(AFI::L2VPN),
            0x4004 => Ok(AFI::BGPLS),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!("Not a supported AFI: '{}'", v),
            )),
        }
    }
}

/// Display AFI in a human-friendly format
/// ```
/// use bgp_rs::AFI;
/// let afi = AFI::IPV6;
/// assert_eq!(&afi.to_string(), "IPv6");
/// ```
impl Display for AFI {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        use AFI::*;
        let s = match self {
            IPV4 => "IPv4",
            IPV6 => "IPv6",
            L2VPN => "L2VPN",
            BGPLS => "BGPLS",
        };
        write!(f, "{}", s)
    }
}

/// Represents an Subsequent Address Family Identifier. Currently only Unicast and Multicast are
/// supported.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SAFI {
    /// Unicast Forwarding [RFC4760]
    Unicast = 1,
    /// Multicast Forwarding [RFC4760]
    Multicast = 2,
    /// MPLS Labels [RFC3107]
    Mpls = 4,
    /// Multicast VPN
    MulticastVpn = 5,
    /// VPLS [draft-ietf-l2vpn-evpn]
    Vpls = 65,
    /// EVPN [draft-ietf-l2vpn-evpn]
    Evpn = 70,
    /// BGP LS [RFC7752]
    BgpLs = 71,
    /// BGP LS VPN [RFC7752]
    BgpLsVpn = 72,
    /// RTC [RFC4684]
    Rtc = 132,
    /// MPLS VPN [RFC4364]
    MplsVpn = 128,
    /// Flowspec Unicast
    Flowspec = 133,
    /// Flowspec Unicast
    FlowspecVPN = 134,
}

/// Convert u8 to SAFI
/// ```
/// use std::convert::TryFrom;
/// use bgp_rs::SAFI;
///
/// let val = 1u8;
/// let safi = SAFI::try_from(val).unwrap();
/// assert_eq!(safi, SAFI::Unicast);
///
/// let bad_safi = SAFI::try_from(250);
/// assert!(bad_safi.is_err());
/// ```
impl TryFrom<u8> for SAFI {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(SAFI::Unicast),
            2 => Ok(SAFI::Multicast),
            4 => Ok(SAFI::Mpls),
            5 => Ok(SAFI::MulticastVpn),
            65 => Ok(SAFI::Vpls),
            70 => Ok(SAFI::Evpn),
            71 => Ok(SAFI::BgpLs),
            72 => Ok(SAFI::BgpLsVpn),
            128 => Ok(SAFI::MplsVpn),
            132 => Ok(SAFI::Rtc),
            133 => Ok(SAFI::Flowspec),
            134 => Ok(SAFI::FlowspecVPN),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Not a supported SAFI: '{}'", v),
            )),
        }
    }
}

/// Display SAFI in a human-friendly format
/// ```
/// use bgp_rs::SAFI;
///
/// assert_eq!(&(SAFI::Unicast).to_string(), "Unicast");
/// assert_eq!(&(SAFI::Mpls).to_string(), "MPLS");
/// assert_eq!(&(SAFI::Vpls).to_string(), "VPLS");
/// assert_eq!(&(SAFI::Flowspec).to_string(), "Flowspec");
/// ```
impl Display for SAFI {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        use SAFI::*;
        let s = match self {
            Unicast => "Unicast",
            Multicast => "Multicast",
            Mpls => "MPLS",
            MulticastVpn => "Multicast VPN",
            Vpls => "VPLS",
            Evpn => "EVPN",
            BgpLs => "BGPLS",
            BgpLsVpn => "BGPLSVPN",
            Rtc => "RTC",
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
    pub fn parse(stream: &mut impl Read) -> Result<Header, Error> {
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
    pub fn encode(&self, buf: &mut impl Write) -> Result<(), Error> {
        buf.write_all(&self.marker)?;
        buf.write_u16::<BigEndian>(self.length)?;
        buf.write_u8(self.record_type)
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

impl Message {
    fn encode_noheader(&self, buf: &mut impl Write) -> Result<(), Error> {
        match self {
            Message::Open(open) => open.encode(buf),
            Message::Update(update) => update.encode(buf),
            Message::Notification(notification) => notification.encode(buf),
            Message::KeepAlive => Ok(()),
            Message::RouteRefresh(refresh) => refresh.encode(buf),
        }
    }

    /// Writes message into the stream, including the appropriate header.
    pub fn encode(&self, buf: &mut impl Write) -> Result<(), Error> {
        let mut message_buf: Vec<u8> = Vec::with_capacity(BGP_MIN_MESSAGE_SIZE); // Start with minimum size
        self.encode_noheader(&mut message_buf)?;
        let message_length = message_buf.len();
        if (message_length + BGP_MIN_MESSAGE_SIZE) > BGP_MAX_MESSAGE_SIZE {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Cannot encode message of length {}", message_length),
            ));
        }
        let header = Header {
            marker: [0xff; 16],
            length: (message_length + BGP_MIN_MESSAGE_SIZE) as u16,
            record_type: match self {
                Message::Open(_) => 1,
                Message::Update(_) => 2,
                Message::Notification(_) => 3,
                Message::KeepAlive => 4,
                Message::RouteRefresh(_) => 5,
            },
        };
        header.encode(buf)?;
        buf.write_all(&message_buf)
    }
}

/// Represents a BGP Route Refresh message.
#[derive(Clone, Debug)]
pub struct RouteRefresh {
    /// Address Family being requested
    pub afi: AFI,
    /// Subsequent Address Family being requested
    pub safi: SAFI,
    /// This can be a subtype or RESERVED=0 for older senders
    pub subtype: u8,
}

impl RouteRefresh {
    fn parse(stream: &mut impl Read) -> Result<RouteRefresh, Error> {
        let afi = AFI::try_from(stream.read_u16::<BigEndian>()?)?;
        let subtype = stream.read_u8()?;
        let safi = SAFI::try_from(stream.read_u8()?)?;

        Ok(RouteRefresh { afi, safi, subtype })
    }

    /// Encode RouteRefresh to bytes
    pub fn encode(&self, buf: &mut impl Write) -> Result<(), Error> {
        buf.write_u16::<BigEndian>(self.afi as u16)?;
        buf.write_u8(self.subtype)?;
        buf.write_u8(self.safi as u8)
    }
}

/// An abstract way of getting a reference to a Capabilities struct.
/// This is used in Reader to allow use of either an owned Capabilites or a reference to one.
pub trait CapabilitiesRef {
    /// Gets a reference to the Capabilities
    fn get_ref(&self) -> &Capabilities;
}
impl CapabilitiesRef for Capabilities {
    fn get_ref(&self) -> &Capabilities {
        self
    }
}
impl<'a> CapabilitiesRef for &'a Capabilities {
    fn get_ref(&self) -> &Capabilities {
        self
    }
}

/// The BGPReader can read BGP messages from a BGP-formatted stream.
pub struct Reader<T, C>
where
    T: Read,
    C: CapabilitiesRef,
{
    /// The stream from which BGP messages will be read.
    pub stream: T,

    /// Capability parameters that distinguish how BGP messages should be parsed.
    pub capabilities: C,
}

impl<T, C> Reader<T, C>
where
    T: Read,
    C: CapabilitiesRef,
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
                    self.capabilities.get_ref(),
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
}

impl<T> Reader<T, Capabilities>
where
    T: Read,
{
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
    pub fn new(stream: T) -> Self
    where
        T: Read,
    {
        Reader::<T, Capabilities> {
            stream,
            capabilities: Default::default(),
        }
    }
}
