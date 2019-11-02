//! The `open` mod provides structs and implementation for OPEN messages
//! - Open Attributes
//! - Optional Parameters
//!   - Parsing as Capabilities for comparison between two OPEN messages
//!

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::io::{Error, ErrorKind, Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::*;

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
    pub fn encode(&self, buf: &mut dyn Write) -> Result<(), Error> {
        buf.write_u8(self.version)?;
        buf.write_u16::<BigEndian>(self.peer_asn)?;
        buf.write_u16::<BigEndian>(self.hold_timer)?;
        buf.write_u32::<BigEndian>(self.identifier)?;

        let mut parameter_buf: Vec<u8> = Vec::with_capacity(4);
        for p in self.parameters.iter() {
            p.encode(&mut parameter_buf)?;
        }
        if parameter_buf.len() > std::u8::MAX as usize {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Cannot encode parameters with length {}",
                    parameter_buf.len()
                ),
            ));
        }
        buf.write_u8(parameter_buf.len() as u8)?;
        buf.write_all(&parameter_buf)
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

    fn encode(&self, buf: &mut dyn Write) -> Result<(), Error> {
        match self {
            OpenCapability::MultiProtocol((afi, safi)) => {
                buf.write_u8(1)?;
                buf.write_u8(4)?;
                buf.write_u16::<BigEndian>(*afi as u16)?;
                buf.write_u8(0)?;
                buf.write_u8(*safi as u8)
            }
            OpenCapability::RouteRefresh => {
                buf.write_u8(2)?;
                buf.write_u8(0)
            }
            OpenCapability::OutboundRouteFiltering(orfs) => {
                let length = orfs.len();
                for (i, orf) in orfs.iter().enumerate() {
                    let (afi, safi, orf_type, orf_direction) = orf;
                    if i == 0 {
                        buf.write_u16::<BigEndian>(*afi as u16)?;
                        buf.write_u8(0)?; // Reserved
                        buf.write_u8(*safi as u8)?;
                        buf.write_u8(length as u8)?;
                    }
                    buf.write_u8(*orf_type)?;
                    buf.write_u8(*orf_direction as u8)?;
                }
                Ok(())
            }
            OpenCapability::FourByteASN(asn) => {
                buf.write_u8(65)?;
                buf.write_u8(4)?;
                buf.write_u32::<BigEndian>(*asn)
            }
            OpenCapability::AddPath(add_paths) => {
                buf.write_u8(69)?;
                if add_paths.len() * 4 > std::u8::MAX as usize {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Cannot encode ADD-PATH with too many AFIs {}",
                            add_paths.len()
                        ),
                    ));
                }
                buf.write_u8(add_paths.len() as u8 * 4)?;
                for p in add_paths.iter() {
                    buf.write_u16::<BigEndian>(p.0 as u16)?;
                    buf.write_u8(p.1 as u8)?;
                    buf.write_u8(p.2 as u8)?;
                }
                Ok(())
            }
            OpenCapability::Unknown {
                cap_code,
                cap_length,
                value,
            } => {
                buf.write_u8(*cap_code)?;
                buf.write_u8(*cap_length)?;
                buf.write_all(&value)
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

    fn encode(&self, buf: &mut dyn Write) -> Result<(), Error> {
        match self {
            OpenParameter::Capabilities(caps) => {
                buf.write_u8(2)?;
                let mut cap_buf: Vec<u8> = Vec::with_capacity(20);
                for c in caps.iter() {
                    c.encode(&mut cap_buf)?;
                }
                if cap_buf.len() > std::u8::MAX as usize {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Cannot encode capabilities with length {}", cap_buf.len()),
                    ));
                }
                buf.write_u8(cap_buf.len() as u8)?;
                buf.write_all(&cap_buf)
            }
            OpenParameter::Unknown {
                param_type,
                param_length,
                value,
            } => {
                buf.write_u8(*param_type)?;
                buf.write_u8(*param_length)?;
                buf.write_all(&value)
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
            if let OpenParameter::Capabilities(caps) = parameter {
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
                        // Ignore unimplemented capabilities
                        _ => (),
                    }
                }
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
