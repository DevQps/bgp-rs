/// Contains the implementation of all BGP path attributes.
pub mod attributes;
pub use crate::attributes::*;
/// Contains the implementation of BGP NLRI.
pub mod nlri;
pub use crate::nlri::*;
/// Contains the implementation of Flowspec attributes
pub mod flowspec;
pub use crate::flowspec::*;

use crate::*;

use std::io::{Cursor, Error, Read};
use std::net::IpAddr;

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

    /// Update message to bytes
    pub fn encode(&self, buf: &mut dyn Write) -> Result<(), Error> {
        // TODO: Handle Withdrawn routes
        buf.write_u16::<BigEndian>(0)?; // self.withdrawn_routes.len() as u16)

        // Path Attributes
        let mut attribute_buf: Vec<u8> = Vec::with_capacity(self.attributes.len() * 8);
        for attribute in &self.attributes {
            attribute.encode(&mut attribute_buf)?;
        }
        buf.write_u16::<BigEndian>(attribute_buf.len() as u16)?;
        buf.write_all(&attribute_buf)?;

        // NLRI
        let mut nlri_buf: Vec<u8> = Vec::with_capacity(self.announced_routes.len() * 8);
        for route in &self.announced_routes {
            route.encode(&mut nlri_buf)?;
        }
        buf.write_all(&nlri_buf)
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
#[derive(Debug, Clone, Eq, PartialEq)]
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

impl NLRIEncoding {
    /// Encode NLRI to bytes
    pub fn encode(&self, buf: &mut dyn Write) -> Result<(), Error> {
        match self {
            Self::IP(prefix) => {
                let num_octets = (prefix.length + 7) / 8;
                let octets = &prefix.prefix[..num_octets as usize];
                buf.write_u8(prefix.length)?;
                buf.write_all(octets)
            }
            Self::FLOWSPEC(filters) => {
                let mut bytes: Vec<u8> = Vec::with_capacity(16);
                for filter in filters {
                    filter.encode(&mut bytes)?;
                }
                buf.write_u8(bytes.len() as u8)?;
                buf.write_all(&bytes)
            }
            _ => unimplemented!(),
        }
    }
}

/// Represents a generic prefix. For example an IPv4 prefix or IPv6 prefix.
#[derive(Clone, Eq, PartialEq)]
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
            AFI::BGPLS => unimplemented!(),
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
                AFI::BGPLS => unimplemented!(),
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
