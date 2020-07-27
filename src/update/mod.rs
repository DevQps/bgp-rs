/// Contains the implementation of all BGP path attributes.
pub mod attributes;
pub use crate::attributes::*;
/// Contains the implementation of BGP NLRI.
pub mod nlri;
pub use crate::nlri::*;
#[cfg(feature = "flowspec")]
/// Contains the implementation of Flowspec attributes
pub mod flowspec;
#[cfg(feature = "flowspec")]
pub use crate::flowspec::*;

use crate::*;

use std::collections::HashMap;
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
        stream: &mut impl Read,
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

        while cursor.position() < withdraw_len as u64 {
            if util::detect_add_path_prefix(&mut cursor, 255)? {
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
    pub fn encode(&self, buf: &mut impl Write) -> Result<(), Error> {
        // Create one buf to reuse for each Update attribute
        let mut temp_buf: Vec<u8> = Vec::with_capacity(8);

        let mut unreach_nlri: HashMap<(AFI, SAFI), Vec<NLRIEncoding>> = HashMap::new();
        for withdrawal in &self.withdrawn_routes {
            if withdrawal.is_ipv4() {
                withdrawal.encode(&mut temp_buf)?;
            } else {
                // Encode into MP_UNREACH_NLRI
                let nlris = unreach_nlri
                    .entry((withdrawal.afi(), withdrawal.safi()))
                    .or_insert_with(Vec::new);
                nlris.push(withdrawal.clone());
            }
        }
        buf.write_u16::<BigEndian>(temp_buf.len() as u16)?;
        buf.write_all(&temp_buf)?;
        temp_buf.clear();

        // Path Attributes
        for attribute in &self.attributes {
            attribute.encode(&mut temp_buf)?;
        }
        for ((afi, safi), unreach_nlris) in unreach_nlri.into_iter() {
            let pa = PathAttribute::MP_UNREACH_NLRI(MPUnreachNLRI {
                afi,
                safi,
                withdrawn_routes: unreach_nlris,
            });
            pa.encode(&mut temp_buf)?;
        }
        buf.write_u16::<BigEndian>(temp_buf.len() as u16)?;
        buf.write_all(&temp_buf)?;
        temp_buf.clear();

        // NLRI
        for route in &self.announced_routes {
            route.encode(&mut temp_buf)?;
        }
        buf.write_all(&temp_buf)
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
    #[cfg(feature = "flowspec")]
    FLOWSPEC(Vec<FlowspecFilter>),
}

impl NLRIEncoding {
    /// Check if this is a normal IPv4 NLRI for Update encoding
    pub fn is_ipv4(&self) -> bool {
        if let NLRIEncoding::IP(prefix) = &self {
            prefix.protocol == AFI::IPV4
        } else {
            false
        }
    }

    /// Derive the AFI for this NLRI
    pub fn afi(&self) -> AFI {
        use NLRIEncoding::*;
        match &self {
            IP(prefix) => prefix.protocol,
            #[cfg(feature = "flowspec")]
            FLOWSPEC(_) => AFI::IPV4, // TODO: match ipv6 from filters
            _ => unimplemented!(),
        }
    }

    /// Derive the SAFI for this NLRI
    pub fn safi(&self) -> SAFI {
        use NLRIEncoding::*;
        match &self {
            IP(_) => SAFI::Unicast,
            #[cfg(feature = "flowspec")]
            FLOWSPEC(_) => SAFI::Flowspec,
            _ => unimplemented!(),
        }
    }

    /// Encode NLRI to bytes
    pub fn encode(&self, buf: &mut impl Write) -> Result<(), Error> {
        match self {
            NLRIEncoding::IP(prefix) => {
                buf.write_u8(prefix.length)?;
                buf.write_all(&prefix.masked_octets())
            }
            NLRIEncoding::IP_WITH_PATH_ID((prefix, path_id)) => {
                buf.write_u32::<BigEndian>(*path_id)?;
                buf.write_u8(prefix.length)?;
                buf.write_all(&prefix.masked_octets())
            }
            NLRIEncoding::IP_VPN_MPLS((rd, prefix, label)) => {
                // TODO: the parsing in nlri.rs may not be correct
                buf.write_u32::<BigEndian>(*label)?;
                buf.write_u64::<BigEndian>(*rd)?;
                buf.write_all(&prefix.prefix)
            }
            #[cfg(feature = "flowspec")]
            NLRIEncoding::FLOWSPEC(filters) => {
                let mut bytes: Vec<u8> = Vec::with_capacity(16);
                for filter in filters {
                    filter.encode(&mut bytes)?;
                }
                buf.write_u8(bytes.len() as u8)?;
                buf.write_all(&bytes)
            }
            _ => unimplemented!("{:?}", self),
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
    /// Convert from IpAddr/CIDR to Prefix
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    /// use bgp_rs::Prefix;
    /// let prefix: Prefix = ("5.5.5.5".parse().unwrap(), 32).into();
    /// let (addr, length) = (&prefix).into();
    /// assert_eq!(addr, IpAddr::from(Ipv4Addr::new(5, 5, 5, 5)));
    /// assert_eq!(length, 32);
    /// ```
    fn from(prefix: &Prefix) -> (IpAddr, u8) {
        (IpAddr::from(prefix), prefix.length)
    }
}

impl From<(IpAddr, u8)> for Prefix {
    /// Convert from IpAddr/CIDR to Prefix
    /// ```
    /// use bgp_rs::Prefix;
    /// let prefix: Prefix = ("5.5.5.5".parse().unwrap(), 32).into();
    /// assert_eq!(prefix.length, 32);
    /// assert_eq!(prefix.prefix, vec![5, 5, 5, 5]);
    /// ```
    fn from(prefix: (IpAddr, u8)) -> Prefix {
        let (protocol, octets) = match prefix.0 {
            IpAddr::V4(v4) => (AFI::IPV4, v4.octets().to_vec()),
            IpAddr::V6(v6) => (AFI::IPV6, v6.octets().to_vec()),
        };
        Prefix {
            protocol,
            length: prefix.1,
            prefix: octets,
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

    fn octet_length(&self) -> usize {
        (self.length as usize + 7) / 8
    }

    /// Get a slice of the prefix octets covered by the prefix mask
    /// Useful for encoding the prefix in NLRI
    pub fn masked_octets(&self) -> &[u8] {
        &self.prefix[..self.octet_length()]
    }

    fn parse(stream: &mut impl Read, protocol: AFI) -> Result<Prefix, Error> {
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

#[test]
fn test_prefix_masked_octets() {
    let prefix = Prefix::new(AFI::IPV4, 32, vec![1, 1, 1, 1]);
    assert_eq!(prefix.masked_octets(), &[1, 1, 1, 1]);
    assert_eq!(&prefix.to_string(), "1.1.1.1/32");

    let prefix = Prefix::new(AFI::IPV4, 16, vec![1, 1, 1, 1]);
    assert_eq!(prefix.masked_octets(), &[1, 1]);
    assert_eq!(&prefix.to_string(), "1.1.1.1/16");

    let prefix = Prefix::new(AFI::IPV4, 18, vec![1, 1, 1, 1]);
    assert_eq!(prefix.masked_octets(), &[1, 1, 1]);
    assert_eq!(&prefix.to_string(), "1.1.1.1/18");
}

#[test]
fn test_prefix_bad_length() {
    let mut buf = std::io::Cursor::new(vec![35, 5, 5, 5, 5]);
    assert!(Prefix::parse(&mut buf, AFI::IPV4).is_err());
    let mut buf = std::io::Cursor::new(vec![145, 48, 1, 0, 16, 0, 16, 0]);
    assert!(Prefix::parse(&mut buf, AFI::IPV6).is_err());
}
