use crate::Capabilities;

use byteorder::{BigEndian, ReadBytesExt};

use std::fmt::{Display, Formatter};
use std::io::{Cursor, Error, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::*;

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[allow(missing_docs)]
pub enum Identifier {
    ORIGIN = 1,
    AS_PATH = 2,
    NEXT_HOP = 3,
    MULTI_EXIT_DISC = 4,
    LOCAL_PREF = 5,
    ATOMIC_AGGREGATOR = 6,
    AGGREGATOR = 7,
    COMMUNITY = 8,
    ORIGINATOR_ID = 9,
    CLUSTER_LIST = 10,
    DPA = 11,
    ADVERTISER = 12,
    CLUSTER_ID = 13,
    MP_REACH_NLRI = 14,
    MP_UNREACH_NLRI = 15,
    EXTENDED_COMMUNITIES = 16,
    AS4_PATH = 17,
    AS4_AGGREGATOR = 18,
    SSA = 19,
    CONNECTOR = 20,
    AS_PATHLIMIT = 21,
    PMSI_TUNNEL = 22,
    TUNNEL_ENCAPSULATION = 23,
    TRAFFIC_ENGINEERING = 24,
    IPV6_SPECIFIC_EXTENDED_COMMUNITY = 25,
    AIGP = 26,
    PE_DISTINGUISHER_LABELS = 27,
    ENTROPY_LABEL_CAPABILITY = 28,
    BGP_LS = 29,
    LARGE_COMMUNITY = 32,
    BGPSEC_PATH = 33,
    BGP_PREFIX_SID = 34,
    ATTR_SET = 128,
}

/// Represents a path attribute that described meta data of a specific route.
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub enum PathAttribute {
    /// Indicates how an UPDATE message has been generated. Defined in [RFC4271](http://www.iana.org/go/rfc4271).
    ORIGIN(Origin),

    /// Represents the path through which an UPDATE message traveled. Defined in [RFC4271](http://www.iana.org/go/rfc4271).
    AS_PATH(ASPath),

    /// Indicates IP address that is to be used as a next hop. Defined in [RFC4271](http://www.iana.org/go/rfc4271).
    NEXT_HOP(IpAddr),

    /// Used to discriminate between multiple exit or entry points. Defined in [RFC4271](http://www.iana.org/go/rfc4271).
    MULTI_EXIT_DISC(u32),

    /// Represents the degree of preference for internal routes. Defined in [RFC4271](http://www.iana.org/go/rfc4271).
    LOCAL_PREF(u32),

    /// May be used when a route has been aggregated. Defined in [RFC4271](http://www.iana.org/go/rfc4271).
    ATOMIC_AGGREGATOR,

    /// May be used to add information on who aggregated this route. Defined in [RFC4271](http://www.iana.org/go/rfc4271).
    AGGREGATOR((u32, Ipv4Addr)),

    /// Enables users to add extra information. Defined in [RFC1997](http://www.iana.org/go/rfc1997).
    COMMUNITY(Vec<u32>),

    /// Defined in [RFC4456](http://www.iana.org/go/rfc4456).
    ORIGINATOR_ID(u32),

    /// Defined in [RFC4456](http://www.iana.org/go/rfc4456).
    /// Holds a list of CLUSTER_IDs.
    CLUSTER_LIST(Vec<u32>),

    /// Defined in [RFC6938](http://www.iana.org/go/rfc6938). **(deprecated)**
    /// Tuple represents the (ASN specifying the preference, DPA value).
    DPA((u16, u32)),

    /// Defined in [RFC6938](http://www.iana.org/go/rfc6938). **(deprecated)**
    ADVERTISER,

    /// Defined in [RFC6938](http://www.iana.org/go/rfc6938). **(deprecated)**
    CLUSTER_ID,

    /// Multi-protocol extensions. Defined in [RFC4760](http://www.iana.org/go/rfc4760).
    MP_REACH_NLRI(MPReachNLRI),

    /// Multi-protocol extensions. Defined in [RFC4760](http://www.iana.org/go/rfc4760).
    MP_UNREACH_NLRI(MPUnreachNLRI),

    /// Defined in [RFC4360](http://www.iana.org/go/rfc4360).
    EXTENDED_COMMUNITIES(Vec<u64>),

    /// AS_PATH using 32-bit ASN. Defined in [RFC6793](http://www.iana.org/go/rfc6793).
    AS4_PATH(ASPath),

    /// AGGREGATOR using 32-bit ASN. Defined in [RFC6793](http://www.iana.org/go/rfc6793).
    AS4_AGGREGATOR((u32, Ipv4Addr)),

    /// SAFI Specific Attribute  **(deprecated)**.
    SSA,

    /// Defined in [RFC6037](http://www.iana.org/go/rfc6037).  **(deprecated)**
    CONNECTOR(Ipv4Addr),

    /// Defined [here](http://www.iana.org/go/draft-ietf-idr-as-pathlimit).  **(deprecated)**
    AS_PATHLIMIT((u8, u32)),

    /// Defined in [RFC6514](http://www.iana.org/go/rfc6514).
    /// Specifies the (Flags, Tunnel Type + MPLS Label, Tunnel Identifier) fields.
    PMSI_TUNNEL((u8, u32, Vec<u8>)),

    /// Defined in [RFC5512](http://www.iana.org/go/rfc5512).
    /// Specifies the (Tunnel Type, Value) fields.
    TUNNEL_ENCAPSULATION((u16, Vec<u8>)),

    /// Defined in [RFC5543](http://www.iana.org/go/rfc5543).
    TRAFFIC_ENGINEERING,

    /// Defined in [RFC5701](http://www.iana.org/go/rfc5701).
    /// Specifies the (Transitive, Sub-type, Global Administrator, Local Administrator) fields.
    IPV6_SPECIFIC_EXTENDED_COMMUNITY((u8, u8, Ipv6Addr, u16)),

    /// Defined in [RFC7311](http://www.iana.org/go/rfc7311).
    /// Specifies the (Type, Value) fields.
    AIGP((u8, Vec<u8>)),

    /// Defined in [RFC6514](http://www.iana.org/go/rfc6514).
    PE_DISTINGUISHER_LABELS,

    /// Defined in [RFC6790](http://www.iana.org/go/rfc6790).
    ENTROPY_LABEL_CAPABILITY,

    /// Defined in [RFC7752](http://www.iana.org/go/rfc7752).  **(deprecated)**
    BGP_LS,

    /// Defined in [RFC8092](http://www.iana.org/go/rfc8092).
    LARGE_COMMUNITY(Vec<(u32, u32, u32)>),

    /// Defined in [RFC8205](http://www.iana.org/go/rfc8205).
    BGPSEC_PATH,

    /// Defined [here](http://www.iana.org/go/draft-ietf-idr-bgp-prefix-sid-27).
    BGP_PREFIX_SID,

    /// Defined in [RFC6368](http://www.iana.org/go/rfc6368).
    ATTR_SET((u32, Vec<PathAttribute>)),
}

struct ReadCountingStream<'a, R: Read> {
    stream: &'a mut R,
    remaining: usize,
}

impl<'a, R: Read> Read for ReadCountingStream<'a, R> {
    fn read(&mut self, buff: &mut [u8]) -> Result<usize, Error> {
        if buff.len() > self.remaining {
            return Err(Error::new(
                ErrorKind::Other,
                "Attribute decode tried to read more than its length",
            ));
        }
        let res = self.stream.read(buff)?;
        self.remaining -= res;
        Ok(res)
    }
}

impl PathAttribute {
    ///
    /// Reads a Path Attribute from an object that implements Read.
    ///
    /// # Panics
    /// This function does not panic.
    ///
    /// # Errors
    /// Any IO error will be returned while reading from the stream.
    /// Behavior is undefined when an ill-formatted stream is provided.
    ///
    /// # Safety
    /// This function does not make use of unsafe code.
    ///
    pub fn parse(
        stream: &mut impl Read,
        capabilities: &Capabilities,
    ) -> Result<PathAttribute, Error> {
        let flags = stream.read_u8()?;
        let code = stream.read_u8()?;

        // Check if the Extended Length bit is set.
        let length: u16 = if flags & (1 << 4) == 0 {
            u16::from(stream.read_u8()?)
        } else {
            stream.read_u16::<BigEndian>()?
        };

        let mut count_stream = ReadCountingStream {
            stream,
            remaining: length as usize,
        };

        let res =
            PathAttribute::parse_limited(&mut count_stream, capabilities, flags, code, length);

        // Some routes include bogus attributes, which we attempt to parse, but if they're supposed
        // to be longer than we parsed, just ignore the remaining bytes.
        if count_stream.remaining != 0 {
            let mut dummy_buff = vec![0; count_stream.remaining];
            stream.read_exact(&mut dummy_buff)?;
        }
        res
    }

    fn parse_limited(
        stream: &mut impl Read,
        capabilities: &Capabilities,
        _flags: u8,
        code: u8,
        length: u16,
    ) -> Result<PathAttribute, Error> {
        match code {
            1 => Ok(PathAttribute::ORIGIN(Origin::parse(stream)?)),
            2 => Ok(PathAttribute::AS_PATH(ASPath::parse(
                stream,
                length,
                capabilities,
            )?)),
            3 => {
                let ip: IpAddr = if length == 4 {
                    IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?))
                } else {
                    IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?))
                };

                Ok(PathAttribute::NEXT_HOP(ip))
            }
            4 => Ok(PathAttribute::MULTI_EXIT_DISC(
                stream.read_u32::<BigEndian>()?,
            )),
            5 => Ok(PathAttribute::LOCAL_PREF(stream.read_u32::<BigEndian>()?)),
            6 => Ok(PathAttribute::ATOMIC_AGGREGATOR),
            7 => {
                let asn = if length == 6 {
                    u32::from(stream.read_u16::<BigEndian>()?)
                } else {
                    stream.read_u32::<BigEndian>()?
                };

                let ip = Ipv4Addr::from(stream.read_u32::<BigEndian>()?);
                Ok(PathAttribute::AGGREGATOR((asn, ip)))
            }
            8 => {
                let mut communities = Vec::with_capacity(usize::from(length / 4));
                for _ in 0..(length / 4) {
                    communities.push(stream.read_u32::<BigEndian>()?)
                }

                Ok(PathAttribute::COMMUNITY(communities))
            }
            9 => Ok(PathAttribute::ORIGINATOR_ID(
                stream.read_u32::<BigEndian>()?,
            )),
            10 => {
                let mut ids = Vec::with_capacity(usize::from(length / 4));
                for _ in 0..(length / 4) {
                    ids.push(stream.read_u32::<BigEndian>()?)
                }

                Ok(PathAttribute::CLUSTER_LIST(ids))
            }
            11 => Ok(PathAttribute::DPA((
                stream.read_u16::<BigEndian>()?,
                stream.read_u32::<BigEndian>()?,
            ))),
            14 => Ok(PathAttribute::MP_REACH_NLRI(MPReachNLRI::parse(
                stream,
                length,
                capabilities,
            )?)),
            15 => Ok(PathAttribute::MP_UNREACH_NLRI(MPUnreachNLRI::parse(
                stream,
                length,
                capabilities,
            )?)),
            16 => {
                let mut communities = Vec::with_capacity(usize::from(length / 8));
                for _ in 0..(length / 8) {
                    communities.push(stream.read_u64::<BigEndian>()?)
                }

                Ok(PathAttribute::EXTENDED_COMMUNITIES(communities))
            }
            17 => Ok(PathAttribute::AS4_PATH(ASPath::parse(
                stream,
                length,
                capabilities,
            )?)),
            18 => {
                let asn = stream.read_u32::<BigEndian>()?;
                let ip = Ipv4Addr::from(stream.read_u32::<BigEndian>()?);
                Ok(PathAttribute::AS4_AGGREGATOR((asn, ip)))
            }
            20 => {
                let mut buf = vec![0u8; length as usize];
                stream.read_exact(&mut buf)?;

                let mut cur = Cursor::new(buf);
                let _ = cur.read_u16::<BigEndian>()?;
                // I have no idea what this is.. both Junos and IOS-XR send this but it's
                // not covered in the RFC at all
                let _ = cur.read_u64::<BigEndian>()?;
                let ip = Ipv4Addr::from(cur.read_u32::<BigEndian>()?);

                Ok(PathAttribute::CONNECTOR(ip))
            }
            21 => {
                let limit = stream.read_u8()?;
                let asn = stream.read_u32::<BigEndian>()?;

                Ok(PathAttribute::AS_PATHLIMIT((limit, asn)))
            }
            22 => {
                let flags = stream.read_u8()?;
                let label = stream.read_u32::<BigEndian>()?;
                let mut identifier = vec![0; usize::from(length - 4)];
                stream.read_exact(&mut identifier)?;

                Ok(PathAttribute::PMSI_TUNNEL((flags, label, identifier)))
            }
            23 => {
                let tunnel_type = stream.read_u16::<BigEndian>()?;
                let length = stream.read_u16::<BigEndian>()?;
                let mut value = vec![0; usize::from(length)];
                stream.read_exact(&mut value)?;

                Ok(PathAttribute::TUNNEL_ENCAPSULATION((tunnel_type, value)))
            }
            25 => {
                let transitive = stream.read_u8()?;
                let subtype = stream.read_u8()?;
                let global_admin = Ipv6Addr::from(stream.read_u128::<BigEndian>()?);
                let local_admin = stream.read_u16::<BigEndian>()?;

                Ok(PathAttribute::IPV6_SPECIFIC_EXTENDED_COMMUNITY((
                    transitive,
                    subtype,
                    global_admin,
                    local_admin,
                )))
            }
            26 => {
                let aigp_type = stream.read_u8()?;
                let length = stream.read_u16::<BigEndian>()?;
                if length < 3 {
                    Err(Error::new(
                        ErrorKind::Other,
                        format!("Bogus AIGP length: {} < 3", length),
                    ))
                } else {
                    let mut value = vec![0; usize::from(length - 3)];
                    stream.read_exact(&mut value)?;

                    Ok(PathAttribute::AIGP((aigp_type, value)))
                }
            }
            28 => {
                stream.read_exact(&mut vec![0u8; length as usize])?;

                Ok(PathAttribute::ENTROPY_LABEL_CAPABILITY)
            }
            32 => {
                let mut communities: Vec<(u32, u32, u32)> =
                    Vec::with_capacity(usize::from(length / 12));
                for _ in 0..(length / 12) {
                    let admin = stream.read_u32::<BigEndian>()?;
                    let part1 = stream.read_u32::<BigEndian>()?;
                    let part2 = stream.read_u32::<BigEndian>()?;
                    communities.push((admin, part1, part2))
                }

                Ok(PathAttribute::LARGE_COMMUNITY(communities))
            }
            128 => {
                let asn = stream.read_u32::<BigEndian>()?;

                let mut buffer = vec![0; length as usize - 4];
                stream.read_exact(&mut buffer)?;

                let mut cursor = Cursor::new(buffer);

                let mut attributes = Vec::with_capacity(5);
                while cursor.position() < (length - 4).into() {
                    let result = PathAttribute::parse(&mut cursor, capabilities);
                    match result {
                        Err(x) => println!("Error: {}", x),
                        Ok(x) => attributes.push(x),
                    }
                }

                Ok(PathAttribute::ATTR_SET((asn, attributes)))
            }
            x => {
                let mut buffer = vec![0; usize::from(length)];
                stream.read_exact(&mut buffer)?;

                Err(Error::new(
                    ErrorKind::Other,
                    format!("Unknown path attribute type found: {}", x),
                ))
            }
        }
    }

    /// Retrieve the identifier belonging to this PathAttribute
    pub fn id(&self) -> Identifier {
        match self {
            PathAttribute::ORIGIN(_) => Identifier::ORIGIN,
            PathAttribute::AS_PATH(_) => Identifier::AS_PATH,
            PathAttribute::NEXT_HOP(_) => Identifier::NEXT_HOP,
            PathAttribute::MULTI_EXIT_DISC(_) => Identifier::MULTI_EXIT_DISC,
            PathAttribute::LOCAL_PREF(_) => Identifier::LOCAL_PREF,
            PathAttribute::ATOMIC_AGGREGATOR => Identifier::ATOMIC_AGGREGATOR,
            PathAttribute::AGGREGATOR(_) => Identifier::AGGREGATOR,
            PathAttribute::COMMUNITY(_) => Identifier::COMMUNITY,
            PathAttribute::ORIGINATOR_ID(_) => Identifier::ORIGINATOR_ID,
            PathAttribute::CLUSTER_LIST(_) => Identifier::CLUSTER_LIST,
            PathAttribute::DPA(_) => Identifier::DPA,
            PathAttribute::ADVERTISER => Identifier::ADVERTISER,
            PathAttribute::CLUSTER_ID => Identifier::CLUSTER_ID,
            PathAttribute::MP_REACH_NLRI(_) => Identifier::MP_REACH_NLRI,
            PathAttribute::MP_UNREACH_NLRI(_) => Identifier::MP_UNREACH_NLRI,
            PathAttribute::EXTENDED_COMMUNITIES(_) => Identifier::EXTENDED_COMMUNITIES,
            PathAttribute::AS4_PATH(_) => Identifier::AS4_PATH,
            PathAttribute::AS4_AGGREGATOR(_) => Identifier::AS4_AGGREGATOR,
            PathAttribute::SSA => Identifier::SSA,
            PathAttribute::CONNECTOR(_) => Identifier::CONNECTOR,
            PathAttribute::AS_PATHLIMIT(_) => Identifier::AS_PATHLIMIT,
            PathAttribute::PMSI_TUNNEL(_) => Identifier::PMSI_TUNNEL,
            PathAttribute::TUNNEL_ENCAPSULATION(_) => Identifier::TUNNEL_ENCAPSULATION,
            PathAttribute::TRAFFIC_ENGINEERING => Identifier::TRAFFIC_ENGINEERING,
            PathAttribute::IPV6_SPECIFIC_EXTENDED_COMMUNITY(_) => {
                Identifier::IPV6_SPECIFIC_EXTENDED_COMMUNITY
            }
            PathAttribute::AIGP(_) => Identifier::AIGP,
            PathAttribute::PE_DISTINGUISHER_LABELS => Identifier::PE_DISTINGUISHER_LABELS,
            PathAttribute::ENTROPY_LABEL_CAPABILITY => Identifier::ENTROPY_LABEL_CAPABILITY,
            PathAttribute::BGP_LS => Identifier::BGP_LS,
            PathAttribute::LARGE_COMMUNITY(_) => Identifier::LARGE_COMMUNITY,
            PathAttribute::BGPSEC_PATH => Identifier::BGPSEC_PATH,
            PathAttribute::BGP_PREFIX_SID => Identifier::BGP_PREFIX_SID,
            PathAttribute::ATTR_SET(_) => Identifier::ATTR_SET,
        }
    }

    /// Encode path attribute to bytes
    pub fn encode(&self, buf: &mut impl Write) -> Result<(), Error> {
        use PathAttribute::*;
        let mut bytes = Vec::with_capacity(8);
        let (mut flags, identifier) = match self {
            ORIGIN(origin) => {
                let value: u8 = match origin {
                    Origin::IGP => 0,
                    Origin::EGP => 1,
                    Origin::INCOMPLETE => 2,
                };
                bytes.write_u8(value)?;
                (0x40, Identifier::ORIGIN)
            }
            AS_PATH(as_path) => {
                as_path.encode(&mut bytes)?;
                (0x40, Identifier::AS_PATH)
            }
            COMMUNITY(communities) => {
                for comm in communities {
                    bytes.write_u32::<BigEndian>(*comm)?;
                }
                (0xc0, Identifier::COMMUNITY)
            }
            NEXT_HOP(next_hop) => {
                match next_hop {
                    IpAddr::V4(addr) => bytes.write_all(&addr.octets())?,
                    IpAddr::V6(addr) => bytes.write_all(&addr.octets())?,
                }
                (0x40, Identifier::NEXT_HOP)
            }
            MULTI_EXIT_DISC(med) => {
                bytes.write_u32::<BigEndian>(*med)?;
                (0x80, Identifier::MULTI_EXIT_DISC)
            }
            LOCAL_PREF(pref) => {
                bytes.write_u32::<BigEndian>(*pref)?;
                (0x40, Identifier::LOCAL_PREF)
            }
            MP_REACH_NLRI(mp_reach) => {
                mp_reach.encode(&mut bytes)?;
                (0x80, Identifier::MP_REACH_NLRI)
            }
            MP_UNREACH_NLRI(mp_unreach) => {
                mp_unreach.encode(&mut bytes)?;
                (0x80, Identifier::MP_UNREACH_NLRI)
            }
            EXTENDED_COMMUNITIES(ext_communities) => {
                for comm in ext_communities {
                    bytes.write_u64::<BigEndian>(*comm)?;
                }
                (0xc0, Identifier::EXTENDED_COMMUNITIES)
            }
            CLUSTER_LIST(clusters) => {
                for cluster in clusters {
                    bytes.write_u32::<BigEndian>(*cluster)?;
                }
                (0x80, Identifier::CLUSTER_LIST)
            }
            ORIGINATOR_ID(origin_id) => {
                bytes.write_u32::<BigEndian>(*origin_id)?;
                (0x80, Identifier::ORIGINATOR_ID)
            }
            AS4_PATH(as_path) => {
                as_path.encode(&mut bytes)?;
                (0xc0, Identifier::AS4_PATH)
            }
            AGGREGATOR((asn, ip)) => {
                bytes.write_u16::<BigEndian>(*asn as u16)?;
                bytes.write_u32::<BigEndian>((*ip).into())?;
                (0xc0, Identifier::AGGREGATOR)
            }
            _ => {
                unimplemented!("{:?}", self);
            }
        };
        // Use extended length if the attribute bytes are greater than 255
        // Or if a PathAttribute has explicitly set the ext-length bit (0x10)
        let is_extended_length = bytes.len() > std::u8::MAX as usize || (flags & 0x10) == 0x10;
        if is_extended_length {
            flags |= 0x10; // Set extended length bit
        }
        buf.write_u8(flags)?;
        buf.write_u8(identifier as u8)?;
        if is_extended_length {
            buf.write_u16::<BigEndian>(bytes.len() as u16)?;
        } else {
            buf.write_u8(bytes.len() as u8)?;
        }
        buf.write_all(&bytes)
    }
}

/// Indicated how an announcement has been generated.
///
/// ```
/// use bgp_rs::Origin;
///
/// assert_eq!(&(Origin::IGP).to_string(), "IGP");
/// assert_eq!(&(Origin::EGP).to_string(), "EGP");
/// assert_eq!(&(Origin::INCOMPLETE).to_string(), "Incomplete");
/// ```
#[derive(Debug, Clone)]
pub enum Origin {
    /// Generated by an Interior Gateway Protocol
    IGP,

    /// Generated by an Exterior Gateway Protocol
    EGP,

    /// Unknown how this route has been generated.
    INCOMPLETE,
}

impl Origin {
    fn parse(stream: &mut impl Read) -> Result<Origin, Error> {
        match stream.read_u8()? {
            0 => Ok(Origin::IGP),
            1 => Ok(Origin::EGP),
            2 => Ok(Origin::INCOMPLETE),
            _ => Err(Error::new(ErrorKind::Other, "Unknown origin type found.")),
        }
    }
}

impl Display for Origin {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Origin::IGP => write!(f, "IGP"),
            Origin::EGP => write!(f, "EGP"),
            Origin::INCOMPLETE => write!(f, "Incomplete"),
        }
    }
}

/// Represents the path that an announcement has traveled.
#[derive(Debug, Clone)]
pub struct ASPath {
    /// A collection of segments that together form the path that a message has traveled.
    pub segments: Vec<Segment>,
}

impl ASPath {
    fn parse(stream: &mut impl Read, length: u16, _: &Capabilities) -> Result<ASPath, Error> {
        let segments = Segment::parse_unknown_segments(stream, length)?;
        Ok(ASPath { segments })
    }

    /// Retrieves the AS that originated the announcement.
    /// Returns None if it is originated by as an AS_SET.
    /// ```
    /// use bgp_rs::{ASPath, Segment};
    ///
    /// let aspath = ASPath { segments: vec![
    ///     Segment::AS_SEQUENCE(vec![100, 200]),
    ///     Segment::AS_SEQUENCE(vec![300, 400]),
    /// ]};
    /// assert_eq!(aspath.origin(), Some(400));
    ///
    /// let aspath = ASPath { segments: vec![
    ///     Segment::AS_SET(vec![100, 200]),
    ///     Segment::AS_SET(vec![300, 400]),
    /// ]};
    /// assert_eq!(aspath.origin(), None);
    /// ```
    pub fn origin(&self) -> Option<u32> {
        let segment = self.segments.last()?;
        if let Segment::AS_SEQUENCE(x) = segment {
            return Some(*x.last()?);
        }
        None
    }

    /// Does this AsPath contain 4-byte ASNs
    /// ```
    /// use bgp_rs::{ASPath, Segment};
    ///
    /// let aspath = ASPath { segments: vec![
    ///     Segment::AS_SEQUENCE(vec![100, 200]),
    /// ]};
    /// assert!(!aspath.has_4_byte_asns());
    ///
    /// let aspath = ASPath { segments: vec![
    ///     Segment::AS_SEQUENCE(vec![90123000, 200]),
    /// ]};
    /// assert!(aspath.has_4_byte_asns());
    /// ```
    pub fn has_4_byte_asns(&self) -> bool {
        self.segments.iter().any(|s| s.has_4_byte_asns())
    }

    /// Returns the AS_PATH as a singular sequence of ASN.
    /// Returns None if there are any AS_SET segments.
    /// ```
    /// use bgp_rs::{ASPath, Segment};
    ///
    /// let aspath = ASPath { segments: vec![
    ///     Segment::AS_SEQUENCE(vec![100, 200]),
    ///     Segment::AS_SEQUENCE(vec![300, 400]),
    /// ]};
    /// assert_eq!(aspath.sequence(), Some(vec![100, 200, 300, 400]));
    ///
    /// let aspath = ASPath { segments: vec![
    ///     Segment::AS_SET(vec![100, 200]),
    ///     Segment::AS_SET(vec![300, 400]),
    /// ]};
    /// assert_eq!(aspath.sequence(), None);
    /// ```
    pub fn sequence(&self) -> Option<Vec<u32>> {
        let mut sequence = Vec::with_capacity(8);
        for segment in &self.segments {
            match segment {
                Segment::AS_SEQUENCE(x) => sequence.extend(x),
                Segment::AS_SET(_) => return None,
            }
        }

        Some(sequence)
    }

    /// Encode AS Path to bytes
    pub fn encode(&self, buf: &mut impl Write) -> Result<(), Error> {
        for segment in &self.segments {
            let (path_type, seq) = match segment {
                Segment::AS_SET(set) => (1u8, set),
                Segment::AS_SEQUENCE(seq) => (2u8, seq),
            };
            buf.write_u8(path_type)?;
            buf.write_u8(seq.len() as u8)?;
            let is_4_byte_aspath = self.has_4_byte_asns();
            for asn in seq.iter() {
                if is_4_byte_aspath {
                    buf.write_u32::<BigEndian>(*asn)?;
                } else {
                    buf.write_u16::<BigEndian>(*asn as u16)?;
                }
            }
        }
        Ok(())
    }
}

/// Represents the segment type of an AS_PATH. Can be either AS_SEQUENCE or AS_SET.
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub enum Segment {
    /// Represents a sequence of ASN that an announcement traveled through.
    AS_SEQUENCE(Vec<u32>),

    /// Represents a set of ASN through which a BGP message traveled.
    AS_SET(Vec<u32>),
}

impl Segment {
    /// Are there any 4-byte ASNs in the Segment
    pub fn has_4_byte_asns(&self) -> bool {
        let asns = match &self {
            Segment::AS_SEQUENCE(asns) => asns,
            Segment::AS_SET(asns) => asns,
        };
        asns.iter().any(|a| a > &(std::u16::MAX as u32))
    }

    fn parse_unknown_segments(stream: &mut impl Read, length: u16) -> Result<Vec<Segment>, Error> {
        // Read in everything so we can touch the buffer multiple times in order to
        // work out what we have
        let mut buf = vec![0u8; length as usize];
        stream.read_exact(&mut buf)?;
        let size = buf.len();
        let mut cur = Cursor::new(buf);

        'as_len: for i in 1..=2u64 {
            cur.set_position(0);

            // Now attempt to work out whether the first segment is 2 byte or 4 byte
            let assumed_as_len = i * 2;
            let mut total_segments = 0u64;

            while cur.position() < size as u64 {
                let segment_type = cur.read_u8()?;
                let segment_len = cur.read_u8()?;

                // If the second segment type isn't valid, pretty sure this isn't 2 byte
                if (assumed_as_len == 2 && total_segments >= 1)
                    && (segment_type < 1 || segment_type > 2)
                {
                    continue 'as_len;
                }

                cur.set_position(cur.position() + (u64::from(segment_len) * assumed_as_len));
                total_segments += 1;
            }

            if cur.position() == u64::from(length) {
                cur.set_position(0);

                match i {
                    1 => {
                        return Segment::parse_u16_segments(&mut cur, length);
                    }
                    2 => {
                        return Segment::parse_u32_segments(&mut cur, length);
                    }
                    _ => {}
                };
            }
        }

        Err(Error::new(
            ErrorKind::Other,
            "Invalid AS_PATH length detected",
        ))
    }

    fn parse_u16_segments(stream: &mut impl Read, length: u16) -> Result<Vec<Segment>, Error> {
        let mut segments: Vec<Segment> = Vec::with_capacity(1);

        // While there are multiple AS_PATH segments, parse the segments.
        let mut size = length;
        while size != 0 {
            // The type of a segment, either AS_SET or AS_SEQUENCE.
            let segment_type = stream.read_u8()?;

            // The amount of ASN inside a segment.
            let segment_length = stream.read_u8()?;

            // Construct a Vec<u32> such that one interface be used when handling AS_PATHs.
            let mut elements: Vec<u32> = Vec::with_capacity(usize::from(segment_length));

            // Parse the ASN as 16-bit ASN.
            for _ in 0..segment_length {
                elements.push(u32::from(stream.read_u16::<BigEndian>()?));
            }

            match segment_type {
                1 => segments.push(Segment::AS_SET(elements)),
                2 => segments.push(Segment::AS_SEQUENCE(elements)),
                x => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Unknown AS_PATH (2 byte) segment type found: {}", x),
                    ));
                }
            }

            size -= 2 + (u16::from(segment_length) * 2);
        }

        Ok(segments)
    }

    fn parse_u32_segments(stream: &mut impl Read, length: u16) -> Result<Vec<Segment>, Error> {
        let mut segments: Vec<Segment> = Vec::with_capacity(1);

        // While there are multiple AS_PATH segments, parse the segments.
        let mut size: i32 = i32::from(length);

        while size != 0 {
            // The type of a segment, either AS_SET or AS_SEQUENCE.
            let segment_type = stream.read_u8()?;

            // The amount of ASN inside a segment.
            let segment_length = stream.read_u8()?;

            // Construct a Vec<u32> such that one interface be used when handling AS_PATHs.
            let mut elements: Vec<u32> = Vec::with_capacity(usize::from(segment_length));

            // Parse the ASN as 32-bit ASN.
            for _ in 0..segment_length {
                elements.push(stream.read_u32::<BigEndian>()?);
            }

            match segment_type {
                1 => segments.push(Segment::AS_SET(elements)),
                2 => segments.push(Segment::AS_SEQUENCE(elements)),
                x => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Unknown AS_PATH (4 byte) segment type found: {}", x),
                    ));
                }
            }

            size -= 2 + i32::from(u16::from(segment_length) * 4);
        }

        Ok(segments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maplit::hashset;

    // Macro to make building a new `Prefix` easier
    //
    // Supports:
    // ```
    // // Prefix
    // let prefix = Prefix { afi: AFI::IPV4, length: 24, octets: vec![192, 168, 0]};
    // assert_eq!(prefix, make_prefix!("192.168.0.0", 24));
    //
    // // IpAddr
    // let addr = std::net::IpAddr::V4(std::net::Ipv4Addr:new(10, 10, 10, 10));
    // assert_eq!(addr, make_prefix!("10.10.10.10"));
    // ```
    #[allow(unused_macros)]
    #[macro_use]
    macro_rules! make_prefix {
        ($prefix:tt, $mask_len:expr) => {{
            let _prefix: Prefix = ($prefix.parse().unwrap(), $mask_len).into();
            _prefix
        }};
        ($prefix:tt) => {{
            let _addr: std::net::IpAddr = $prefix.parse().unwrap();
            _addr
        }};
    }

    fn _attr_roundtrip(attr: &PathAttribute, capabilities: &Capabilities) {
        eprintln!("Testing {:?}", attr);
        let mut bytes = vec![];
        attr.encode(&mut bytes).unwrap();
        let mut buffer = std::io::Cursor::new(bytes);
        let result = PathAttribute::parse(&mut buffer, capabilities).unwrap();

        // Now compare bytes for both:
        let cursor_depth = buffer.position() as usize;
        // Cursor can add bytes, only take valid bytes
        let original_bytes = buffer.into_inner()[..cursor_depth].to_vec();
        let roundtrip_bytes = {
            let mut rb = vec![];
            result.encode(&mut rb).unwrap();
            rb
        };
        if original_bytes != roundtrip_bytes {
            eprintln!("Error roundtripping: {:?}", attr);
            assert_eq!(original_bytes, roundtrip_bytes);
        }
    }

    #[test]
    fn test_attr_roundtrips() {
        let attrs = vec![
            (PathAttribute::ORIGIN(Origin::IGP), None),
            (PathAttribute::ORIGIN(Origin::EGP), None),
            (PathAttribute::ORIGIN(Origin::INCOMPLETE), None),
            (
                PathAttribute::AS_PATH(ASPath {
                    segments: vec![Segment::AS_SEQUENCE(vec![100, 200])],
                }),
                None,
            ),
            (
                PathAttribute::AS_PATH(ASPath {
                    segments: vec![
                        Segment::AS_SET(vec![100, 200]),
                        Segment::AS_SET(vec![100, 200]),
                    ],
                }),
                None,
            ),
            (PathAttribute::NEXT_HOP(make_prefix!("1.1.1.1")), None),
            (PathAttribute::MULTI_EXIT_DISC(500), None),
            (PathAttribute::MULTI_EXIT_DISC(3200001010), None),
            (PathAttribute::LOCAL_PREF(100), None),
            (
                PathAttribute::AGGREGATOR((100, "1.1.1.1".parse().unwrap())),
                None,
            ),
            (PathAttribute::COMMUNITY(vec![100, 9000008]), None),
            (
                PathAttribute::MP_REACH_NLRI(MPReachNLRI {
                    afi: AFI::IPV4,
                    safi: SAFI::Unicast,
                    next_hop: vec![1, 1, 1, 1],
                    announced_routes: vec![
                        NLRIEncoding::IP(make_prefix!("10.10.10.0", 24)),
                        NLRIEncoding::IP(make_prefix!("20.20.20.0", 24)),
                    ],
                }),
                None,
            ),
            (
                PathAttribute::MP_REACH_NLRI(MPReachNLRI {
                    afi: AFI::IPV6,
                    safi: SAFI::Unicast,
                    next_hop: "3001::1"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                    announced_routes: vec![
                        NLRIEncoding::IP(make_prefix!("2620:10:20::", 64)),
                        NLRIEncoding::IP(make_prefix!("2620:10:20::", 64)),
                    ],
                }),
                None,
            ),
            (
                PathAttribute::MP_REACH_NLRI(MPReachNLRI {
                    afi: AFI::IPV6,
                    safi: SAFI::Unicast,
                    next_hop: "3001::1"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                    announced_routes: vec![
                        NLRIEncoding::IP_WITH_PATH_ID((make_prefix!("2620:10:20::", 64), 10)),
                        NLRIEncoding::IP_WITH_PATH_ID((make_prefix!("2620:10:20::", 64), 20)),
                    ],
                }),
                Some(Capabilities::from_parameters(vec![
                    OpenParameter::Capabilities(vec![OpenCapability::AddPath(hashset! {
                        (AFI::IPV4, SAFI::Unicast, AddPathDirection::SendReceivePaths)
                    })]),
                ])),
            ),
            (
                PathAttribute::MP_UNREACH_NLRI(MPUnreachNLRI {
                    afi: AFI::IPV4,
                    safi: SAFI::Unicast,
                    withdrawn_routes: vec![
                        NLRIEncoding::IP(make_prefix!("10.10.10.0", 24)),
                        NLRIEncoding::IP(make_prefix!("20.20.20.0", 24)),
                    ],
                }),
                None,
            ),
            (
                PathAttribute::MP_UNREACH_NLRI(MPUnreachNLRI {
                    afi: AFI::IPV6,
                    safi: SAFI::Unicast,
                    withdrawn_routes: vec![
                        NLRIEncoding::IP(make_prefix!("2620:10:20::", 64)),
                        NLRIEncoding::IP(make_prefix!("2620:10:20::", 64)),
                    ],
                }),
                None,
            ),
            (
                PathAttribute::EXTENDED_COMMUNITIES(vec![100, 9000008, 10e50 as u64]),
                None,
            ),
            (
                PathAttribute::AS4_PATH(ASPath {
                    segments: vec![Segment::AS_SEQUENCE(vec![100, 200])],
                }),
                None,
            ),
            (
                PathAttribute::AS4_PATH(ASPath {
                    segments: vec![
                        Segment::AS_SET(vec![100, 200]),
                        Segment::AS_SET(vec![100, 200]),
                    ],
                }),
                None,
            ),
            // Not yet implemented
            // (PathAttribute::AS_PATHLIMIT((6, 65000)), None),
            // (
            //     PathAttribute::IPV6_SPECIFIC_EXTENDED_COMMUNITY((
            //         1,
            //         1,
            //         "3001::10".parse().unwrap(),
            //         200,
            //     )),
            //     None,
            // ),
        ];

        for (attr, caps) in attrs {
            _attr_roundtrip(&attr, &caps.unwrap_or_default());
        }
    }

    #[test]
    fn test_unknown_attribute() {
        let attr_data: Vec<u8> = vec![0x80, 190 /* not valid */, 4, 0, 0, 0, 0];
        let mut buf = std::io::Cursor::new(attr_data);
        let res = PathAttribute::parse(&mut buf, &Capabilities::default());
        assert!(res.is_err());
    }

    #[test]
    fn test_read_counter_overflow() {
        let data: Vec<u8> = (0..10).collect();
        let length = data.len();
        let mut buf = std::io::Cursor::new(data);
        let mut counter = ReadCountingStream {
            stream: &mut buf,
            remaining: length,
        };
        let mut output = [0u8; 16];
        // output is longer, so read will overrun
        assert!(counter.read_exact(&mut output).is_err());
    }
}
