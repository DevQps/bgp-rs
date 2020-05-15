use crate::Capabilities;
use crate::NLRIEncoding;
use crate::{Prefix, AFI};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Error, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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
        stream: &mut dyn Read,
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
                stream, length,
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
                stream.read_u16::<BigEndian>()?;
                let ip = Ipv4Addr::from(stream.read_u32::<BigEndian>()?);

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
                let mut value = vec![0; usize::from(length - 3)];
                stream.read_exact(&mut value)?;

                Ok(PathAttribute::AIGP((aigp_type, value)))
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
            PathAttribute::BGP_LS => Identifier::BGP_LS,
            PathAttribute::LARGE_COMMUNITY(_) => Identifier::LARGE_COMMUNITY,
            PathAttribute::BGPSEC_PATH => Identifier::BGPSEC_PATH,
            PathAttribute::BGP_PREFIX_SID => Identifier::BGP_PREFIX_SID,
            PathAttribute::ATTR_SET(_) => Identifier::ATTR_SET,
        }
    }
}

/// Indicated how an announcement has been generated.
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
    fn parse(stream: &mut dyn Read) -> Result<Origin, Error> {
        match stream.read_u8()? {
            0 => Ok(Origin::IGP),
            1 => Ok(Origin::EGP),
            2 => Ok(Origin::INCOMPLETE),
            _ => Err(Error::new(ErrorKind::Other, "Unknown origin type found.")),
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
    fn parse(
        stream: &mut dyn Read,
        length: u16,
        capabilities: &Capabilities,
    ) -> Result<ASPath, Error> {
        let segments = if capabilities.FOUR_OCTET_ASN_SUPPORT {
            Segment::parse_u32_segments(stream, length)?
        } else {
            Segment::parse_u16_segments(stream, length)?
        };

        Ok(ASPath { segments })
    }

    /// Retrieves the AS that originated the announcement.
    /// Returns None if it is originated by as an AS_SET.
    pub fn origin(&self) -> Option<u32> {
        let segment = self.segments.last()?;
        if let Segment::AS_SEQUENCE(x) = segment {
            return Some(*x.last()?);
        }

        None
    }

    /// Returns the AS_PATH as a singular sequence of ASN.
    /// Returns None if there are any AS_SET segments.
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
    fn parse_u16_segments(stream: &mut dyn Read, length: u16) -> Result<Vec<Segment>, Error> {
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
                elements.push(stream.read_u16::<BigEndian>()? as u32);
            }

            match segment_type {
                1 => segments.push(Segment::AS_SET(elements)),
                2 => segments.push(Segment::AS_SEQUENCE(elements)),
                x => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Unknown AS_PATH segment type found: {}", x),
                    ));
                }
            }

            size -= 2 + (u16::from(segment_length) * 2);
        }

        Ok(segments)
    }

    fn parse_u32_segments(stream: &mut dyn Read, length: u16) -> Result<Vec<Segment>, Error> {
        let mut segments: Vec<Segment> = Vec::with_capacity(1);

        // While there are multiple AS_PATH segments, parse the segments.
        let mut size: i32 = length as i32;

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
                        format!("Unknown AS_PATH segment type found: {}", x),
                    ));
                }
            }

            size -= 2 + (u16::from(segment_length) * 4) as i32;
        }

        Ok(segments)
    }
}

/// Used when announcing routes to non-IPv4 addresses.
#[derive(Debug, Clone)]
pub struct MPReachNLRI {
    /// The Address Family Identifier of the routes being announced.
    pub afi: AFI,

    /// The Subsequent Address Family Identifier of the routes being announced.
    pub safi: u8,

    /// The next hop of the announced routes.
    pub next_hop: Vec<u8>,

    /// The routes that are being announced.
    pub announced_routes: Vec<NLRIEncoding>,
}

impl MPReachNLRI {
    // TODO: Give argument that determines the AS size.
    fn parse(
        stream: &mut dyn Read,
        length: u16,
        capabilities: &Capabilities,
    ) -> Result<MPReachNLRI, Error> {
        let afi = AFI::from(stream.read_u16::<BigEndian>()?)?;
        let safi = stream.read_u8()?;

        let next_hop_length = stream.read_u8()?;
        let mut next_hop = vec![0; usize::from(next_hop_length)];
        stream.read_exact(&mut next_hop)?;

        let _reserved = stream.read_u8()?;

        // ----------------------------
        // Read NLRI
        // ----------------------------
        let size = length - u16::from(5 + next_hop_length);

        let mut buffer = vec![0; usize::from(size)];
        stream.read_exact(&mut buffer)?;
        let mut cursor = Cursor::new(buffer);
        let mut announced_routes: Vec<NLRIEncoding> = Vec::with_capacity(4);

        if capabilities.EXTENDED_PATH_NLRI_SUPPORT {
            while cursor.position() < u64::from(size) {
                let path_id = stream.read_u32::<BigEndian>()?;
                let prefix = Prefix::parse(&mut cursor, afi)?;
                announced_routes.push(NLRIEncoding::IP_WITH_PATH_ID((prefix, path_id)));
            }
        } else {
            while cursor.position() < u64::from(size) {
                let prefix = Prefix::parse(&mut cursor, afi)?;
                announced_routes.push(NLRIEncoding::IP(prefix));
            }
        }

        Ok(MPReachNLRI {
            afi,
            safi,
            next_hop,
            announced_routes,
        })
    }
}

/// Used when withdrawing routes to non-IPv4 addresses.
#[derive(Debug, Clone)]
pub struct MPUnreachNLRI {
    /// The Address Family Identifier of the routes being withdrawn.
    pub afi: AFI,

    /// The Subsequent Address Family Identifier of the routes being withdrawn.
    pub safi: u8,

    /// The routes being withdrawn.
    pub withdrawn_routes: Vec<Prefix>,
}

impl MPUnreachNLRI {
    // TODO: Handle different ASN sizes.
    fn parse(stream: &mut dyn Read, length: u16) -> Result<MPUnreachNLRI, Error> {
        let afi = AFI::from(stream.read_u16::<BigEndian>()?)?;
        let safi = stream.read_u8()?;

        // ----------------------------
        // Read NLRI
        // ----------------------------
        let size = length - 3;

        let mut buffer = vec![0; usize::from(size)];
        stream.read_exact(&mut buffer)?;
        let mut cursor = Cursor::new(buffer);
        let mut withdrawn_routes: Vec<Prefix> = Vec::with_capacity(4);

        while cursor.position() < u64::from(size) {
            withdrawn_routes.push(Prefix::parse(&mut cursor, afi)?);
        }

        Ok(MPUnreachNLRI {
            afi,
            safi,
            withdrawn_routes,
        })
    }
}
