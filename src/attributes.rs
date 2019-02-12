use crate::{Prefix, AFI};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Error, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Represents a path attribute that described meta data of a specific route.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum PathAttribute {
    /// Indicates how an UPDATE message has been generated. Defined in [RFC4271](http://www.iana.org/go/rfc4271).
    ORIGIN(Origin),

    /// Represents the path through which an UPDATE message travelled. Defined in [RFC4271](http://www.iana.org/go/rfc4271).
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
    CLUSTER_LIST,

    /// Defined in [RFC6938](http://www.iana.org/go/rfc6938).
    DPA,

    /// Defined in [RFC6938](http://www.iana.org/go/rfc6938).
    ADVERTISER,

    /// Defined in [RFC6938](http://www.iana.org/go/rfc6938).
    CLUSTER_ID,

    /// Multi-protocol extensions. Defined in [RFC4760](http://www.iana.org/go/rfc4760).
    MP_REACH_NLRI(MPReachNLRI),

    /// Multi-protocol extensions. Defined in [RFC4760](http://www.iana.org/go/rfc4760).
    MP_UNREACH_NLRI(MPUnreachNLRI),

    /// Defined in [RFC4360](http://www.iana.org/go/rfc4360).
    EXTENDED_COMMUNITIES(Vec<u64>),

    /// AS_PATH using 32-bit ASN. Defined in [RFC6793](http://www.iana.org/go/rfc6793).
    AS4_PATH,

    /// AGGREGATOR using 32-bit ASN. Defined in [RFC6793](http://www.iana.org/go/rfc6793).
    AS4_AGGREGATOR,

    /// SAFI Specific Attribute (Deprecated).
    SSA,

    /// Defined in [RFC6037](http://www.iana.org/go/rfc6037). (Deprecated)
    CONNECTOR(Ipv4Addr),

    /// Defined [here](http://www.iana.org/go/draft-ietf-idr-as-pathlimit). (Deprecated)
    AS_PATHLIMIT((u8, u32)),

    /// Defined in [RFC6514](http://www.iana.org/go/rfc6514).
    PMSI_TUNNEL,

    /// Defined in [RFC5512](http://www.iana.org/go/rfc5512).
    TUNNEL_ENCAPSULATION,

    /// Defined in [RFC5543](http://www.iana.org/go/rfc5543).
    TRAFFIC_ENGINEERING,

    /// Defined in [RFC5701](http://www.iana.org/go/rfc5701).
    IPV6_SPECIFIC_EXTENDED_COMMUNITY,

    /// Defined in [RFC7311](http://www.iana.org/go/rfc7311).
    AIGP,

    /// Defined in [RFC6514](http://www.iana.org/go/rfc6514).
    PE_DISTINGUISHER_LABELS,

    /// Defined in [RFC7752](http://www.iana.org/go/rfc7752).
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
    pub fn parse(stream: &mut Read) -> Result<PathAttribute, Error> {
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
            2 => Ok(PathAttribute::AS_PATH(ASPath::parse(stream, length)?)),
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
            14 => Ok(PathAttribute::MP_REACH_NLRI(MPReachNLRI::parse(
                stream, length,
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
            },
            20 => {
                stream.read_u16::<BigEndian>()?;
                let ip = Ipv4Addr::from(stream.read_u32::<BigEndian>()?);

                Ok(PathAttribute::CONNECTOR(ip))
            },
            21 => {
                let limit = stream.read_u8()?;
                let asn = stream.read_u32::<BigEndian>()?;

                Ok(PathAttribute::AS_PATHLIMIT((limit, asn)))
            },
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
            },
            128 => {
                let asn = stream.read_u32::<BigEndian>()?;

                let mut buffer = vec![0; length as usize - 4];
                stream.read_exact(&mut buffer)?;

                let mut cursor = Cursor::new(buffer);

                let mut attributes = Vec::with_capacity(5);
                while cursor.position() < (length - 4).into() {
                    let result = PathAttribute::parse(&mut cursor);
                    match result {
                        Err(x) => println!("Error: {}", x),
                        Ok(x) => attributes.push(x),
                    }
                }

                Ok(PathAttribute::ATTR_SET((asn, attributes)))
            },
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
}

/// Indicated how an announcement has been generated.
#[derive(Debug)]
pub enum Origin {
    /// Generated by an Interior Gateway Protocol
    IGP,

    /// Generated by an Exterior Gateway Protocol
    EGP,

    /// Unknown how this route has been generated.
    INCOMPLETE,
}

impl Origin {
    fn parse(stream: &mut Read) -> Result<Origin, Error> {
        match stream.read_u8()? {
            0 => Ok(Origin::IGP),
            1 => Ok(Origin::EGP),
            2 => Ok(Origin::INCOMPLETE),
            _ => Err(Error::new(ErrorKind::Other, "Unknown origin type found.")),
        }
    }
}

/// Represents the path that an announcement has travelled.
#[derive(Debug)]
pub struct ASPath {
    /// A collection of segments that together form the path that a message has travelled.
    pub segments: Vec<Segment>,
}

impl ASPath {
    // TODO: Give argument that determines the AS size.
    fn parse(stream: &mut Read, length: u16) -> Result<ASPath, Error> {
        // Create an AS_PATH struct with a capacity of 1, since AS_SETs
        // or multiple AS_SEQUENCES, are not seen often anymore.
        let mut path = ASPath {
            segments: Vec::with_capacity(1),
        };

        // While there are multiple AS_PATH segments, parse the segments.
        let mut size = length;
        while size != 0 {
            let segment_type = stream.read_u8()?;
            let length = stream.read_u8()?;
            let mut values: Vec<u32> = Vec::with_capacity(usize::from(length));

            for _ in 0..length {
                values.push(stream.read_u32::<BigEndian>()?);
            }

            match segment_type {
                1 => path.segments.push(Segment::AS_SEQUENCE(values)),
                2 => path.segments.push(Segment::AS_SET(values)),
                x => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Unknown AS_PATH segment type found: {}", x),
                    ));
                }
            }

            size -= 2 + (u16::from(length) * 4);
        }

        Ok(path)
    }
}

/// Represents the segment type of an AS_PATH. Can be either AS_SEQUENCE or AS_SET.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum Segment {
    /// Represents a sequence of ASN that an announcement travelled through.
    AS_SEQUENCE(Vec<u32>),

    /// Represents a set of ASN through which a BGP message travelled.
    AS_SET(Vec<u32>),
}

/// Used when announcing routes to non-IPv4 addresses.
#[derive(Debug)]
pub struct MPReachNLRI {
    /// The Address Family Identifier of the routes being announced.
    pub afi: AFI,

    /// The Subsequent Address Family Identifier of the routes being announced.
    pub safi: u8,

    /// The next hop of the announced routes.
    pub next_hop: Vec<u8>,

    /// The routes that are being announced.
    pub announced_routes: Vec<Prefix>,
}

impl MPReachNLRI {
    // TODO: Give argument that determines the AS size.
    fn parse(stream: &mut Read, length: u16) -> Result<MPReachNLRI, Error> {
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
        let mut announced_routes: Vec<Prefix> = Vec::with_capacity(4);

        while cursor.position() < u64::from(size) {
            announced_routes.push(Prefix::parse(&mut cursor)?);
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
#[derive(Debug)]
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
    fn parse(stream: &mut Read, length: u16) -> Result<MPUnreachNLRI, Error> {
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
            withdrawn_routes.push(Prefix::parse(&mut cursor)?);
        }

        Ok(MPUnreachNLRI {
            afi,
            safi,
            withdrawn_routes,
        })
    }
}
