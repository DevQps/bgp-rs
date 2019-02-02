use crate::{Prefix, AFI};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Error, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum Attribute {
    ORIGIN(Origin),
    AS_PATH(ASPath),
    NEXT_HOP(IpAddr),
    MULTI_EXIT_DISC(u32),
    LOCAL_PREF(u32),
    ATOMIC_AGGREGATOR,
    AGGREGATOR((u32, Ipv4Addr)),
    COMMUNITY(Vec<u32>),
    ORIGINATOR_ID(u32),
    CLUSTER_LIST,
    DPA,
    ADVERTISER,
    CLUSTER_ID,
    MP_REACH_NLRI(MPReachNLRI),
    MP_UNREACH_NLRI(MPUnreachNLRI),
    EXTENDED_COMMUNITIES(Vec<u64>),
    AS4_PATH,
    AS4_AGGREGATOR,
    SSA,
    CONNECTOR,
    AS_PATHLIMIT,
    PMSI_TUNNEL,
    TUNNEL_ENCAPSULATION,
    TRAFFIC_ENGINEERING,
    IPV6_SPECIFIC_EXTENDED_COMMUNITY,
    AIGP,
    PE_DISTINGUISHER_LABELS,
    BGP_LS,
    LARGE_COMMUNITY(Vec<(u32, u32, u32)>),
    BGPSEC_PATH,
    BGP_PREFIX_SID,
    ATTR_SET,
}

impl Attribute {
    pub fn parse(stream: &mut Read) -> Result<Attribute, Error> {
        let flags = stream.read_u8()?;
        let code = stream.read_u8()?;

        // Check if the Extended Length bit is set.
        let length: u16 = if flags & (1 << 4) == 0 {
            stream.read_u8()? as u16
        } else {
            stream.read_u16::<BigEndian>()?
        };

        match code {
            1 => Ok(Attribute::ORIGIN(Origin::parse(stream)?)),
            2 => Ok(Attribute::AS_PATH(ASPath::parse(stream, length)?)),
            3 => {
                let ip: IpAddr = if length == 4 {
                    IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?))
                } else {
                    IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?))
                };

                Ok(Attribute::NEXT_HOP(ip))
            }
            4 => Ok(Attribute::MULTI_EXIT_DISC(stream.read_u32::<BigEndian>()?)),
            5 => Ok(Attribute::LOCAL_PREF(stream.read_u32::<BigEndian>()?)),
            6 => Ok(Attribute::ATOMIC_AGGREGATOR),
            7 => {
                let asn = if length == 6 {
                    stream.read_u16::<BigEndian>()? as u32
                } else {
                    stream.read_u32::<BigEndian>()?
                };

                let ip = Ipv4Addr::from(stream.read_u32::<BigEndian>()?);
                Ok(Attribute::AGGREGATOR((asn, ip)))
            }
            8 => {
                let mut communities = Vec::with_capacity((length / 4) as usize);
                for _ in 0..(length / 4) {
                    communities.push(stream.read_u32::<BigEndian>()?)
                }

                Ok(Attribute::COMMUNITY(communities))
            }
            9 => Ok(Attribute::ORIGINATOR_ID(stream.read_u32::<BigEndian>()?)),
            14 => Ok(Attribute::MP_REACH_NLRI(MPReachNLRI::parse(
                stream, length,
            )?)),
            15 => Ok(Attribute::MP_UNREACH_NLRI(MPUnreachNLRI::parse(
                stream, length,
            )?)),
            16 => {
                let mut communities = Vec::with_capacity((length / 8) as usize);
                for _ in 0..(length / 8) {
                    communities.push(stream.read_u64::<BigEndian>()?)
                }

                Ok(Attribute::EXTENDED_COMMUNITIES(communities))
            }
            32 => {
                let mut communities: Vec<(u32, u32, u32)> =
                    Vec::with_capacity((length / 12) as usize);
                for _ in 0..(length / 12) {
                    let admin = stream.read_u32::<BigEndian>()?;
                    let part1 = stream.read_u32::<BigEndian>()?;
                    let part2 = stream.read_u32::<BigEndian>()?;
                    communities.push((admin, part1, part2))
                }

                Ok(Attribute::LARGE_COMMUNITY(communities))
            }
            x => {
                let mut buffer = vec![0; length as usize];
                stream.read_exact(&mut buffer);

                Err(Error::new(
                    ErrorKind::Other,
                    format!("Unknown path attribute type found: {}", x),
                ))
            }
        }
    }
}

#[derive(Debug)]
pub enum Origin {
    IGP,
    EGP,
    INCOMPLETE,
}

impl Origin {
    pub fn parse(stream: &mut Read) -> Result<Origin, Error> {
        match stream.read_u8()? {
            0 => Ok(Origin::IGP),
            1 => Ok(Origin::EGP),
            2 => Ok(Origin::INCOMPLETE),
            _ => Err(Error::new(ErrorKind::Other, "Unknown origin type found.")),
        }
    }
}

#[derive(Debug)]
pub struct ASPath {
    pub segments: Vec<Segment>,
}

impl ASPath {
    // TODO: Give argument that determines the AS size.
    pub fn parse(stream: &mut Read, length: u16) -> Result<ASPath, Error> {
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
            let mut values: Vec<u32> = Vec::with_capacity(length as usize);

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

            size -= 2 + (length as u16 * 4);
        }

        Ok(path)
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum Segment {
    AS_SEQUENCE(Vec<u32>),
    AS_SET(Vec<u32>),
}

#[derive(Debug)]
pub struct MPReachNLRI {
    pub afi: AFI,
    pub safi: u8,
    pub next_hop: Vec<u8>,
    pub announced_routes: Vec<Prefix>,
}

impl MPReachNLRI {
    // TODO: Give argument that determines the AS size.
    pub fn parse(stream: &mut Read, length: u16) -> Result<MPReachNLRI, Error> {
        let afi = AFI::from(stream.read_u16::<BigEndian>()?)?;
        let safi = stream.read_u8()?;

        let next_hop_length = stream.read_u8()?;
        let mut next_hop = vec![0; next_hop_length as usize];
        stream.read_exact(&mut next_hop)?;

        let _reserved = stream.read_u8()?;

        // ----------------------------
        // Read NLRI
        // ----------------------------
        let size = length - (5 + next_hop_length) as u16;

        let mut buffer = vec![0; size as usize];
        stream.read_exact(&mut buffer);
        let mut cursor = Cursor::new(buffer);
        let mut announced_routes: Vec<Prefix> = Vec::with_capacity(4);

        while cursor.position() < size as u64 {
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

#[derive(Debug)]
pub struct MPUnreachNLRI {
    pub afi: AFI,
    pub safi: u8,
    pub withdrawn_routes: Vec<Prefix>,
}

impl MPUnreachNLRI {
    // TODO: Give argument that determines the AS size.
    pub fn parse(stream: &mut Read, length: u16) -> Result<MPUnreachNLRI, Error> {
        let afi = AFI::from(stream.read_u16::<BigEndian>()?)?;
        let safi = stream.read_u8()?;

        // ----------------------------
        // Read NLRI
        // ----------------------------
        let size = length - 3 as u16;

        let mut buffer = vec![0; size as usize];
        stream.read_exact(&mut buffer);
        let mut cursor = Cursor::new(buffer);
        let mut withdrawn_routes: Vec<Prefix> = Vec::with_capacity(4);

        while cursor.position() < size as u64 {
            withdrawn_routes.push(Prefix::parse(&mut cursor)?);
        }

        Ok(MPUnreachNLRI {
            afi,
            safi,
            withdrawn_routes,
        })
    }
}
