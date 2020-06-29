use byteorder::{BigEndian, ReadBytesExt};

use std::convert::TryFrom;
use std::io::{self, Cursor, Error, ErrorKind, Read};

use crate::*;

/// Used when announcing routes to non-IPv4 addresses.
#[derive(Debug, Clone)]
pub struct MPReachNLRI {
    /// The Address Family Identifier of the routes being announced.
    pub afi: AFI,

    /// The Subsequent Address Family Identifier of the routes being announced.
    pub safi: SAFI,

    /// The next hop of the announced routes.
    pub next_hop: Vec<u8>,

    /// The routes that are being announced.
    pub announced_routes: Vec<NLRIEncoding>,
}

impl MPReachNLRI {
    /// Parse MPUnreachNLRI information
    pub(crate) fn parse(
        stream: &mut impl Read,
        length: u16,
        capabilities: &Capabilities,
    ) -> io::Result<MPReachNLRI> {
        let afi = AFI::try_from(stream.read_u16::<BigEndian>()?)?;
        let safi = SAFI::try_from(stream.read_u8()?)?;

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

        let announced_routes = match afi {
            AFI::IPV4 | AFI::IPV6 => parse_nlri(afi, safi, &capabilities, &mut cursor, size)?,
            AFI::L2VPN => parse_l2vpn(&mut cursor)?,
            AFI::BGPLS => unimplemented!(),
        };

        Ok(MPReachNLRI {
            afi,
            safi,
            next_hop,
            announced_routes,
        })
    }

    /// Encode Multiprotocol Reach NLRI to bytes
    pub fn encode(&self, mut buf: &mut impl Write) -> io::Result<()> {
        buf.write_u16::<BigEndian>(self.afi as u16)?;
        buf.write_u8(self.safi as u8)?;
        buf.write_u8(self.next_hop.len() as u8)?;
        buf.write_all(&self.next_hop)?;
        buf.write_u8(0u8)?; // Reserved
        for nlri in &self.announced_routes {
            nlri.encode(&mut buf)?;
        }
        Ok(())
    }
}

/// Used when withdrawing routes to non-IPv4 addresses.
#[derive(Debug, Clone)]
pub struct MPUnreachNLRI {
    /// The Address Family Identifier of the routes being withdrawn.
    pub afi: AFI,

    /// The Subsequent Address Family Identifier of the routes being withdrawn.
    pub safi: SAFI,

    /// The routes being withdrawn.
    pub withdrawn_routes: Vec<NLRIEncoding>,
}

impl MPUnreachNLRI {
    /// Parse MPUnreachNLRI information
    pub(crate) fn parse(
        stream: &mut impl Read,
        length: u16,
        capabilities: &Capabilities,
    ) -> io::Result<MPUnreachNLRI> {
        let afi = AFI::try_from(stream.read_u16::<BigEndian>()?)?;
        let safi = SAFI::try_from(stream.read_u8()?)?;

        // ----------------------------
        // Read NLRI
        // ----------------------------
        let size = length - 3;

        let mut buffer = vec![0; usize::from(size)];
        stream.read_exact(&mut buffer)?;
        let mut cursor = Cursor::new(buffer);
        let withdrawn_routes = parse_nlri(afi, safi, &capabilities, &mut cursor, size)?;

        Ok(MPUnreachNLRI {
            afi,
            safi,
            withdrawn_routes,
        })
    }

    /// Encode Multiprotocol Reach NLRI to bytes
    pub fn encode(&self, buf: &mut impl Write) -> io::Result<()> {
        buf.write_u16::<BigEndian>(self.afi as u16)?;
        buf.write_u8(self.safi as u8)?;
        for nlri in &self.withdrawn_routes {
            nlri.encode(buf)?;
        }
        Ok(())
    }
}

fn parse_l2vpn(buf: &mut impl Read) -> io::Result<Vec<NLRIEncoding>> {
    let _len = buf.read_u16::<BigEndian>()?;
    let rd = buf.read_u64::<BigEndian>()?;
    let ve_id = buf.read_u16::<BigEndian>()?;
    let label_block_offset = buf.read_u16::<BigEndian>()?;
    let label_block_size = buf.read_u16::<BigEndian>()?;
    let label_base = buf.read_u24::<BigEndian>()?;

    Ok(vec![NLRIEncoding::L2VPN((
        rd,
        ve_id,
        label_block_offset,
        label_block_size,
        label_base,
    ))])
}

// Parse AFI::IPV4/IPv6 NLRI, based on the MP SAFI
// Common across MPReach and MPUnreach
fn parse_nlri(
    afi: AFI,
    safi: SAFI,
    capabilities: &Capabilities,
    buf: &mut Cursor<Vec<u8>>,
    size: u16,
) -> io::Result<Vec<NLRIEncoding>> {
    let mut nlri: Vec<NLRIEncoding> = Vec::with_capacity(4);
    while buf.position() < u64::from(size) {
        match safi {
            // Labelled nexthop
            // TODO Add label parsing and support capabilities.MULTIPLE_LABELS
            SAFI::Mpls => {
                nlri.push(parse_mpls(afi, buf)?);
            }
            SAFI::MplsVpn => {
                nlri.push(parse_mplsvpn(afi, buf)?);
            }
            #[cfg(feature = "flowspec")]
            SAFI::Flowspec => {
                nlri.push(parse_flowspec(afi, buf)?);
            }
            #[cfg(feature = "flowspec")]
            SAFI::FlowspecVPN => {
                unimplemented!();
            }
            // DEFAULT
            _ => {
                if capabilities.EXTENDED_PATH_NLRI_SUPPORT {
                    while buf.position() < u64::from(size) {
                        let path_id = buf.read_u32::<BigEndian>()?;
                        let prefix = Prefix::parse(buf, afi)?;
                        nlri.push(NLRIEncoding::IP_WITH_PATH_ID((prefix, path_id)));
                    }
                } else {
                    while buf.position() < u64::from(size) {
                        let prefix = Prefix::parse(buf, afi)?;
                        nlri.push(NLRIEncoding::IP(prefix));
                    }
                }
            }
        };
    }
    Ok(nlri)
}

// Parse SAFI::Mpls into NLRIEncoding
fn parse_mpls(afi: AFI, buf: &mut Cursor<Vec<u8>>) -> io::Result<NLRIEncoding> {
    let path_id = if util::detect_add_path_prefix(buf, 255)? {
        Some(buf.read_u32::<BigEndian>()?)
    } else {
        None
    };
    let len_bits = buf.read_u8()?;
    // Protect against malformed messages
    if len_bits == 0 {
        return Err(Error::new(ErrorKind::Other, "Invalid prefix length 0"));
    }

    let len_bytes = (f32::from(len_bits) / 8.0).ceil() as u8;
    // discard label, resv and s-bit for now
    buf.read_exact(&mut [0u8; 3])?;
    let remaining = (len_bytes - 3) as usize;

    let mut pfx_buf = afi.empty_buffer();
    buf.read_exact(&mut pfx_buf[..remaining])?;

    // len_bits - MPLS info
    let pfx_len = len_bits - 24;

    let nlri = match path_id {
        Some(path_id) => {
            NLRIEncoding::IP_MPLS_WITH_PATH_ID((Prefix::new(afi, pfx_len, pfx_buf), 0, path_id))
        }
        None => NLRIEncoding::IP_MPLS((Prefix::new(afi, pfx_len, pfx_buf), 0)),
    };
    Ok(nlri)
}

// Parse SAFI::MplsVpn into NLRIEncoding
fn parse_mplsvpn(afi: AFI, buf: &mut Cursor<Vec<u8>>) -> io::Result<NLRIEncoding> {
    let len_bits = buf.read_u8()?;
    let len_bytes = (f32::from(len_bits) / 8.0).ceil() as u8;
    // discard label, resv and s-bit for now
    buf.read_exact(&mut [0u8; 3])?;
    let remaining = (len_bytes - 3) as usize;

    let rd = buf.read_u64::<BigEndian>()?;
    let mut pfx_buf = afi.empty_buffer();
    buf.read_exact(&mut pfx_buf[..(remaining - 8)])?;

    // len_bits - MPLS info - Route Distinguisher
    let pfx_len = len_bits - 24 - 64;
    let prefix = Prefix::new(afi, pfx_len, pfx_buf);

    Ok(NLRIEncoding::IP_VPN_MPLS((rd, prefix, 0u32)))
}

#[cfg(feature = "flowspec")]
// Parse SAFI::Flowspec into NLRIEncoding
fn parse_flowspec(afi: AFI, buf: &mut Cursor<Vec<u8>>) -> io::Result<NLRIEncoding> {
    let mut nlri_length = buf.read_u8()?;
    let mut filters: Vec<FlowspecFilter> = vec![];
    while nlri_length > 0 {
        let cur_position = buf.position();
        filters.push(FlowspecFilter::parse(buf, afi)?);
        nlri_length -= (buf.position() - cur_position) as u8;
    }
    Ok(NLRIEncoding::FLOWSPEC(filters))
}

#[test]
fn test_parse_nlri_ip_add_path() {
    let mut nlri_data = std::io::Cursor::new(vec![0, 0, 0, 10, 17, 10, 10, 128]);

    let capabilities = Capabilities {
        EXTENDED_PATH_NLRI_SUPPORT: true,
        ..Capabilities::default()
    };
    let result = parse_nlri(AFI::IPV4, SAFI::Unicast, &capabilities, &mut nlri_data, 8).unwrap();

    assert!(matches!(
        &result[0],
        NLRIEncoding::IP_WITH_PATH_ID((_prefix, _pathid))
    ));
}

#[test]
fn test_parse_nlri_mpls_add_path() {
    let mut nlri_data = std::io::Cursor::new(vec![0, 0, 0, 10, 41, 0, 0, 0, 10, 10, 128]);

    let capabilities = Capabilities {
        EXTENDED_PATH_NLRI_SUPPORT: true,
        ..Capabilities::default()
    };
    let result = parse_nlri(AFI::IPV4, SAFI::Mpls, &capabilities, &mut nlri_data, 11).unwrap();

    assert!(matches!(
        &result[0],
        NLRIEncoding::IP_MPLS_WITH_PATH_ID((_prefix, _label, _pathid))
    ));
}

#[test]
fn test_parse_nlri_mpls() {
    let mut nlri_data = std::io::Cursor::new(vec![41, 0, 0, 0, 10, 10, 128]);

    let capabilities = Capabilities {
        EXTENDED_PATH_NLRI_SUPPORT: true,
        ..Capabilities::default()
    };
    let result = parse_nlri(AFI::IPV4, SAFI::Mpls, &capabilities, &mut nlri_data, 7).unwrap();

    assert!(matches!(
        &result[0],
        NLRIEncoding::IP_MPLS((_prefix, _label))
    ));
}

#[test]
fn test_parse_l2vpn() {
    let mut nlri_data = std::io::Cursor::new(vec![
        19, 0, 0, 0, 0, 0, 0, 0, 100, 0, 10, 0, 10, 0, 10, 0, 0, 0, 0,
    ]);

    let result = parse_l2vpn(&mut nlri_data).unwrap();
    assert!(matches!(&result[0], NLRIEncoding::L2VPN(_)));
}

#[cfg(feature = "flowspec")]
#[test]
fn test_parse_nlri_flowspec() {
    // FlowspecFilter::Prefix redirect
    let mut nlri_data = std::io::Cursor::new(vec![
        0x26, 0x01, 0x80, 0x00, 0x30, 0x01, 0x00, 0x99, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x80, 0x00, 0x30, 0x01, 0x00, 0x99, 0x00, 0x0a, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ]);

    let capabilities = Capabilities::default();
    let result = parse_nlri(AFI::IPV6, SAFI::Flowspec, &capabilities, &mut nlri_data, 39).unwrap();

    assert!(matches!(&result[0], NLRIEncoding::FLOWSPEC(_filters)));
}
