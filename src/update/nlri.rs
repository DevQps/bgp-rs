use byteorder::{BigEndian, ReadBytesExt};

use std::convert::TryFrom;
use std::io::{Cursor, Error, ErrorKind, Read};

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
        stream: &mut dyn Read,
        length: u16,
        capabilities: &Capabilities,
    ) -> Result<MPReachNLRI, Error> {
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
        let mut announced_routes: Vec<NLRIEncoding> = Vec::with_capacity(4);

        match afi {
            AFI::IPV4 | AFI::IPV6 => {
                while cursor.position() < u64::from(size) {
                    match safi {
                        // Labelled nexthop
                        // TODO Add label parsing and support capabilities.MULTIPLE_LABELS
                        SAFI::Mpls => {
                            let path_id = if util::detect_add_path_prefix(&mut cursor, 255)? {
                                Some(cursor.read_u32::<BigEndian>()?)
                            } else {
                                None
                            };
                            let len_bits = cursor.read_u8()?;
                            // Protect against malformed messages
                            if len_bits == 0 {
                                return Err(Error::new(
                                    ErrorKind::Other,
                                    "Invalid prefix length 0",
                                ));
                            }

                            let len_bytes = (f32::from(len_bits) / 8.0).ceil() as u8;
                            // discard label, resv and s-bit for now
                            cursor.read_exact(&mut [0u8; 3])?;
                            let remaining = (len_bytes - 3) as usize;

                            let mut pfx_buf = afi.empty_buffer();
                            cursor.read_exact(&mut pfx_buf[..remaining])?;

                            // len_bits - MPLS info
                            let pfx_len = len_bits - 24;
                            let prefix = Prefix::new(afi, pfx_len, pfx_buf);

                            match path_id {
                                Some(path_id) => announced_routes.push(
                                    NLRIEncoding::IP_MPLS_WITH_PATH_ID((prefix, 0u32, path_id)),
                                ),
                                None => {
                                    announced_routes.push(NLRIEncoding::IP_MPLS((prefix, 0u32)))
                                }
                            };
                        }
                        SAFI::MplsVpn => {
                            let len_bits = cursor.read_u8()?;
                            let len_bytes = (f32::from(len_bits) / 8.0).ceil() as u8;
                            // discard label, resv and s-bit for now
                            cursor.read_exact(&mut [0u8; 3])?;
                            let remaining = (len_bytes - 3) as usize;

                            let rd = cursor.read_u64::<BigEndian>()?;
                            let mut pfx_buf = afi.empty_buffer();
                            cursor.read_exact(&mut pfx_buf[..(remaining - 8)])?;

                            // len_bits - MPLS info - Route Distinguisher
                            let pfx_len = len_bits - 24 - 64;
                            let prefix = Prefix::new(afi, pfx_len, pfx_buf);

                            announced_routes.push(NLRIEncoding::IP_VPN_MPLS((rd, prefix, 0u32)));
                        }
                        SAFI::Flowspec => {
                            let mut nlri_length = cursor.read_u8()?;
                            let mut filters: Vec<FlowspecFilter> = vec![];
                            while nlri_length > 0 {
                                let cur_position = cursor.position();
                                filters.push(FlowspecFilter::parse(&mut cursor, afi)?);
                                nlri_length -= (cursor.position() - cur_position) as u8;
                            }
                            announced_routes.push(NLRIEncoding::FLOWSPEC(filters));
                        }
                        _ => {
                            if capabilities.EXTENDED_PATH_NLRI_SUPPORT {
                                while cursor.position() < u64::from(size) {
                                    let path_id = cursor.read_u32::<BigEndian>()?;
                                    let prefix = Prefix::parse(&mut cursor, afi)?;
                                    announced_routes
                                        .push(NLRIEncoding::IP_WITH_PATH_ID((prefix, path_id)));
                                }
                            } else {
                                while cursor.position() < u64::from(size) {
                                    let prefix = Prefix::parse(&mut cursor, afi)?;
                                    announced_routes.push(NLRIEncoding::IP(prefix));
                                }
                            }
                        }
                    };
                }
            }
            AFI::L2VPN => {
                let _len = cursor.read_u16::<BigEndian>()?;
                let rd = cursor.read_u64::<BigEndian>()?;
                let ve_id = cursor.read_u16::<BigEndian>()?;
                let label_block_offset = cursor.read_u16::<BigEndian>()?;
                let label_block_size = cursor.read_u16::<BigEndian>()?;
                let label_base = cursor.read_u24::<BigEndian>()?;

                announced_routes.push(NLRIEncoding::L2VPN((
                    rd,
                    ve_id,
                    label_block_offset,
                    label_block_size,
                    label_base,
                )));
            }
            AFI::BGPLS => unimplemented!(),
        };

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
    pub safi: SAFI,

    /// The routes being withdrawn.
    pub withdrawn_routes: Vec<NLRIEncoding>,
}

impl MPUnreachNLRI {
    /// Parse MPUnreachNLRI information
    pub(crate) fn parse(
        stream: &mut dyn Read,
        length: u16,
        capabilities: &Capabilities,
    ) -> Result<MPUnreachNLRI, Error> {
        let afi = AFI::try_from(stream.read_u16::<BigEndian>()?)?;
        let safi = SAFI::try_from(stream.read_u8()?)?;

        // ----------------------------
        // Read NLRI
        // ----------------------------
        let size = length - 3;

        let mut buffer = vec![0; usize::from(size)];
        stream.read_exact(&mut buffer)?;
        let mut cursor = Cursor::new(buffer);
        let mut withdrawn_routes: Vec<NLRIEncoding> = Vec::with_capacity(4);

        while cursor.position() < u64::from(size) {
            match safi {
                // Labelled nexthop
                // TODO Add label parsing and support capabilities.MULTIPLE_LABELS
                SAFI::Mpls => {
                    let path_id = if util::detect_add_path_prefix(&mut cursor, 255)? {
                        Some(cursor.read_u32::<BigEndian>()?)
                    } else {
                        None
                    };
                    let len_bits = cursor.read_u8()?;
                    // Protect against malformed messages
                    if len_bits == 0 {
                        return Err(Error::new(ErrorKind::Other, "Invalid prefix length 0"));
                    }

                    let len_bytes = (f32::from(len_bits) / 8.0).ceil() as u8;
                    // discard label, resv and s-bit for now
                    cursor.read_exact(&mut [0u8; 3])?;
                    let remaining = (len_bytes - 3) as usize;

                    let mut pfx_buf = afi.empty_buffer();
                    cursor.read_exact(&mut pfx_buf[..remaining])?;

                    // len_bits - MPLS info
                    let pfx_len = len_bits - 24;
                    match path_id {
                        Some(path_id) => withdrawn_routes.push(NLRIEncoding::IP_MPLS_WITH_PATH_ID(
                            (Prefix::new(afi, pfx_len, pfx_buf), 0, path_id),
                        )),
                        None => withdrawn_routes.push(NLRIEncoding::IP_MPLS((
                            Prefix::new(afi, pfx_len, pfx_buf),
                            0,
                        ))),
                    };
                }
                SAFI::MplsVpn => {
                    let len_bits = cursor.read_u8()?;
                    let len_bytes = (f32::from(len_bits) / 8.0).ceil() as u8;

                    // Upon reception, the value of the Compatibility field MUST be ignored.
                    cursor.read_exact(&mut [0u8; 3])?;

                    let remaining = (len_bytes - 3) as usize;

                    let rd = cursor.read_u64::<BigEndian>()?;
                    let mut pfx_buf = afi.empty_buffer();
                    cursor.read_exact(&mut pfx_buf[..(remaining - 8)])?;

                    // len_bits - MPLS info - Route Distinguisher
                    let pfx_len = len_bits - 24 - 64;
                    // withdrawn_routes.push(NLRIEncoding::IP(Prefix::new(afi, pfx_len, pfx_buf)));
                    withdrawn_routes.push(NLRIEncoding::IP_VPN_MPLS((
                        rd,
                        Prefix::new(afi, pfx_len, pfx_buf),
                        0u32,
                    )));
                }
                SAFI::Flowspec | SAFI::FlowspecVPN => {
                    unimplemented!();
                }
                // DEFAULT
                _ => {
                    if capabilities.EXTENDED_PATH_NLRI_SUPPORT {
                        while cursor.position() < u64::from(size) {
                            let path_id = cursor.read_u32::<BigEndian>()?;
                            let prefix = Prefix::parse(&mut cursor, afi)?;
                            withdrawn_routes.push(NLRIEncoding::IP_WITH_PATH_ID((prefix, path_id)));
                        }
                    } else {
                        while cursor.position() < u64::from(size) {
                            let prefix = Prefix::parse(&mut cursor, afi)?;
                            withdrawn_routes.push(NLRIEncoding::IP(prefix));
                        }
                    }
                }
            };
        }

        Ok(MPUnreachNLRI {
            afi,
            safi,
            withdrawn_routes,
        })
    }
}
