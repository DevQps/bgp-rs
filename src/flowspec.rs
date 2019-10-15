use crate::{Prefix, AFI};

use bitflags::bitflags;
use byteorder::{BigEndian, ReadBytesExt};

use std::io::{Error, ErrorKind, Read};

/// Check if the EOL bit is set,
/// signaling the last filter in the list
fn is_end_of_list(b: u8) -> bool {
    b & (1 << 7) != 0
}

/// Determine the value length
/// Will only return a value in: [1, 2, 4, 8]
fn find_length(b: u8) -> u8 {
    1 << ((b & 0x30) >> 4)
}

bitflags! {
    /// Operator for Numeric values, providing ways to compare values
    pub struct NumericOperator: u8 {
        /// Equality comparison between data and value
        const EQ  = 0b0000_0001;
        /// Greater-than comparison between data and value
        const GT  = 0b0000_0010;
        /// Lesser-than comparison between data and value
        const LT  = 0b0000_0100;
        /// AND bit, if set, must be matched in addition to previous value
        const AND = 0b0100_0000;
        /// This is the last {op, value} pair in the list.
        const EOL = 0b1000_000;
    }
}

bitflags! {
    /// Operator for Binary values, providing ways to compare values
    pub struct BinaryOperator: u8 {
        /// MATCH bit. If set, this is a bitwise match operation
        /// (E.g. "(data & value) == value")
        const MATCH  = 0b0000_0001;
        /// NOT bit. If set, logical negation of operation
        const NOT  = 0b0000_0010;
        /// AND bit, if set, must be matched in addition to previous value
        const AND = 0b0100_0000;
        /// This is the last {op, value} pair in the list.
        const EOL = 0b1000_000;
    }
}

bitflags! {
    /// Operator for Fragment values, providing ways to specify rules
    pub struct FragmentOperator: u8 {
        /// Do Not Fragment
        const DF  = 0b0000_0001;
        /// Is a Fragment
        const IF  = 0b0000_0010;
        /// First Fragment
        const FF = 0b0000_0100;
        /// Last Fragment
        const LF = 0b0000_1000;
    }
}

/// Represents the segment type of an AS_PATH. Can be either AS_SEQUENCE or AS_SET.
#[derive(Debug, Clone)]
pub enum FlowspecFilter {
    /// Defines the destination prefix to match
    // Filter type == 1
    DestinationPrefix(Prefix),
    /// Defines the source prefix to match
    // Filter type == 2
    SourcePrefix(Prefix),
    /// Contains a set of {operator, value} pairs that are used to
    /// match the IP protocol value byte in IP packets.
    // Filter type == 3
    IpProtocol(Vec<(NumericOperator, u32)>),
    /// Defines a list of {operation, value} pairs that matches source
    /// OR destination TCP/UDP ports.
    // Filter type == 4
    Port(Vec<(NumericOperator, u32)>),
    /// Defines a list of {operation, value} pairs that matches
    /// destination TCP/UDP ports.
    // Filter type == 5
    DestinationPort(Vec<(NumericOperator, u32)>),
    /// Defines a list of {operation, value} pairs that matches
    /// source TCP/UDP ports.
    // Filter type == 6
    SourcePort(Vec<(NumericOperator, u32)>),
    /// Defines a list of {operation, value} pairs used to match the
    /// type field of an ICMP packet.
    // Filter type == 7
    IcmpType(Vec<(NumericOperator, u8)>),
    /// Defines a list of {operation, value} pairs used to match the
    /// code field of an ICMP packet.
    // Filter type == 8
    IcmpCode(Vec<(NumericOperator, u8)>),
    /// Defines a list of {operation, value} pairs used to match the
    /// code field of an ICMP packet.
    // Filter type == 9
    TcpFlags(Vec<(BinaryOperator, u32)>),
    /// Defines a list of {operation, value} pairs used to match the
    /// code field of an ICMP packet.
    // Filter type == 10
    PacketLength(Vec<(NumericOperator, u32)>),
    /// Defines a list of {operation, value} pairs used to match the
    /// 6-bit DSCP field [RFC2474].
    // Filter type == 11
    DSCP(Vec<(NumericOperator, u8)>),
    /// Defines a list of {operation, value} pairs used to match the
    /// 6-bit DSCP field [RFC2474].
    // Filter type == 12
    Fragment(Vec<(FragmentOperator, u8)>),
}

impl FlowspecFilter {
    pub(crate) fn parse(stream: &mut dyn Read, afi: AFI) -> Result<Self, Error> {
        let filter_type = stream.read_u8()?;
        match filter_type {
            // Prefix-based filters
            1 | 2 => {
                let prefix_length = stream.read_u8()?;
                let prefix_octets = match afi {
                    AFI::IPV6 => {
                        let _prefix_offset = stream.read_u8()?;
                        (f32::from(prefix_length) / 8.0).ceil() as u8
                    }
                    AFI::IPV4 => 4u8,
                    _ => unimplemented!(),
                };
                let mut buf = vec![0u8; prefix_octets as usize];
                stream.read_exact(&mut buf)?;
                let prefix = Prefix::new(afi, prefix_length, buf);
                match filter_type {
                    1 => Ok(FlowspecFilter::DestinationPrefix(prefix)),
                    2 => Ok(FlowspecFilter::SourcePrefix(prefix)),
                    _ => unreachable!(),
                }
            }
            // Variable length Op/Value filters
            3..=6 | 9..=10 => {
                let mut values: Vec<(u8, u32)> = Vec::with_capacity(4);
                loop {
                    let operator = stream.read_u8()?;
                    let length = find_length(operator);
                    let value = match length {
                        1 => u32::from(stream.read_u8()?),
                        2 => u32::from(stream.read_u16::<BigEndian>()?),
                        4 => stream.read_u32::<BigEndian>()?,
                        _ => unreachable!(),
                    };
                    values.push((operator, value));
                    // Check for end-of-list bit
                    if is_end_of_list(operator) {
                        break;
                    }
                }
                match filter_type {
                    3 => Ok(FlowspecFilter::IpProtocol(into_num_op(values))),
                    4 => Ok(FlowspecFilter::Port(into_num_op(values))),
                    5 => Ok(FlowspecFilter::DestinationPort(into_num_op(values))),
                    6 => Ok(FlowspecFilter::SourcePort(into_num_op(values))),
                    9 => {
                        let values: Vec<(_, _)> = values
                            .into_iter()
                            .map(|(op, v)| (BinaryOperator { bits: op }, v))
                            .collect();
                        Ok(FlowspecFilter::TcpFlags(values))
                    }
                    10 => Ok(FlowspecFilter::PacketLength(into_num_op(values))),
                    _ => unreachable!(),
                }
            }
            // Single byte Op/Value filters
            7..=8 | 11..=12 => {
                let mut values: Vec<(u8, u8)> = Vec::with_capacity(4);
                loop {
                    let operator = stream.read_u8()?;
                    let value = stream.read_u8()?;
                    values.push((operator, value));
                    // Check for end-of-list bit
                    if is_end_of_list(operator) {
                        break;
                    }
                }
                match filter_type {
                    7 => Ok(FlowspecFilter::IcmpType(into_num_op(values))),
                    8 => Ok(FlowspecFilter::IcmpCode(into_num_op(values))),
                    11 => Ok(FlowspecFilter::DSCP(into_num_op(values))),
                    12 => {
                        let values: Vec<(_, _)> = values
                            .into_iter()
                            .map(|(op, v)| (FragmentOperator { bits: op }, v))
                            .collect();
                        Ok(FlowspecFilter::Fragment(values))
                    }
                    _ => unreachable!(),
                }
            }
            _ => Err(Error::new(
                ErrorKind::Other,
                format!("Unsupported Flowspec filter type: {}", filter_type),
            )),
        }
    }
}

/// Convert raw values (u8, T) operators into Numeric Operator + value pairs
fn into_num_op<T>(values: Vec<(u8, T)>) -> Vec<(NumericOperator, T)> {
    values
        .into_iter()
        .map(|(op, v)| (NumericOperator { bits: op }, v))
        .collect()
}

#[test]
fn test_flowspec_operator() {
    assert!(is_end_of_list(0x81));
    assert!(!is_end_of_list(0x06));

    assert_eq!(find_length(0b0000_0000), 1);
    assert_eq!(find_length(0b0000_1111), 1);
    assert_eq!(find_length(0b0001_0000), 2);
    assert_eq!(find_length(0b0010_0000), 4);
    assert_eq!(find_length(0b0011_0000), 8);
}
