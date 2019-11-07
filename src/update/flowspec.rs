use crate::{Prefix, AFI};

use bitflags::bitflags;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use std::io::{Error, ErrorKind, Read, Write};

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
        /// Value length of 2 bytes
        const V2  = 0b0001_0000;
        /// Value length of 4 bytes
        const V4  = 0b0010_0000;
        /// Value length of 8 bytes
        const V8  = 0b0011_0000;
        /// AND bit, if set, must be matched in addition to previous value
        const AND = 0b0100_0000;
        /// This is the last {op, value} pair in the list.
        const EOL = 0b1000_0000;
    }
}

impl NumericOperator {
    /// Create a new Numeric Operator from a u8
    pub fn new(bits: u8) -> Self {
        Self { bits }
    }

    /// Set End-of-list bit
    pub fn set_eol(&mut self) {
        *self |= Self::EOL;
    }
    /// Clear End-of-list bit
    pub fn unset_eol(&mut self) {
        // byte &= 0b1111_0111; // Unset a bit
        *self &= !Self::EOL;
    }

    /// Set the operator value byte length. Must be one of: [1, 2, 4, 8]
    pub fn set_length(&mut self, length: u8) {
        match length {
            1 => *self &= !Self::V8, // Clear the 2 bits
            2 => {
                *self &= !Self::V8;
                *self |= Self::V2;
            }
            4 => {
                *self &= !Self::V8;
                *self |= Self::V4;
            }
            8 => *self |= Self::V8,
            _ => unimplemented!(),
        }
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
        /// Value length of 2 bytes
        const V2  = 0b0001_0000;
        /// AND bit, if set, must be matched in addition to previous value
        const AND = 0b0100_0000;
        /// This is the last {op, value} pair in the list.
        const EOL = 0b1000_0000;
    }
}

impl BinaryOperator {
    /// Create a new Binary Operator from a u8
    pub fn new(bits: u8) -> Self {
        Self { bits }
    }

    /// Set End-of-list bit
    pub fn set_eol(&mut self) {
        *self |= Self::EOL;
    }
    /// Clear End-of-list bit
    pub fn unset_eol(&mut self) {
        // byte &= 0b1111_0111; // Unset a bit
        *self &= !Self::EOL;
    }

    /// Set the operator value byte length. Must be one of: [1, 2]
    pub fn set_length(&mut self, length: u8) {
        match length {
            1 => *self &= !Self::V2,
            2 => {
                *self &= !Self::V2;
                *self |= Self::V2;
            }
            _ => unimplemented!(),
        }
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
        /// This is the last {op, value} pair in the list.
        const EOL = 0b1000_0000;
    }
}

impl FragmentOperator {
    /// Create a new Fragment Operator from a u8
    pub fn new(bits: u8) -> Self {
        Self { bits }
    }

    /// Set End-of-list bit
    pub fn set_eol(&mut self) {
        *self |= Self::EOL;
    }
    /// Clear End-of-list bit
    pub fn unset_eol(&mut self) {
        // byte &= 0b1111_0111; // Unset a bit
        *self &= !Self::EOL;
    }
}

/// Represents the segment type of an AS_PATH. Can be either AS_SEQUENCE or AS_SET.
#[derive(Debug, Clone, Eq, PartialEq)]
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
    /// Flags in a TCP header
    // Filter type == 9
    TcpFlags(Vec<(BinaryOperator, u16)>),
    /// Defines a list of {operation, value} pairs used to match the
    /// packet length.
    // Filter type == 10
    PacketLength(Vec<(NumericOperator, u32)>),
    /// Defines a list of {operation, value} pairs used to match the
    /// 6-bit DSCP field [RFC2474].
    // Filter type == 11
    DSCP(Vec<(NumericOperator, u8)>),
    /// Defines a list of {operation, value} pairs used to match the
    /// packet fragment status.
    // Filter type == 12
    Fragment(Vec<(FragmentOperator, u8)>),
}

impl FlowspecFilter {
    /// The Flowspec Filter Type Code [RFC: 5575]
    pub fn code(&self) -> u8 {
        match self {
            Self::DestinationPrefix(_) => 1,
            Self::SourcePrefix(_) => 2,
            Self::IpProtocol(_) => 3,
            Self::Port(_) => 4,
            Self::DestinationPort(_) => 5,
            Self::SourcePort(_) => 6,
            Self::IcmpType(_) => 7,
            Self::IcmpCode(_) => 8,
            Self::TcpFlags(_) => 9,
            Self::PacketLength(_) => 10,
            Self::DSCP(_) => 11,
            Self::Fragment(_) => 12,
        }
    }
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
                            .map(|(op, v)| (BinaryOperator { bits: op }, v as u16))
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

    /// Encode Flowspec NLRI to bytes
    pub fn encode(&self, buf: &mut dyn Write) -> Result<(), Error> {
        use FlowspecFilter::*;
        buf.write_u8(self.code())?;
        match self {
            DestinationPrefix(prefix) | SourcePrefix(prefix) => {
                buf.write_u8(prefix.length)?;
                buf.write_u8(0)?; // Offset
                buf.write_all(&prefix.prefix)?;
            }
            IpProtocol(values)
            | DestinationPort(values)
            | SourcePort(values)
            | Port(values)
            | PacketLength(values) => {
                for (i, (mut oper, value)) in values.iter().enumerate() {
                    if i + 1 == values.len() {
                        oper.set_eol();
                    } else {
                        oper.unset_eol();
                    }
                    match value {
                        0..=255 => {
                            oper.set_length(1);
                            buf.write_u8(oper.bits())?;
                            buf.write_u8(*value as u8)?;
                        }
                        256..=65535 => {
                            oper.set_length(2);
                            buf.write_u8(oper.bits())?;
                            buf.write_u16::<BigEndian>(*value as u16)?;
                        }
                        65536..=std::u32::MAX => {
                            oper.set_length(4);
                            buf.write_u8(oper.bits())?;
                            buf.write_u32::<BigEndian>(*value)?;
                        }
                    }
                }
            }
            IcmpCode(values) | IcmpType(values) | DSCP(values) => {
                for (i, (mut oper, value)) in values.iter().enumerate() {
                    if i + 1 == values.len() {
                        oper.set_eol();
                    } else {
                        oper.unset_eol();
                    }
                    oper.set_length(1);
                    buf.write_u8(oper.bits())?;
                    buf.write_u8(*value as u8)?;
                }
            }
            TcpFlags(values) => {
                for (i, (mut oper, value)) in values.iter().enumerate() {
                    if i + 1 == values.len() {
                        oper.set_eol();
                    } else {
                        oper.unset_eol();
                    }
                    match value {
                        0..=255 => {
                            oper.set_length(1);
                            buf.write_u8(oper.bits())?;
                            buf.write_u8(*value as u8)?;
                        }
                        256..=std::u16::MAX => {
                            oper.set_length(2);
                            buf.write_u8(oper.bits())?;
                            buf.write_u16::<BigEndian>(*value)?;
                        }
                    }
                }
            }
            Fragment(values) => {
                for (i, (mut oper, value)) in values.iter().enumerate() {
                    if i + 1 == values.len() {
                        oper.set_eol();
                    } else {
                        oper.unset_eol();
                    }
                    buf.write_u8(oper.bits())?;
                    buf.write_u8(*value as u8)?;
                }
            }
        }
        Ok(())
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
fn test_flowspec_operator_length() {
    assert_eq!(find_length(0b0000_0000), 1);
    assert_eq!(find_length(0b0000_1111), 1);
    assert_eq!(find_length(0b0001_0000), 2);
    assert_eq!(find_length(0b0010_0000), 4);
    assert_eq!(find_length(0b0011_0000), 8);
}

#[test]
fn test_flowspec_numeric_operator_bits() {
    let mut eol = NumericOperator::new(0x81);
    assert!(is_end_of_list(eol.bits()));
    eol.unset_eol();
    assert!(!is_end_of_list(eol.bits()));

    let mut not_eol = NumericOperator::new(0x06);
    assert!(!is_end_of_list(not_eol.bits()));
    not_eol.set_eol();
    assert!(is_end_of_list(not_eol.bits()));

    let mut oper = NumericOperator::EQ;
    oper.set_length(1);
    assert_eq!(find_length(oper.bits()), 1);
    oper.set_length(2);
    assert_eq!(find_length(oper.bits()), 2);
    oper.set_length(4);
    assert_eq!(find_length(oper.bits()), 4);
    oper.set_length(8);
    assert_eq!(find_length(oper.bits()), 8);
}
