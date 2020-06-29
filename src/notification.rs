use std::fmt;
use std::io::{Error, Read, Write};

use byteorder::{ReadBytesExt, WriteBytesExt};

use crate::*;

/// Represents a BGP Notification message.
#[derive(Clone, Debug)]
pub struct Notification {
    /// Major Error Code [RFC4271]
    pub major_err_code: u8,
    /// Minor Error Code [RFC4271]
    pub minor_err_code: u8,
    /// Notification data
    pub data: Vec<u8>,
}

impl Notification {
    /// Parse Notification message
    /// Parses the error codes and checks for additional (optional) data
    pub fn parse(header: &Header, stream: &mut impl Read) -> Result<Notification, Error> {
        let major_err_code = stream.read_u8()?;
        let minor_err_code = stream.read_u8()?;
        let data = if header.length > 21 {
            let remaining_length = header.length as usize - 21;
            let mut data = vec![0; remaining_length as usize];
            stream.read_exact(&mut data)?;
            data
        } else {
            vec![]
        };

        Ok(Notification {
            major_err_code,
            minor_err_code,
            data,
        })
    }

    /// Encode message to bytes
    pub fn encode(&self, buf: &mut impl Write) -> Result<(), Error> {
        buf.write_u8(self.major_err_code)?;
        buf.write_u8(self.minor_err_code)?;
        buf.write_all(&self.data)
    }

    /// Major Error Code Description
    pub fn major(&self) -> String {
        match self.major_err_code {
            1 => "Message Header Error".to_string(),
            2 => "OPEN Message Error".to_string(),
            3 => "UPDATE Message Error".to_string(),
            4 => "Hold Timer Expired".to_string(),
            5 => "Finite State Machine".to_string(),
            6 => "Cease".to_string(),
            _ => format!("Major Code {}", self.major_err_code),
        }
    }
    /// Minor Error Code Description
    pub fn minor(&self) -> String {
        format!("{}", self.minor_err_code)
    }

    /// Included message (if present)
    pub fn message(&self) -> Option<String> {
        String::from_utf8(self.data.clone()).ok()
    }
}

impl fmt::Display for Notification {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} / {} {}",
            self.major(),
            self.minor(),
            self.message().unwrap_or_else(|| "".to_string())
        )
    }
}

#[test]
fn test_notification_display() {
    let notification = Notification {
        major_err_code: 6,
        minor_err_code: 3,
        data: vec![],
    };
    assert_eq!(&notification.to_string(), "Cease / 3 ");
    let notification = Notification {
        major_err_code: 2,
        minor_err_code: 1,
        data: b"Unsupported Capability".to_vec(),
    };
    assert_eq!(
        &notification.to_string(),
        "OPEN Message Error / 1 Unsupported Capability"
    );
}

#[test]
fn test_notification_display_unknown_maj() {
    let notification = Notification {
        major_err_code: 9,
        minor_err_code: 0,
        data: vec![],
    };
    assert_eq!(&notification.to_string(), "Major Code 9 / 0 ");
}
