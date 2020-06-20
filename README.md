# Border Gateway Protocol in Rust (bgp-rs)
[![Build Status](https://github.com/DevQps/bgp-rs/workflows/Validation/badge.svg)](https://github.com/DevQps/bgp-rs/actions) [![codecov](https://codecov.io/gh/DevQps/bgp-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/DevQps/bgp-rs)

A library for parsing Border Gateway Protocol (BGP) formatted streams in Rust.
Messages such as UPDATE, OPEN, KEEPALIVE and NOTIFICATION can be read this way.

## Examples & Documentation

**Reading a MRT file containing BGP4MP messages**
```
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::io::BufReader;
use mrt_rs::Record;
use mrt_rs::bgp4mp::BGP4MP;
use libflate::gzip::Decoder;
use bgp_rs::{Identifier, PathAttribute};

fn main() {
   // Download an update message.
   let file = File::open("res/updates.20190101.0000.gz").unwrap();

   // Decode the GZIP stream.
   let decoder = Decoder::new(BufReader::new(file)).unwrap();

   // Create a new MRTReader with a Cursor such that we can keep track of the position.
   let mut reader = mrt_rs::Reader { stream: decoder };

   // Keep reading MRT (Header, Record) tuples till the end of the file has been reached.
   while let Ok(Some((_, record))) = reader.read() {

       // Extract BGP4MP::MESSAGE_AS4 entries.
       if let Record::BGP4MP(BGP4MP::MESSAGE_AS4(x)) = record {

           // Read each BGP (Header, Message)
           let cursor = Cursor::new(x.message);
           let mut reader = bgp_rs::Reader::new(cursor);
           let (_, message) = reader.read().unwrap();

           // If this is an UPDATE message that contains announcements, extract its origin.
           if let bgp_rs::Message::Update(x) = message {
               if x.is_announcement() {
                   if let PathAttribute::AS_PATH(path) = x.get(Identifier::AS_PATH).unwrap()
                   {
                       // Test the path.origin() method.
                       let origin = path.origin();

                       // Do other stuff ...
                   }
               }
           }
       }
   }
```

**Reading a MRT file containing TABLE_DUMP_V2 messages**

For examples and documentation look [here](https://docs.rs/bgp-rs/).

## Supported Path Attributes
IANA has an [official list of number assignments](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml) for BGP path attributes.
In the table below one can see the status of each path attribute:

| Number |                   Attribute                   |                                                         Specification                                                         |        Status       |
|:------:|:---------------------------------------------:|:-----------------------------------------------------------------------------------------------------------------------------:|:-------------------:|
|    1   |                     ORIGIN                    |                                           [RFC4271](http://www.iana.org/go/rfc4271)                                           |     Implemented     |
|    2   |                    AS_PATH                    |                                           [RFC4271](http://www.iana.org/go/rfc4271)                                           |     Implemented     |
|    3   |                    NEXT_HOP                   |                                           [RFC4271](http://www.iana.org/go/rfc4271)                                           |     Implemented     |
|    4   |                MULTI_EXIT_DISC                |                                           [RFC4271](http://www.iana.org/go/rfc4271)                                           |     Implemented     |
|    5   |                   LOCAL_PREF                  |                                           [RFC4271](http://www.iana.org/go/rfc4271)                                           |     Implemented     |
|    6   |                ATOMIC_AGGREGATE               |                                           [RFC4271](http://www.iana.org/go/rfc4271)                                           |     Implemented     |
|    7   |                   AGGREGATOR                  |                                           [RFC4271](http://www.iana.org/go/rfc4271)                                           |     Implemented     |
|    8   |                   COMMUNITY                   |                                           [RFC1997](http://www.iana.org/go/rfc1997)                                           |     Implemented     |
|    9   |                 ORIGINATOR_ID                 |                                           [RFC4456](http://www.iana.org/go/rfc4456)                                           |     Implemented     |
|   10   |                  CLUSTER_LIST                 |                                           [RFC4456](http://www.iana.org/go/rfc4456)                                           |     Implemented     |
|   11   |              DPA **(deprecated)**             |                                           [RFC6938](http://www.iana.org/go/rfc6938)                                           |     Implemented     |
|   12   |          ADVERTISER **(deprecated)**          | [RFC1863](http://www.iana.org/go/rfc1863) [RFC4223](http://www.iana.org/go/rfc4223) [RFC6938](http://www.iana.org/go/rfc6938) | Not yet implemented |
|   13   |    RCID_PATH / CLUSTER_ID **(deprecated)**    | [RFC1863](http://www.iana.org/go/rfc1863) [RFC4223](http://www.iana.org/go/rfc4223) [RFC6938](http://www.iana.org/go/rfc6938) | Not yet implemented |
|   14   |                 MP_REACH_NLRI                 |                                           [RFC4760](http://www.iana.org/go/rfc4760)                                           |     Implemented     |
|   15   |                MP_UNREACH_NLRI                |                                           [RFC4760](http://www.iana.org/go/rfc4760)                                           |     Implemented     |
|   16   |              EXTENDED_COMMUNITIES             |                                           [RFC4360](http://www.iana.org/go/rfc4360)                                           |     Implemented     |
|   17   |                    AS4_PATH                   |                                           [RFC6793](http://www.iana.org/go/rfc6793)                                           |     Implemented     |
|   18   |                 AS4_AGGREGATOR                |                                           [RFC6793](http://www.iana.org/go/rfc6793)                                           |     Implemented     |
|   19   |    SAFI Specific Attribute **(deprecated)**   |                    [draft-wijnands-mt-discovery-00](http://www.iana.org/go/draft-wijnands-mt-discovery-00)                    | Not yet implemented |
|   20   |                   CONNECTOR                   |                                           [RFC6037](http://www.iana.org/go/rfc6037)                                           |     Implemented     |
|   21   |                  AS_PATHLIMIT                 |                        [draft-ietf-idr-as-pathlimit](http://www.iana.org/go/draft-ietf-idr-as-pathlimit)                      |     Implemented     |
|   22   |                  PMSI_TUNNEL                  |                                           [RFC6514](http://www.iana.org/go/rfc6514)                                           |     Implemented     |
|   23   |              Tunnel Encapsulation             |                                           [RFC5512](http://www.iana.org/go/rfc5512)                                           |     Implemented     |
|   24   |              Traffic Engineering              |                                           [RFC5543](http://www.iana.org/go/rfc5543)                                           | Not yet implemented |
|   25   |    IPv6 Address Specific Extended Community   |                                           [RFC5701](http://www.iana.org/go/rfc5701)                                           |     Implemented     |
|   26   |                      AIGP                     |                                           [RFC7311](http://www.iana.org/go/rfc7311)                                           |     Implemented     |
|   27   |            PE Distinguisher Labels            |                                           [RFC6514](http://www.iana.org/go/rfc6514)                                           | Not yet implemented |
|   28   | BGP Entropy Label Capability **(deprecated)** |                      [RFC6790](http://www.iana.org/go/rfc6790) [RFC7447](http://www.iana.org/go/rfc7447)                      | Not yet implemented |
|   29   |                     BGP-LS                    |                                           [RFC7752](http://www.iana.org/go/rfc7752)                                           | Not yet implemented |
|   32   |                LARGE_COMMUNITY                |                                           [RFC8092](http://www.iana.org/go/rfc8092)                                           |     Implemented     |
|   33   |                  BGPSEC_PATH                  |                                           [RFC8205](http://www.iana.org/go/rfc8205)                                           | Not yet implemented |
|   34   |    BGP Community Container **(temporary)**    |               [draft-ietf-idr-wide-bgp-communities](http://www.iana.org/go/draft-ietf-idr-wide-bgp-communities)               | Not yet implemented |
|   35   |   Internal Only To Customer **(temporary)**   |                    [draft-ietf-idr-bgp-open-policy](http://www.iana.org/go/draft-ietf-idr-bgp-open-policy)                    | Not yet implemented |
|   40   |                 BGP Prefix-SID                |                   [RFC-ietf-idr-bgp-prefix-sid-27](http://www.iana.org/go/draft-ietf-idr-bgp-prefix-sid-27)                   | Not yet implemented |
|   128  |                    ATTR_SET                   |                                           [RFC6368](http://www.iana.org/go/rfc6368)                                           |     Implemented     |

# Minimum Supported Rust Version
This crate's minimum supported `rustc` version is `1.34.2`.

# Crate Features
The default feature set includes encoding & decoding of BGP Messages with attributes listed above

## Enable Flowspec NLRI
To enable Flowspec NLRI (SAFI 133) parsing ([RFC5575](https://tools.ietf.org/html/rfc5575)), specify the `flowspec` feature:

```
[dependencies]
...
bgp-rs = { version = "*", features = ["flowspec"]}
...
```

*NOTE*: This will add the [`bitflags`](https://crates.io/crates/bitflags) dependency
