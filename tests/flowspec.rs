#![cfg(feature = "flowspec")]
use bgp_rs::flowspec::{BinaryOperator, FlowspecFilter, NumericOperator};
use bgp_rs::{Identifier, Message, NLRIEncoding, PathAttribute, AFI, SAFI};
mod common;
use common::parse::{parse_pcap_messages, transform_u64_to_bytes};

#[test]
fn test_flowspec_v6() {
    let updates: Vec<_> = parse_pcap_messages("res/pcap/BGP_flowspec_v6.cap")
        .unwrap()
        .into_iter()
        .filter_map(|message| match message {
            Message::Update(update) => Some(update),
            _ => None,
        })
        .collect();
    assert_eq!(updates.len(), 2);
    let update_announce = &updates[0];
    match update_announce.get(Identifier::EXTENDED_COMMUNITIES) {
        Some(PathAttribute::EXTENDED_COMMUNITIES(communities)) => {
            assert_eq!(
                transform_u64_to_bytes(communities[0]),
                [0x80, 0x06, 0, 0, 0, 0, 0, 0],
                // ^------^ FlowSpec Traffic Rate
            );
        }
        _ => panic!("Extended Communities not present"),
    }
    match update_announce.get(Identifier::MP_REACH_NLRI) {
        Some(PathAttribute::MP_REACH_NLRI(reach_nlri)) => {
            assert_eq!(reach_nlri.afi, AFI::IPV6);
            assert_eq!(reach_nlri.safi, SAFI::Flowspec);
            assert_eq!(reach_nlri.announced_routes.len(), 1);
            match &reach_nlri.announced_routes[0] {
                NLRIEncoding::FLOWSPEC(filters) => {
                    assert_eq!(filters.len(), 1);
                    match &filters[0] {
                        FlowspecFilter::DestinationPrefix(prefix) => {
                            assert_eq!(&prefix.to_string(), "2100::/16");
                        }
                        _ => panic!("Destination Prefix not present"),
                    }
                }
                _ => panic!("FLOWSPEC NLRI not present"),
            }
        }
        _ => panic!("MP_REACH_NLRI not present"),
    }
    let update_withdraw = &updates[1];
    match update_withdraw.get(Identifier::MP_UNREACH_NLRI) {
        Some(PathAttribute::MP_UNREACH_NLRI(unreach_nlri)) => {
            assert_eq!(unreach_nlri.afi, AFI::IPV6);
            assert_eq!(unreach_nlri.safi, SAFI::Flowspec);
            assert_eq!(unreach_nlri.withdrawn_routes.len(), 0);
        }
        _ => panic!("MP_UNREACH_NLRI not present"),
    }
}

#[test]
fn test_flowspec_v6_redirect() {
    let updates: Vec<_> = parse_pcap_messages("res/pcap/BGP_flowspec_redirect.cap")
        .unwrap()
        .into_iter()
        .filter_map(|message| match message {
            Message::Update(update) => Some(update),
            _ => None,
        })
        .collect();
    let update = &updates[2];
    match update.get(Identifier::EXTENDED_COMMUNITIES) {
        Some(PathAttribute::EXTENDED_COMMUNITIES(communities)) => {
            assert_eq!(
                transform_u64_to_bytes(communities[0]),
                [0x80, 0x08, 0, 6, 0, 0, 0x01, 0x2e],
                //                       ^--------^ 4-oct AN
                //              ^-- 2-oct AS
                // ^------^ FlowSpec Redirect
            );
        }
        _ => panic!("Extended Communities not present"),
    }
    match update.get(Identifier::MP_REACH_NLRI) {
        Some(PathAttribute::MP_REACH_NLRI(reach_nlri)) => {
            assert_eq!(reach_nlri.afi, AFI::IPV6);
            assert_eq!(reach_nlri.safi, SAFI::Flowspec);
            assert_eq!(reach_nlri.announced_routes.len(), 1);
            match &reach_nlri.announced_routes[0] {
                NLRIEncoding::FLOWSPEC(filters) => {
                    assert_eq!(filters.len(), 2);
                    match &filters[0] {
                        FlowspecFilter::DestinationPrefix(prefix) => {
                            assert_eq!(&prefix.to_string(), "3001:99:b::10/128");
                        }
                        _ => panic!("Destination Prefix not present"),
                    }
                    match &filters[1] {
                        FlowspecFilter::SourcePrefix(prefix) => {
                            assert_eq!(&prefix.to_string(), "3001:99:a::10/128");
                        }
                        _ => panic!("Source Prefix not present"),
                    }
                }
                _ => panic!("FLOWSPEC NLRI not present"),
            }
        }
        _ => panic!("MP_REACH_NLRI not present"),
    }
}

#[test]
fn test_flowspec_dscp() {
    let updates: Vec<_> = parse_pcap_messages("res/pcap/BGP_flowspec_dscp.cap")
        .unwrap()
        .into_iter()
        .filter_map(|message| match message {
            Message::Update(update) => Some(update),
            _ => None,
        })
        .collect();
    let update = &updates[0];
    match update.get(Identifier::MP_REACH_NLRI) {
        Some(PathAttribute::MP_REACH_NLRI(reach_nlri)) => {
            assert_eq!(reach_nlri.afi, AFI::IPV6);
            assert_eq!(reach_nlri.safi, SAFI::Flowspec);
            match &reach_nlri.announced_routes[0] {
                NLRIEncoding::FLOWSPEC(filters) => {
                    assert_eq!(filters.len(), 1);
                    match &filters[0] {
                        FlowspecFilter::DSCP(values) => {
                            assert_eq!(values.len(), 4);
                        }
                        _ => panic!("DSCP Markers not present"),
                    }
                }
                _ => panic!("FLOWSPEC NLRI not present"),
            }
        }
        _ => panic!("MP_REACH_NLRI not present"),
    }
}

#[test]
fn test_flowspec_v4() {
    let updates: Vec<_> = parse_pcap_messages("res/pcap/BGP_flowspec_v4.cap")
        .unwrap()
        .into_iter()
        .filter_map(|message| match message {
            Message::Update(update) => Some(update),
            _ => None,
        })
        .collect();
    let update = &updates[0];
    match update.get(Identifier::EXTENDED_COMMUNITIES) {
        Some(PathAttribute::EXTENDED_COMMUNITIES(communities)) => {
            assert_eq!(
                transform_u64_to_bytes(communities[0]),
                [0x80, 0x06, 0, 0, 0, 0, 0, 0],
                // ^------^ FlowSpec Traffic Rate
            );
        }
        _ => panic!("Extended Communities not present"),
    }
    match update.get(Identifier::MP_REACH_NLRI) {
        Some(PathAttribute::MP_REACH_NLRI(reach_nlri)) => {
            assert_eq!(reach_nlri.afi, AFI::IPV4);
            assert_eq!(reach_nlri.safi, SAFI::Flowspec);
            match &reach_nlri.announced_routes[0] {
                NLRIEncoding::FLOWSPEC(filters) => {
                    assert_eq!(filters.len(), 6);
                    match &filters[0] {
                        FlowspecFilter::DestinationPrefix(prefix) => {
                            assert_eq!(&prefix.to_string(), "192.168.0.1/32");
                        }
                        _ => panic!("Destination Prefix not present"),
                    }
                    match &filters[1] {
                        FlowspecFilter::SourcePrefix(prefix) => {
                            assert_eq!(&prefix.to_string(), "10.0.0.9/32");
                        }
                        _ => panic!("Source Prefix not present"),
                    }
                    match &filters[2] {
                        FlowspecFilter::IpProtocol(protocols) => {
                            assert_eq!(protocols[0], (NumericOperator::new(1), 17u32));
                            assert_eq!(protocols[1], (NumericOperator::new(129), 6u32));
                        }
                        _ => panic!("IpProtocol not present"),
                    }
                    match &filters[3] {
                        FlowspecFilter::Port(protocols) => {
                            assert_eq!(protocols[0], (NumericOperator::new(1), 80u32));
                            assert_eq!(protocols[1], (NumericOperator::new(145), 8080u32));
                        }
                        _ => panic!("Port not present"),
                    }
                    match &filters[4] {
                        FlowspecFilter::DestinationPort(protocols) => {
                            assert_eq!(protocols[0], (NumericOperator::new(18), 8080u32));
                            assert_eq!(protocols[1], (NumericOperator::new(84), 8088u32));
                            assert_eq!(protocols[2], (NumericOperator::new(145), 3128u32));
                        }
                        _ => panic!("DestinationPort not present"),
                    }
                    match &filters[5] {
                        FlowspecFilter::SourcePort(protocols) => {
                            assert_eq!(protocols[0], (NumericOperator::new(146), 1024u32));
                        }
                        _ => panic!("DestinationPort not present"),
                    }
                }
                _ => panic!("FLOWSPEC NLRI not present"),
            }
        }
        _ => panic!("MP_REACH_NLRI not present"),
    }
}

fn _filter_roundtrip(filter: &FlowspecFilter, afi: AFI) {
    eprintln!("Testing {}", filter);
    let mut bytes = vec![];
    filter.encode(&mut bytes).unwrap();
    let mut buffer = std::io::Cursor::new(bytes);
    let result = FlowspecFilter::parse(&mut buffer, afi).unwrap();
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
        eprintln!("Error roundtripping: {:?}", filter);
        assert_eq!(original_bytes, roundtrip_bytes);
    }
}

#[test]
fn test_filter_roundtrips() {
    let filters = vec![
        FlowspecFilter::DestinationPrefix(("192.168.0.0".parse().unwrap(), 16).into()),
        FlowspecFilter::DestinationPrefix(("2620:10:20::".parse().unwrap(), 64).into()),
        FlowspecFilter::SourcePrefix(("192.168.0.0".parse().unwrap(), 16).into()),
        FlowspecFilter::SourcePrefix(("2620:10:20::".parse().unwrap(), 64).into()),
        FlowspecFilter::IpProtocol(vec![(NumericOperator::EQ, 80), (NumericOperator::EQ, 8080)]),
        FlowspecFilter::Port(vec![(NumericOperator::GT, 80), (NumericOperator::LT, 8080)]),
        FlowspecFilter::DestinationPort(vec![(NumericOperator::EQ, 443)]),
        FlowspecFilter::SourcePort(vec![(NumericOperator::EQ, 22)]),
        FlowspecFilter::IcmpType(vec![(NumericOperator::EQ, 2), (NumericOperator::EQ, 1)]),
        FlowspecFilter::IcmpCode(vec![(NumericOperator::EQ, 2), (NumericOperator::EQ, 1)]),
        FlowspecFilter::TcpFlags(vec![(BinaryOperator::MATCH, 2), (BinaryOperator::NOT, 8)]),
        FlowspecFilter::PacketLength(vec![(NumericOperator::LT, 64), (NumericOperator::GT, 1500)]),
    ];

    for filter in filters {
        _filter_roundtrip(&filter, AFI::IPV4);
    }
}
