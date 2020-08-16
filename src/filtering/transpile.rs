use std::net::{IpAddr, Ipv4Addr};
use cidr_utils::cidr::IpCidr;
use crate::network::{PacketType, PacketInfo};

use pest::Parser;
use pest::error::Error;
use pest::iterators::{Pair, Pairs};

#[derive(Parser, Debug)]
#[grammar = "filtering/rshark_grammar.pest"]
struct RsharkParser;

#[derive(Copy, Clone, Debug)]
enum Comparison<T> {
    Eq(T),
    Gt(T),
    Lt(T),
    Gte(T),
    Lte(T),
}

#[derive(Debug)]
pub enum DisplayFilter {
    PacketFilter(PacketType),
    IpAddrFilter(Comparison<IpAddr>),

    // TODO implementing evaluator for these two
    IpCidrFilter(IpCidr),
    PortFilter(Comparison<IpCidr>),

    And(Box<DisplayFilter>, Box<DisplayFilter>),
    Or(Box<DisplayFilter>, Box<DisplayFilter>),
    Not(Box<DisplayFilter>),
}

impl DisplayFilter {
    pub fn new(query: &str) -> Result<Self, Error<Rule>> {
        let mut parsed_query = RsharkParser::parse(Rule::rule, query)?;
        //    .next().unwrap();
        let mut stack = Vec::new();
        Self::parse_rule(parsed_query.next().unwrap().into_inner(), &mut stack);
        Ok(stack.pop().unwrap())
    }

    fn get_precedence(pair: Pair<Rule>) -> u8 {
        match pair.as_rule() {
            Rule::not => 3,
            Rule::and => 2,
            Rule::or => 1,
        }
    }

    fn parse_rule(mut parsed_query: Pairs<Rule>, mut stack: &mut Vec<Self>) {
        let mut pair = parsed_query.next().unwrap();
        let mut operator_stack = Vec::new();
        pair = pair.into_inner().next().unwrap();
        parse_primitive(pair, &mut stack);
        while let Some(pair) = stack.pop() {
            match pair.as_rule() {
                Rule::primitive => {
                    Self::parse_primitive(pair, &mut stack);
                }
                Rule::and => {
                    operator_stack.push(pair);
                    pair = parsed_query.next().unwrap();
                    if let Some(next_pair) = pair.into_inner().next() {
                        Self::parse_primitive(next_pair, &mut stack);
                        let prim1 = stack.pop().unwrap();
                        let prim2 = stack.pop().unwrap();
                        let result = Self::And(Box::new(prim1), Box::new(prim2));
                        stack.push(result);
                        Self::parse_rule(parsed_query, &mut stack);
                    } else {
                        return;
                    }
                }
                Rule::or => {
                    pair = parsed_query.next().unwrap();
                    if let Some(next_pair) = pair.into_inner().next() {
                        Self::parse_primitive(next_pair, &mut stack);
                        let prim1 = stack.pop().unwrap();
                        let prim2 = stack.pop().unwrap();
                        let result = Self::Or(Box::new(prim1), Box::new(prim2));
                        stack.push(result);
                        Self::parse_rule(parsed_query, &mut stack);
                    } else {
                        return;
                    }
                }
                Rule::not => {
                    pair = parsed_query.next().unwrap();
                    if let Some(next_pair) = pair.into_inner().next() {
                        Self::parse_primitive(next_pair, &mut stack);
                        let prim = stack.pop().unwrap();
                        let result = Self::Not(Box::new(prim));
                        stack.push(result);
                        Self::parse_rule(parsed_query, &mut stack);
                    } else {
                        return;
                    }
                }
                Rule::EOI => return,
                rule @ _ => panic!("Failed in parsing rule, got {:?}", rule),
            }       
        }
    }

    fn parse_primitive(pair: Pair<Rule>, stack: &mut Vec<Self>) {
        match pair.as_rule() {
            Rule::tcp => stack.push(Self::PacketFilter(PacketType::TCP)),
            Rule::udp => stack.push(Self::PacketFilter(PacketType::UDP)),
            Rule::arp => stack.push(Self::PacketFilter(PacketType::ARP)),
            Rule::icmp => stack.push(Self::PacketFilter(PacketType::ICMP)),
            Rule::icmpv6 => stack.push(Self::PacketFilter(PacketType::ICMPv6)),
            Rule::ip => {
                let mut ip_pairs = pair.into_inner();
                let op = ip_pairs.next().unwrap();
                let value = str::parse(ip_pairs.next().unwrap().as_str()).unwrap();
                match op.as_rule() {
                    Rule::eq => stack
                        .push(Self::IpAddrFilter(Comparison::Eq(value))),
                    Rule::gt => stack
                        .push(Self::IpAddrFilter(Comparison::Gt(value))),
                    Rule::lt => stack
                        .push(Self::IpAddrFilter(Comparison::Lt(value))),
                    Rule::ge => stack
                        .push(Self::IpAddrFilter(Comparison::Gte(value))),
                    Rule::le => stack
                        .push(Self::IpAddrFilter(Comparison::Lte(value))),
                    rule @ _ => panic!("Failed in parsing comparison, got {:?}", rule),
                }
            }
            rule @ _ => panic!("Failed in parsing primitive, got {:?}", rule),
        }
    }

    pub fn is_match(&self, given: &PacketInfo) -> Result<bool, String> {
        match self {
            &Self::PacketFilter(packet_type) => {
                if packet_type == given.packet_type {
                    return Ok(true);
                }
                Ok(false)
            }
            &Self::IpAddrFilter(ip_comp) => {
                let given_src_ip = given.source_ip;
                let given_dst_ip = given.dest_ip;
                match ip_comp {
                    Comparison::Eq(value) => {
                        if let Some(given_src_ip) = given_src_ip {
                            if value == given_src_ip {
                                return Ok(true);
                            }
                        }
                        if let Some(given_dst_ip) = given_dst_ip {
                            if value == given_dst_ip {
                                return Ok(true);
                            }
                        }
                        Ok(false)
                    }
                    Comparison::Gt(value) => {
                        if let Some(given_src_ip) = given_src_ip {
                            if value > given_src_ip {
                                return Ok(true);
                            }
                        }
                        if let Some(given_dst_ip) = given_dst_ip {
                            if value > given_dst_ip {
                                return Ok(true);
                            }
                        }
                        Ok(false)
                    }
                    Comparison::Lt(value) => {
                        if let Some(given_src_ip) = given_src_ip {
                            if value < given_src_ip {
                                return Ok(true);
                            }
                        }
                        if let Some(given_dst_ip) = given_dst_ip {
                            if value < given_dst_ip {
                                return Ok(true);
                            }
                        }
                        Ok(false)
                    }
                    Comparison::Gte(value) => {
                        if let Some(given_src_ip) = given_src_ip {
                            if value >= given_src_ip {
                                return Ok(true);
                            }
                        }
                        if let Some(given_dst_ip) = given_dst_ip {
                            if value >= given_dst_ip {
                                return Ok(true);
                            }
                        }
                        Ok(false)
                    }
                    Comparison::Lte(value) => {
                        if let Some(given_src_ip) = given_src_ip {
                            if value <= given_src_ip {
                                return Ok(true);
                            }
                        }
                        if let Some(given_dst_ip) = given_dst_ip {
                            if value <= given_dst_ip {
                                return Ok(true);
                            }
                        }
                        Ok(false)
                    }
                }
            }
            Self::And(df1, df2) => {
                Ok(df1.is_match(&given)? && df2.is_match(&given)?)
            }
            Self::Or(df1, df2) => {
                Ok(df1.is_match(&given)? || df2.is_match(&given)?)
            }
            Self::Not(df) => {
                Ok(!(df.is_match(&given)?))
            }
            _ => Err(String::from("Error evaluating DisplayFilter"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{PacketType, PacketInfo};
    use pnet::packet::udp::UdpPacket;
    #[test]

    fn parse_test() {
        let unparsed_rule = "(ip == 192.168.0.1 || tcp) && arp";

        let rule = RsharkParser::parse(Rule::rule, &unparsed_rule)
            .expect("parse failed")
            .next().unwrap();

        // let filter_prop = Filter_Prop::default();

        for item in rule.into_inner() {
            println!("{:#?}\n------\n", item);
        }
    }
}
