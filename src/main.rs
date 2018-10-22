extern crate libjail;

use std::collections::HashMap;
use libjail::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() {
    let _rules: HashMap<Val, Val> = HashMap::new();

    // rules.insert("path".into(), "/jails/freebsd112".into());
    // rules.insert("name".into(), "freebsd112".into());
    // rules.insert("ip4.addr".into(), "127.0.0.1".parse::<Ipv4Addr>().unwrap().into());
    // rules.insert("ip6.addr".into(), "::123".parse::<Ipv6Addr>().unwrap().into());
    // rules.insert("persist".into(), true.into());
    // rules.insert("nopersist".into(), Val::Null);

    // let jid = set(rules, Action::create() + Modifier::attach()).unwrap();

    let rules = get_rules(1, vec!["name", "ip4.addr", "jid", "ip6.addr"]).unwrap();
    println!("-- {:?}", rules);

    // rules.insert("jid".into(), 1.into());
    // // rules.insert("name".into(), "freebsd112".into());
    // rules.insert("name".into(), vec![0; 256].into());
    // // rules.insert("host.hostname".into(), "".into());

    // println!("{:#?}", rules);
}
