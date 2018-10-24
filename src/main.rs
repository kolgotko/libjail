extern crate libjail;
extern crate sysctl;

use std::process::Command;
use std::collections::HashMap;
use libjail::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() {

    // let mut rules: HashMap<Val, Val> = HashMap::new();

    // rules.insert("jid".into(), 1.into());
    // rules.insert("path".into(), "/jails/freebsd112".into());
    // rules.insert("name".into(), "freebsd112".into());
    // rules.insert("ip4".into(), JAIL_SYS_INHERIT.into());
    // rules.insert("host.hostname".into(), "${name}.jmaker.service".into());
    // rules.insert("ip4.addr".into(), "127.0.0.2".parse::<Ipv4Addr>().unwrap().into());
    // rules.insert("persist".into(), true.into());
    // rules.insert("nopersist".into(), Val::Null);

    // let jid = set(rules, Action::create()).unwrap();

    // remove(jid).unwrap();

    // loop {}

    let rules = get_rules(1, vec!["test"]).unwrap();
    // let rules = get_rules_all(1).unwrap();
    // let name = rules.get("name".into()).unwrap();
    println!("{:#?}", rules);

    // rules.insert("jid".into(), 1.into());
    // // rules.insert("name".into(), "freebsd112".into());
    // rules.insert("name".into(), vec![0; 256].into());
    // // rules.insert("host.hostname".into(), "".into());

    // println!("{:#?}", rules);
}
