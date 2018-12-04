#![feature(try_from)]
extern crate libjail;
extern crate sysctl;

use std::process::Command;
use std::collections::HashMap;
use libjail::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::error::Error;
use std::convert::TryInto;

fn main() -> Result<(), Box<Error>> {

    let mut rules: HashMap<Val, Val> = HashMap::new();

    rules.insert("jid".try_into()?, "1".try_into()?);
    rules.insert("path".try_into()?, "/jails/freebsd112".try_into()?);
    rules.insert("name".try_into()?, "freebsd112".try_into()?);
    rules.insert("host.hostname".try_into()?, "freebsd112.jmaker.service".try_into()?);
    rules.insert("ip4.addr".try_into()?, "127.0.0.2".try_into()?);
    rules.insert("persist".try_into()?, true.try_into()?);

    let jid = set(rules, Action::create()).unwrap();

    Ok(())
}
