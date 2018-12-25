# libjail
 Interface for system calls: jail_get, jail_set, jail_remove, jail_attach

## Example:
```rust
#![feature(try_from)]
extern crate libjail;

use libjail::*;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::error::Error;
use std::convert::TryInto;

fn main() -> Result<(), Box<Error>> {

    let mut rules: HashMap<Val, Val> = HashMap::new();

    rules.insert("path".try_into()?, "/jails/freebsd112".try_into()?);
    rules.insert("name".try_into()?, "freebsd112".try_into()?);
    rules.insert("host.hostname".try_into()?, "freebsd112.local.net".try_into()?);
    rules.insert("ip4.addr".try_into()?, "127.0.0.2".try_into()?);
    rules.insert("persist".try_into()?, true.try_into()?);

    let jid = set(rules, Action::create()).unwrap();

    Ok(())
}
```
