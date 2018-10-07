extern crate libc;

use libc::{jail_get, jail_set};
use libc::iovec;
use libc::{__error, strerror};

use std::mem::size_of_val;
use std::ffi::{CStr, CString};
use std::collections::HashMap;
use std::convert::*;

#[derive(Hash, Eq, PartialEq)]
enum Iov {
    CString(CString),
    I32(i32),
    Bool(bool),
}

impl From<String> for Iov {
    fn from(value: String) -> Self {
        Iov::CString(CString::new(value).unwrap())
    }
}

impl From<i32> for Iov {
    fn from(value: i32) -> Self {
        Iov::I32(value)
    }
}

impl From<bool> for Iov {
    fn from(value: bool) -> Self {
        Iov::Bool(value)
    }
}

impl<'a> From<&'a str> for Iov {
    fn from(value: &str) -> Self {
        Iov::CString(CString::new(value).unwrap())
    }
}

impl Iov {

    fn to_iov(&self) -> libc::iovec {

        match &self {
            Iov::CString(value) => {
                iovec {
                    iov_base: value.as_ptr() as *mut _,
                    iov_len: value.as_bytes_with_nul().len(),
                }
            },
            Iov::I32(value) => {
                iovec {
                    iov_base: value as *const _ as *mut _,
                    iov_len: size_of_val(value),
                }
            },
            Iov::Bool(value) => {
                iovec {
                    iov_base: value as *const _ as *mut _,
                    iov_len: size_of_val(value),
                }
            },
        }

    }
}

fn run(mut rules: HashMap<Iov, Iov>) {

    let mut iovec_vec = Vec::new();

    for (key, value) in rules.iter() {

        iovec_vec.push(key.to_iov());
        iovec_vec.push(value.to_iov());

    }

    let jid = unsafe {
        jail_set(
            iovec_vec.as_slice().as_ptr() as *mut _,
            iovec_vec.len() as u32,
            libc::JAIL_CREATE
        )
    };

    if jid { Ok(jid) }
    else {
    
    }
    println!("{}", jid);

    unsafe {
        let mut err = *__error();
        println!("{}", err);
        let err_str = strerror(err);
        let err_str = CString::from_raw(err_str);
        println!("{:?}", err_str);
    }
}

fn main() {

    let mut rules: HashMap<Iov, Iov> = HashMap::new();

    rules.insert("path".into(), "/jails/base11.2".into());
    rules.insert("ip4".into(), libc::JAIL_SYS_INHERIT.into());
    rules.insert("persist".into(), true.into());

    run(rules);

    // let mut path_key = CString::new("path").unwrap();
    // let mut path_value = CString::new("/jails/base11.2").unwrap();
    // let mut ip4_key = CString::new("ip4").unwrap();
    // let mut ip4_value = libc::JAIL_SYS_INHERIT;
    // let mut persist_key = CString::new("persist").unwrap();
    // let mut persist_value = true;

    // unsafe {

    //     let iov_path_key = iovec {
    //         iov_base: path_key.as_ptr() as *mut _,
    //         iov_len: path_key.as_bytes_with_nul().len(),
    //     };

    //     let t = iov_path_key.iov_base;

    //     let r = *t;
    //     println!("{:?}", r);

        // let iov_path_value = iovec {
        //     iov_base: path_value.as_ptr() as *mut _,
        //     iov_len: path_value.as_bytes_with_nul().len(),
        // };

        // let iov_persist_key = iovec {
        //     iov_base: persist_key.as_ptr() as *mut _,
        //     iov_len: persist_key.as_bytes_with_nul().len(),
        // };

        // let iov_persist_value = iovec {
        //     iov_base: &mut persist_value as *const _ as *mut _,
        //     iov_len: size_of_val(&persist_value),
        // };

        // let iov_ip4_key = iovec {
        //     iov_base: ip4_key.as_ptr() as *mut _,
        //     iov_len: ip4_key.as_bytes_with_nul().len(),
        // };

        // let iov_ip4_value = iovec {
        //     iov_base: &mut ip4_value as *const _ as *mut _,
        //     iov_len: size_of_val(&ip4_value),
        // };

        // let iov = [
        //     iov_path_key, iov_path_value,
        //     iov_persist_key, iov_persist_value,
        //     iov_ip4_key, iov_ip4_value,
        // ];

        // let niov = iov.len() as u32;
        // let flags = libc::JAIL_CREATE;

        // let jid = jail_set(iov.as_ptr() as *mut _, niov, flags);

        // println!("jid: {}", jid);

        // let mut err = *__error();
        // println!("{}", err);
        // let err_str = strerror(err);
        // let err_str = CString::from_raw(err_str);
        // println!("{:?}", err_str);


    // }

}
