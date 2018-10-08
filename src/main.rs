extern crate libc;

use libc::{jail_get, jail_set, jail_attach};
use libc::iovec;
use libc::{__error, strerror};

use std::mem::size_of_val;
use std::ffi::{CStr, CString};
use std::collections::HashMap;
use std::convert::*;

use std::process::Command;

#[derive(Debug)]
enum LibJailError {
    CreateError {code: i32, message: String}
}

enum SetAction {
    Create,
    Update,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
enum Val {
    CString(CString),
    I32(i32),
    Bool(bool),
    Null,
}

impl From<String> for Val {
    fn from(value: String) -> Self {
        Val::CString(CString::new(value).unwrap())
    }
}

impl From<i32> for Val {
    fn from(value: i32) -> Self {
        Val::I32(value)
    }
}

impl From<bool> for Val {
    fn from(value: bool) -> Self {
        Val::Bool(value)
    }
}

impl<'a> From<&'a str> for Val {
    fn from(value: &str) -> Self {
        Val::CString(CString::new(value).unwrap())
    }
}

impl Val {

    fn to_iov(&self) -> libc::iovec {

        match &self {
            Val::CString(value) => {
                iovec {
                    iov_base: value.as_ptr() as *mut _,
                    iov_len: value.as_bytes_with_nul().len(),
                }
            },
            Val::I32(value) => {
                iovec {
                    iov_base: value as *const _ as *mut _,
                    iov_len: size_of_val(value),
                }
            },
            Val::Bool(value) => {
                iovec {
                    iov_base: value as *const _ as *mut _,
                    iov_len: size_of_val(value),
                }
            },
            Val::Null => {
                iovec {
                    iov_base: std::ptr::null::<i32>() as *mut _,
                    iov_len: 0,
                }
            },
        }

    }
}

fn set(mut rules: HashMap <Val, Val>, set_action: SetAction) -> Result<i32, LibJailError> {

    let mut iovec_vec = Vec::new();

    for (key, value) in rules.iter() {

        iovec_vec.push(key.to_iov());
        iovec_vec.push(value.to_iov());

    }

    let action = match set_action {
        SetAction::Create => libc::JAIL_CREATE,
        SetAction::Update => libc::JAIL_UPDATE,
    };

    println!("action {}", action);

    let jid = unsafe {
        jail_set(
            iovec_vec.as_slice().as_ptr() as *mut _,
            iovec_vec.len() as u32,
            action
        )
    };

    if jid > 0 {

        Ok(jid)

    } else {

        unsafe {
            let mut code = *__error();
            let message = CString::from_raw(strerror(code))
                .into_string()
                .unwrap();

            Err(LibJailError::CreateError{code: code, message: message})
        }

    }

}

fn attach(jid: i32) -> Result<(), LibJailError> {

    let result = unsafe { jail_attach(jid) };

    if result == 0 {
        Ok(())
    } else {

        unsafe {
            let mut code = *__error();
            let message = CString::from_raw(strerror(code))
                .into_string()
                .unwrap();

            Err(LibJailError::CreateError{ code: code, message: message })
        }

    }

}

fn main() {

    let mut rules: HashMap <Val, Val> = HashMap::new();

    rules.insert("path".into(), "/jails/freebsd112".into());
    rules.insert("name".into(), "freebsd112".into());
    rules.insert("ip4".into(), libc::JAIL_SYS_INHERIT.into());
    // rules.insert("persist".into(), false.into());

    println!("{:#?}", rules);

    let jid = set(rules, SetAction::Create).unwrap();
    attach(jid);

    Command::new("ls")
        .arg("/")
        .spawn()
        .expect("sh command failed to start");

}
