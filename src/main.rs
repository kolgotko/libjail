extern crate libc;
extern crate sysctl;

use std::collections::HashMap;
use std::process::Command;

mod libjail {

    use libc::iovec;
    use libc::{__error, strerror};
    use libc::{jail_attach, jail_get, jail_remove, jail_set};
    use sysctl::{Ctl, CtlType, CtlValue};

    use std::collections::HashMap;
    use std::convert::*;
    use std::error::Error;
    use std::ffi::{CStr, CString};
    use std::mem::{size_of, size_of_val};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::ops;
    use std::fmt;

    #[derive(Debug)]
    pub enum LibJailError {
        ExternalError { code: i32, message: String },
        SysctlError(sysctl::SysctlError),
        KindError(Box<Error>),
        MismatchCtlType,
        MismatchCtlValue,
    }

    impl fmt::Display for LibJailError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    impl Error for LibJailError {}

    impl From<sysctl::SysctlError> for LibJailError {
        fn from(error: sysctl::SysctlError) -> Self {
            LibJailError::SysctlError(error)
        }
    }

    impl From<std::num::ParseIntError> for LibJailError {
        fn from(error: std::num::ParseIntError) -> Self {
            LibJailError::KindError(error.into())
        }
    }

    #[derive(Debug)]
    pub struct Action(i32);

    impl Action {
        pub fn create() -> Self {
            Action(libc::JAIL_CREATE)
        }
        pub fn update() -> Self {
            Action(libc::JAIL_UPDATE)
        }
    }

    impl ops::Add<Action> for Action {
        type Output = Action;

        fn add(self, other: Action) -> Action {
            Action(self.0 | other.0)
        }
    }

    impl ops::Add<Modifier> for Action {
        type Output = Action;

        fn add(self, other: Modifier) -> Action {
            Action(self.0 | other.0)
        }
    }

    #[derive(Debug)]
    pub struct Modifier(i32);

    impl Modifier {
        pub fn attach() -> Self {
            Modifier(libc::JAIL_ATTACH)
        }
    }

    #[derive(Hash, Eq, PartialEq, Clone, Debug)]
    pub enum Val {
        Buffer(Vec<u8>),
        CString(CString),
        I32(i32),
        U32(u32),
        U128(u128),
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

    impl From<u32> for Val {
        fn from(value: u32) -> Self {
            Val::U32(value)
        }
    }

    impl From<Vec<u8>> for Val {
        fn from(value: Vec<u8>) -> Self {
            Val::Buffer(value)
        }
    }

    impl From<bool> for Val {
        fn from(value: bool) -> Self {
            Val::Bool(value)
        }
    }

    impl From<Ipv4Addr> for Val {
        fn from(value: Ipv4Addr) -> Self {
            let numeric: u32 = value.into();
            Val::U32(numeric.swap_bytes())
        }
    }

    impl From<Ipv6Addr> for Val {
        fn from(value: Ipv6Addr) -> Self {
            let numeric: u128 = value.into();
            Val::U128(numeric.swap_bytes())
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
                Val::Buffer(value) => iovec {
                    iov_base: value.as_ptr() as *mut _,
                    iov_len: value.len(),
                },
                Val::CString(value) => iovec {
                    iov_base: value.as_ptr() as *mut _,
                    iov_len: value.as_bytes_with_nul().len(),
                },
                Val::I32(value) => iovec {
                    iov_base: value as *const _ as *mut _,
                    iov_len: size_of_val(value),
                },
                Val::U32(value) => iovec {
                    iov_base: value as *const _ as *mut _,
                    iov_len: size_of_val(value),
                },
                Val::U128(value) => iovec {
                    iov_base: value as *const _ as *mut _,
                    iov_len: size_of_val(value),
                },
                Val::Bool(value) => iovec {
                    iov_base: value as *const _ as *mut _,
                    iov_len: size_of_val(value),
                },
                Val::Null => iovec {
                    iov_base: std::ptr::null::<i32>() as *mut _,
                    iov_len: 0,
                },
            }
        }
    }

    pub fn set(mut rules: HashMap<Val, Val>, action: Action) -> Result<i32, LibJailError> {
        let mut iovec_vec = Vec::new();

        for (key, value) in rules.iter() {
            iovec_vec.push(key.to_iov());
            iovec_vec.push(value.to_iov());
        }

        let jid = unsafe {
            jail_set(
                iovec_vec.as_slice().as_ptr() as *mut _,
                iovec_vec.len() as u32,
                action.0,
            )
        };

        if jid > 0 {
            Ok(jid)
        } else {
            unsafe {
                let mut code = *__error();
                let message = CString::from_raw(strerror(code)).into_string().unwrap();

                Err(LibJailError::ExternalError {
                    code: code,
                    message: message,
                })
            }
        }
    }

    pub fn attach(jid: i32) -> Result<(), LibJailError> {
        let result = unsafe { jail_attach(jid) };

        if result == 0 {
            Ok(())
        } else {
            unsafe {
                let mut code = *__error();
                let message = CString::from_raw(strerror(code)).into_string().unwrap();

                Err(LibJailError::ExternalError {
                    code: code,
                    message: message,
                })
            }
        }
    }

    pub fn remove(jid: i32) -> Result<(), LibJailError> {
        let result = unsafe { jail_remove(jid) };

        if result == 0 {
            Ok(())
        } else {
            unsafe {
                let mut code = *__error();
                let message = CString::from_raw(strerror(code)).into_string().unwrap();

                Err(LibJailError::ExternalError {
                    code: code,
                    message: message,
                })
            }
        }
    }

    pub fn get_rules<R>(jid: i32, rules: R) -> Result<HashMap<Val, Val>, LibJailError>
    where
        R: IntoIterator,
        R::Item: Into<String>,
    {
        let mut iovec_vec = Vec::new();
        let mut hash_map: HashMap<Val, Val> = HashMap::new();

        for rule in rules {
            let key: String = rule.into();
            let rule = format!("security.jail.param.{}", key);
            let ctl = Ctl::new(&rule)?;
            let ctl_name = ctl.name()?;
            let ctl_value = ctl.value()?;
            let ctl_type = ctl.value_type()?;

            let key: Val = key.into();
            let value: Result<Val, LibJailError> = match ctl_type {
                CtlType::Int => Ok(Val::I32(0)),
                CtlType::Ulong => Ok(Val::U32(0)),
                CtlType::String => {
                    if let CtlValue::String(v) = ctl_value {
                        let size: usize = v.parse()?;
                        let buffer: Vec<u8> = vec![0; size];
                        Ok(Val::from(buffer))
                    } else {
                        Err(LibJailError::MismatchCtlValue)
                    }
                }
                CtlType::Struct => {
                    if let CtlValue::Struct(v) = ctl_value {
                        let size: usize = v[0].into();

                        match size {
                            4 => Ok(Val::U32(0)),
                            16 => Ok(Val::U128(0)),
                            _ => Err(LibJailError::MismatchCtlValue),
                        }
                    } else {
                        Err(LibJailError::MismatchCtlValue)
                    }
                }
                _ => Err(LibJailError::MismatchCtlType),
            };

            hash_map.insert(key, value?);
        }

        hash_map.insert("jid".into(), jid.into());

        for (key, value) in hash_map.iter() {
            iovec_vec.push(key.to_iov());
            iovec_vec.push(value.to_iov());
        }

        let result = unsafe {
            jail_get(
                iovec_vec.as_slice().as_ptr() as *mut _,
                iovec_vec.len() as u32,
                0,
            )
        };

        if result >= 0 {
            Ok(hash_map)
        } else {
            unsafe {
                let mut code = *__error();
                let message = CString::from_raw(strerror(code)).into_string().unwrap();

                Err(LibJailError::ExternalError {
                    code: code,
                    message: message,
                })
            }
        }
    }

}

use self::libjail::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() {
    // let mut rules: HashMap<Val, Val> = HashMap::new();

    // rules.insert("path".into(), "/jails/freebsd112".into());
    // rules.insert("name".into(), "freebsd112".into());
    // rules.insert("ip4.addr".into(), "127.0.0.1".parse::<Ipv4Addr>().unwrap().into());
    // rules.insert("ip6.addr".into(), "::123".parse::<Ipv6Addr>().unwrap().into());
    // rules.insert("persist".into(), true.into());
    // rules.insert("nopersist".into(), Val::Null);

    // let jid = set(rules, Action::create() + Modifier::attach()).unwrap();

    let rules = get_rules(1, vec!["name", "ip4.addr", "jid", "ip6.addr"]).unwrap();
    println!("{:?}", rules);

    // rules.insert("jid".into(), 1.into());
    // // rules.insert("name".into(), "freebsd112".into());
    // rules.insert("name".into(), vec![0; 256].into());
    // // rules.insert("host.hostname".into(), "".into());

    // println!("{:#?}", rules);
}
