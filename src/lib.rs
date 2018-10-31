
extern crate libc;
extern crate sysctl;
extern crate lazy_static;

use lazy_static::lazy_static;

use libc::iovec;
use libc::{__error, strerror};
use libc::{jail_attach, jail_get, jail_remove, jail_set};
use sysctl::{Ctl, CtlType, CtlValue};

use std::collections::HashMap;
use std::convert::*;
use std::error::Error;
use std::ffi::{CString, CStr};
use std::mem::{size_of_val};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops;
use std::fmt;

pub use libc::JAIL_SYS_INHERIT;

pub const SYSCTL_PREFIX: &str = "security.jail.param";

#[derive(Debug)]
pub enum LibJailError {
    ExternalError { code: i32, message: String },
    SysctlError(sysctl::SysctlError),
    ConversionError(Box<Error>),
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

#[derive(Debug)]
pub enum Index {
    Jid(i32),
    Name(String),
}

impl From<i32> for Index {
    fn from(value: i32) -> Self {
        Index::Jid(value)
    }
}

impl From<String> for Index {
    fn from(value: String) -> Self {
        Index::Name(value)
    }
}

impl From<&str> for Index {
    fn from(value: &str) -> Self {
        Index::Name(value.to_string())
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum OutVal {
    String(String),
    I32(i32),
    U32(u32),
    U64(u64),
    Bool(bool),
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
    Null,
}

impl OutVal {
    pub fn into_string(self) -> String {
        match self {
            OutVal::String(value) => value,
            _ => "".to_string(),
        }
    }
}

impl From<Val> for OutVal {
    fn from(val: Val) -> Self {
        match val {
            Val::I32(value) => OutVal::I32(value),
            Val::U32(value) => OutVal::U32(value),
            Val::U64(value) => OutVal::U64(value),
            Val::Bool(value) => OutVal::Bool(value),
            Val::CString(value) => {
                let value = value.into_string().unwrap_or("".to_string());
                OutVal::String(value)
            },
            Val::Ip4(value) => {
                let ip = Ipv4Addr::from(value.swap_bytes());
                OutVal::Ip4(ip)
            },
            Val::Ip6(value) => {
                let ip = Ipv6Addr::from(value.swap_bytes());
                OutVal::Ip6(ip)
            },
            Val::Buffer(buffer) => {

                let c_str = unsafe {
                    CStr::from_ptr(buffer.as_ptr() as *const _)
                };
                let string = c_str.to_owned();
                let string = string.into_string().unwrap_or("".to_string());
                OutVal::String(string)
            },
            _ => OutVal::I32(0),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum Val {
    Buffer(Vec<u8>),
    CString(CString),
    I32(i32),
    U32(u32),
    U64(u64),
    U128(u128),
    Bool(bool),
    Ip4(u32),
    Ip6(u128),
    Null,
}

impl From<String> for Val {
    fn from(value: String) -> Self {
        Val::CString(CString::new(value).unwrap())
    }
}

impl From<CString> for Val {
    fn from(value: CString) -> Self {
        Val::CString(value)
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

impl From<u64> for Val {
    fn from(value: u64) -> Self {
        Val::U64(value)
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
        Val::Ip4(numeric.swap_bytes())
    }
}

impl From<Ipv6Addr> for Val {
    fn from(value: Ipv6Addr) -> Self {
        let numeric: u128 = value.into();
        Val::Ip6(numeric.swap_bytes())
    }
}

impl From<&str> for Val {
    fn from(value: &str) -> Self {
        Val::CString(CString::new(value).unwrap())
    }
}

impl Val {
    fn into_string(self) -> Result<String, LibJailError> {

        match self {
            Val::Buffer(buffer) => {

                let string = unsafe {
                    CString::from_raw(buffer.as_ptr() as *mut _) 
                };

                string.into_string()
                    .map_err(|error| LibJailError::ConversionError(error.into()))
            },
            Val::CString(value) => {
                value.into_string()
                    .map_err(|error| LibJailError::ConversionError(error.into()))
            },
            Val::I32(value) => Ok(value.to_string()),
            Val::U32(value) => Ok(value.to_string()),
            Val::U64(value) => Ok(value.to_string()),
            Val::U128(value) => Ok(value.to_string()),
            Val::Bool(value) => Ok(value.to_string()),
            Val::Ip4(value) => {
                let ip: Ipv4Addr = value.swap_bytes().into();
                Ok(format!("{}", ip))
            },
            Val::Ip6(value) => {
                let ip: Ipv6Addr = value.swap_bytes().into();
                Ok(format!("{}", ip))
            },
            Val::Null => Ok("".to_string()),
        }

    }

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
            Val::U64(value) => iovec {
                iov_base: value as *const _ as *mut _,
                iov_len: size_of_val(value),
            },
            Val::U128(value) => iovec {
                iov_base: value as *const _ as *mut _,
                iov_len: size_of_val(value),
            },
            Val::Ip6(value) => iovec {
                iov_base: value as *const _ as *mut _,
                iov_len: size_of_val(value),
            },
            Val::Ip4(value) => iovec {
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

#[derive(Debug)]
pub enum RuleType {
    Int,
    Ulong,
    Ip4,
    Ip6,
    String,
    Unknown,
}

impl From<CtlType> for RuleType {
    fn from(value: CtlType) -> RuleType {
        match value {
            CtlType::Int => RuleType::Int,
            CtlType::String => RuleType::String,
            CtlType::Ulong => RuleType::Ulong,
            _ => RuleType::Unknown,
        }
    }
}

lazy_static! {
    pub static ref RULES_ALL: HashMap<String, RuleType>  = {

        let ctls = Ctl::new(&SYSCTL_PREFIX).unwrap();
        let mut hash_map: HashMap<String, RuleType> = HashMap::new();

        let ip4_rule = format!("{}.{}", SYSCTL_PREFIX, "ip4.addr");
        let ip6_rule = format!("{}.{}", SYSCTL_PREFIX, "ip6.addr");

        for ctl in ctls {

            let ctl = ctl.unwrap();

            let ctl_name = ctl.name().unwrap();
            let ctl_name = ctl_name.trim_matches('.');
            let ctl_value = ctl.value().unwrap();
            let ctl_type = ctl.value_type().unwrap();

            if ctl_name == ip4_rule {

                hash_map.insert(ctl_name.into(), RuleType::Ip4);

            } else if ctl_name == ip6_rule {

                hash_map.insert(ctl_name.into(), RuleType::Ip6);

            } else {

                hash_map.insert(ctl_name.into(), ctl_type.into());

            }

        }

        hash_map

    };
}

pub fn set(rules: HashMap<Val, Val>, action: Action) -> Result<i32, LibJailError> {
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
            let code = *__error();
            let message = CString::from_raw(strerror(code))
                .into_string()
                .map_err(|error| LibJailError::ConversionError(error.into()))?;

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
            let code = *__error();
            let message = CString::from_raw(strerror(code))
                .into_string()
                .map_err(|error| LibJailError::ConversionError(error.into()))?;

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
            let code = *__error();
            let message = CString::from_raw(strerror(code))
                .into_string()
                .map_err(|error| LibJailError::ConversionError(error.into()))?;

            Err(LibJailError::ExternalError {
                code: code,
                message: message,
            })
        }
    }
}

fn get_val_by_key(key: &str) -> Option<Val> {

    if key == "ip4.addr" {

        Some(Val::Ip4(0))

    } else if key == "ip6.addr" {

        Some(Val::Ip6(0))

    } else if key == "ip4" {

        Some(Val::I32(0))

    } else if key == "ip6" {

        Some(Val::I32(0))

    } else { None }

}

fn get_val_by_type(key: &str) -> Result<Val, LibJailError> {

    let rule = format!("{}.{}", SYSCTL_PREFIX, key);

    let ctl = Ctl::new(&rule)?;
    let _ctl_name = ctl.name()?;
    let ctl_value = ctl.value()?;
    let ctl_type = ctl.value_type()?;

    match ctl_type {
        CtlType::Int => Ok(Val::I32(0)),
        CtlType::Ulong => Ok(Val::U64(0)),
        CtlType::String => {
            if let CtlValue::String(v) = ctl_value {
                let size_result = v.parse::<usize>();
                let size_result = size_result
                    .map_err(|error| LibJailError::ConversionError(error.into()));

                let size: usize = size_result?;
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
    }
}

pub fn get_rules<R>(index: impl Into<Index>, keys: R) -> Result<HashMap<String, OutVal>, LibJailError>
where
    R: IntoIterator,
    R::Item: Into<String>,
{
    let mut iovec_vec = Vec::new();
    let mut hash_map: HashMap<Val, Val> = HashMap::new();

    for key in keys {

        let key: String = key.into();
        let value = get_val_by_key(&key);

        if value.is_some() {

            hash_map.insert(key.clone().into(), value.unwrap());
            continue;

        }

        let value = get_val_by_type(&key);
        let key: Val = key.into();

        match value {

            Ok(value) => {
                hash_map.insert(key, value);
            },
            Err(LibJailError::SysctlError(sysctl::SysctlError::NoReadAccess)) => {

                continue;

            },
            Err(err) => return Err(err),

        }

    }

    match index.into() {
        Index::Jid(jid) => {
            hash_map.insert("jid".into(), jid.into());
        },
        Index::Name(name) => {
            hash_map.insert("name".into(), name.into());
        },
    }

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

        let mut out_hash_map: HashMap<String, OutVal> = HashMap::new();

        for (key, value) in hash_map.iter_mut() {

            out_hash_map.insert(
                key.clone().into_string()?,
                value.clone().into()
                );

        }

        Ok(out_hash_map)

    } else {
        unsafe {
            let code = *__error();
            let message = CString::from_raw(strerror(code))
                .into_string()
                .map_err(|error| LibJailError::ConversionError(error.into()))?;

            Err(LibJailError::ExternalError {
                code: code,
                message: message,
            })
        }
    }
}

pub fn get_rules_all(index: impl Into<Index>) -> Result<HashMap<String, OutVal>, LibJailError> {

    let ctl_root = Ctl::new(SYSCTL_PREFIX)?;
    let mut names: Vec<String> = Vec::new();

    for ctl in ctl_root {

        let ctl = ctl?;
        let ctl_name = ctl.name()?;
        let name: &str = ctl_name.as_str()
            .trim_left_matches(SYSCTL_PREFIX)
            .trim_matches('.');

        names.push(name.to_string());

    }

    get_rules(index, names)

}
