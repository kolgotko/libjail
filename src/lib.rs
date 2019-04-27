extern crate libc;
extern crate sysctl;
extern crate lazy_static;

use lazy_static::lazy_static;

use libc::iovec;
use libc::{jail_attach, jail_get, jail_remove, jail_set};
use sysctl::{Ctl, CtlType, CtlValue};

use std::collections::HashMap;
use std::convert::*;
use std::error::Error;
use std::io::Error as IoError;
use std::ffi::*;
use std::mem::{size_of_val};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops;
use std::fmt;
use std::num::*;

pub use libc::JAIL_SYS_INHERIT;
pub use libc::JAIL_SYS_DISABLE;
pub use libc::JAIL_SYS_NEW;

pub const SYSCTL_PREFIX: &str = "security.jail.param";

lazy_static! {
    pub static ref RULES_ALL: HashMap<String, RuleType>  = {

        let ctls = Ctl::new(&SYSCTL_PREFIX).unwrap();
        let mut hash_map: HashMap<String, RuleType> = HashMap::new();

        let ip4_rule = "ip4.addr";
        let ip6_rule = "ip6.addr";

        for ctl in ctls {

            let ctl = ctl.unwrap();

            let ctl_name = ctl.name().unwrap();
            let rule_name = ctl_name
                .trim_left_matches(SYSCTL_PREFIX)
                .trim_matches('.');
            let _ctl_value = ctl.value().unwrap();
            let ctl_type = ctl.value_type().unwrap();

            if rule_name == ip4_rule {

                hash_map.insert(rule_name.into(), RuleType::Ip4);

            } else if rule_name == ip6_rule {

                hash_map.insert(rule_name.into(), RuleType::Ip6);

            } else {

                hash_map.insert(rule_name.into(), ctl_type.into());

            }

        }

        hash_map

    };
}

#[derive(Debug)]
pub enum ConvertError {
    NulError(NulError),
    IntoStringError(IntoStringError),
    ParseIntError(ParseIntError),
}

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConvertError::NulError(error) => error.fmt(f),
            ConvertError::IntoStringError(error) => error.fmt(f),
            ConvertError::ParseIntError(error) => error.fmt(f),
        }
    }
}

impl Error for ConvertError {}

impl From<NulError> for ConvertError {
    fn from(value: NulError) -> Self {
        ConvertError::NulError(value)
    }
}

impl From<IntoStringError> for ConvertError {
    fn from(value: IntoStringError) -> Self {
        ConvertError::IntoStringError(value)
    }
}

impl From<ParseIntError> for ConvertError {
    fn from(value: ParseIntError) -> Self {
        ConvertError::ParseIntError(value)
    }
}

#[derive(Debug)]
pub enum LibJailError {
    IoError(IoError),
    SysctlError(sysctl::SysctlError),
    ConvertError(ConvertError),
    MismatchCtlType,
    MismatchCtlValue,
}

impl fmt::Display for LibJailError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for LibJailError {}

impl From<IoError> for LibJailError {
    fn from(error: IoError) -> Self {
        LibJailError::IoError(error)
    }
}

impl From<sysctl::SysctlError> for LibJailError {
    fn from(error: sysctl::SysctlError) -> Self {
        LibJailError::SysctlError(error)
    }
}

impl From<ConvertError> for LibJailError {
    fn from(value: ConvertError) -> Self {
        LibJailError::ConvertError(value)
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

impl TryFrom<String> for Val {
    type Error = ConvertError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Val::CString(CString::new(value)?))
    }

}

impl TryFrom<&str> for Val {
    type Error = ConvertError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Val::CString(CString::new(value)?))
    }
}

impl TryFrom<CString> for Val {
    type Error = ConvertError;

    fn try_from(value: CString) -> Result<Self, Self::Error> {
        Ok(Val::CString(value))
    }
}

impl TryFrom<i32> for Val {
    type Error = ConvertError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(Val::I32(value))
    }
}

impl TryFrom<u32> for Val {
    type Error = ConvertError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(Val::U32(value))
    }
}

impl TryFrom<u64> for Val {
    type Error = ConvertError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(Val::U64(value))
    }
}

impl TryFrom<Vec<u8>> for Val {
    type Error = ConvertError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Val::Buffer(value))
    }
}

impl TryFrom<bool> for Val {
    type Error = ConvertError;

    fn try_from(value: bool) -> Result<Self, Self::Error> {
        Ok(Val::Bool(value))
    }
}

impl TryFrom<Ipv4Addr> for Val {
    type Error = ConvertError;

    fn try_from(value: Ipv4Addr) -> Result<Self, Self::Error> {
        let numeric: u32 = value.into();
        Ok(Val::Ip4(numeric.swap_bytes()))
    }
}

impl TryFrom<Ipv6Addr> for Val {
    type Error = ConvertError;

    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        let numeric: u128 = value.into();
        Ok(Val::Ip6(numeric.swap_bytes()))
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
                    .map_err(|error| LibJailError::ConvertError(error.into()))
            },
            Val::CString(value) => {
                value.into_string()
                    .map_err(|error| LibJailError::ConvertError(error.into()))
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
        Err(IoError::last_os_error())?
    }
}

pub fn attach(jid: i32) -> Result<(), LibJailError> {

    let result = unsafe { jail_attach(jid) };

    if result == 0 {
        Ok(())
    } else {
        Err(IoError::last_os_error())?
    }

}

pub fn remove(jid: i32) -> Result<(), LibJailError> {

    let result = unsafe { jail_remove(jid) };

    if result == 0 {
        Ok(())
    } else {
        Err(IoError::last_os_error())?
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
                    .map_err(|error| LibJailError::ConvertError(error.into()));

                let size: usize = size_result?;
                let buffer: Vec<u8> = vec![0; size];
                Ok(Val::try_from(buffer)?)
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

            hash_map.insert(key.clone().try_into()?, value.unwrap());
            continue;

        }

        let value = get_val_by_type(&key);
        let key: Val = key.try_into()?;

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
            hash_map.insert("jid".try_into()?, jid.try_into()?);
        },
        Index::Name(name) => {
            hash_map.insert("name".try_into()?, name.try_into()?);
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
        Err(IoError::last_os_error())?
    }
}

pub fn get_rules_all(index: impl Into<Index>) -> Result<HashMap<String, OutVal>, LibJailError> {

    let names: Vec<String> = RULES_ALL.keys()
        .map(|key| key.clone())
        .collect();

    get_rules(index, names)

}
