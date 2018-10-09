extern crate libc;

use std::collections::HashMap;
use std::process::Command;

mod libjail {

    use libc::iovec;
    use libc::{jail_get, jail_set, jail_attach, jail_remove};
    use libc::{__error, strerror};

    use std::mem::size_of_val;
    use std::ffi::{CStr, CString};
    use std::collections::HashMap;
    use std::convert::*;
    use std::ops;

    #[derive(Debug)]
    pub enum LibJailError {
        CreateError {code: i32, message: String}
    }

    #[derive(Debug)]
    pub struct Action(i32);

    impl Action {
        pub fn create() -> Self { Action(libc::JAIL_CREATE) }
        pub fn update() -> Self { Action(libc::JAIL_UPDATE) }
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
        pub fn attach() -> Self { Modifier(libc::JAIL_ATTACH) }
    }

    #[derive(Hash, Eq, PartialEq, Clone, Debug)]
    pub enum Val {
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

    pub fn set(mut rules: HashMap <Val, Val>, action: Action) -> Result<i32, LibJailError> {

        let mut iovec_vec = Vec::new();

        for (key, value) in rules.iter() {

            iovec_vec.push(key.to_iov());
            iovec_vec.push(value.to_iov());

        }

        let jid = unsafe {
            jail_set(
                iovec_vec.as_slice().as_ptr() as *mut _,
                iovec_vec.len() as u32,
                action.0
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

                Err(LibJailError::CreateError{ code: code, message: message })
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
                let message = CString::from_raw(strerror(code))
                    .into_string()
                    .unwrap();

                Err(LibJailError::CreateError{ code: code, message: message })
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
                let message = CString::from_raw(strerror(code))
                    .into_string()
                    .unwrap();

                Err(LibJailError::CreateError{ code: code, message: message })
            }

        }

    }
}

use self::libjail::*;

use std::thread;
use std::os::unix::net::{UnixStream, UnixListener};

fn handle_client(stream: UnixStream) {
    println!("new client");
}

fn main() {

    let listener = UnixListener::bind("/tmp/container.sock").unwrap();

    let mut rules: HashMap <Val, Val> = HashMap::new();

    rules.insert("path".into(), "/jails/freebsd112".into());
    rules.insert("name".into(), "freebsd112".into());
    rules.insert("ip4".into(), libc::JAIL_SYS_INHERIT.into());
    // rules.insert("persist".into(), true.into());
    // rules.insert("nopersist".into(), Val::Null);

    println!("{:#?}", rules);

    let jid = set(rules, Action::create() + Modifier::attach()).unwrap();
    // attach(jid);

    Command::new("ls")
        .arg("/")
        .spawn()
        .expect("sh command failed to start");


    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                /* connection succeeded */
                thread::spawn(|| handle_client(stream));
            }
            Err(err) => {
                /* connection failed */
                break;
            }
        }
    }

}
