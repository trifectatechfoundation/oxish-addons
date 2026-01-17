#![allow(unused)]
use std::{
    ffi::OsStr,
    io::{self, Read, Write},
    os::{
        fd::{AsFd, AsRawFd, RawFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    task::{ready, Poll},
};

use crate::{
    cutils::cerr,
    log::{SudoLogger, dev_info},
    system::{_exit, ForkResult, fork, term::{Pty, PtyLeader}},
};

#[macro_use]
mod macros;
#[macro_use]
pub(crate) mod gettext;

pub(crate) mod common;
pub(crate) mod cutils;
pub(crate) mod exec;
pub(crate) mod log;
pub(crate) mod system;

pub fn get_pty() -> io::Result<Pty> {
    let me = system::User::real().ok().flatten().unwrap();

    crate::exec::get_pty(&me)
}
