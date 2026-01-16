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
    log::{dev_info, SudoLogger},
    system::{fork, term::PtyLeader, ForkResult, _exit},
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

pub fn run_command(mut socket: UnixStream) -> io::Result<()> {
    use crate::{exec, system::User};
    use std::path::Path;

    // Read the length of the command
    let mut buf = [0; std::mem::size_of::<usize>()];
    let read_len = socket.read(&mut buf)?;
    assert_eq!(buf.len(), read_len);

    // Read the actual command
    let command_len = usize::from_ne_bytes(buf);
    let mut buf = vec![0; command_len];
    let read_len = socket.read(&mut buf)?;
    assert_eq!(command_len, read_len);

    let command = Path::new(OsStr::from_bytes(&buf));

    let me = User::real().ok().flatten().unwrap();

    let pty = crate::exec::get_pty(&me).unwrap();

    if let ForkResult::Child = unsafe { fork() }.unwrap() {
        SudoLogger::new("sshd").into_global_logger();
        dev_info!("development logs are enabled");

        let _exit_reason = exec::run_command(
            exec::RunOptions {
                command,
                arguments: &[],
                arg0: None,
                chdir: None,
                is_login: true,
                umask: exec::Umask::Override(0o022),
                use_pty: true,
                noexec: false,
                user: &me,
                group: &me.primary_group().unwrap(),
            },
            vec![("OXI_SH", "1")],
            pty,
            socket,
        )
        .unwrap();

        _exit(0);
    }

    Ok(())
}
