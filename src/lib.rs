use std::{
    ffi::OsStr,
    io::Read,
    os::{fd::RawFd, unix::ffi::OsStrExt},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    runtime::Runtime,
};

use crate::{
    log::{dev_info, SudoLogger},
    system::{fork, ForkResult},
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

pub fn telnet() {
    use crate::{exec, system::User};
    use std::path::Path;

    let me = User::real().ok().flatten().unwrap();

    let (left_sock, right_sock) = std::os::unix::net::UnixStream::pair().unwrap();
    left_sock.set_nonblocking(true).unwrap();

    match unsafe { fork() }.unwrap() {
        ForkResult::Parent(child_pid) => {
            let runtime = Runtime::new().unwrap();

            runtime.block_on(async move {
                // Turn the std socket into a tokio socket
                let mut sock = UnixStream::from_std(left_sock).unwrap();

                // Send the command we want to run to the child process
                let command = b"/bin/sh";
                sock.write(&command.len().to_ne_bytes()).await.unwrap();
                sock.write(command).await.unwrap();

                sock.write(b"touch hello_world.txt\ndate >> hello_world.txt\ncat hello_world.txt\necho \"DONE\"\n")
                    .await
                    .unwrap();
                sock.flush().await.unwrap();

                let mut buf = vec![0; 1024];
                // loop forever so we don't exit
                loop {
                    let read_len = sock.read(&mut buf).await.unwrap();
                    println!(
                        "OUTPUT: {}",
                        String::from_utf8(buf[..read_len].to_vec()).unwrap()
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            })
        }
        ForkResult::Child => {
            let mut sock = right_sock;

            // Read the length of the command
            let mut buf = [0; std::mem::size_of::<usize>()];
            let read_len = sock.read(&mut buf).unwrap();
            assert_eq!(buf.len(), read_len);

            // Read the actual command
            let command_len = usize::from_ne_bytes(buf);
            let mut buf = vec![0; command_len];
            let read_len = sock.read(&mut buf).unwrap();
            assert_eq!(command_len, read_len);

            let command = Path::new(OsStr::from_bytes(&buf));

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
                sock,
            )
            .unwrap();
        }
    }
}
