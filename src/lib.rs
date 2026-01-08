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

    exec::run_command(
        exec::RunOptions {
            command: Path::new("/bin/sh"),
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
    )
    .unwrap();
}
