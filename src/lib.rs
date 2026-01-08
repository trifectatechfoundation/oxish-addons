#[macro_use]
mod macros;
#[macro_use]
pub(crate) mod gettext;

pub(crate) mod common;
pub(crate) mod cutils;
pub(crate) mod defaults;
pub(crate) mod exec;
pub(crate) mod log;
pub(crate) mod pam;
pub(crate) mod sudoers;
pub(crate) mod system;

mod su;
mod sudo;
mod visudo;

pub use sudo::telnet;
