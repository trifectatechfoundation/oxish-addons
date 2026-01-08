use std::{ffi::CStr, fmt::Display, num::ParseIntError, str::FromStr};

/// Represents a group ID in the system.
///
/// `GroupId` is transparent because the memory mapping should stay the same as the underlying
/// type, so we can safely cast as a pointer.
/// See the implementation in `system::mod::set_target_user`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(libc::gid_t);

/// Represents a user ID in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserId(libc::uid_t);

/// Represents a process ID in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(libc::pid_t);

/// Represents a device ID in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(libc::dev_t);

impl GroupId {
    pub fn new(id: libc::gid_t) -> Self {
        Self(id)
    }

    pub fn inner(&self) -> libc::gid_t {
        self.0
    }
}

impl UserId {
    pub fn new(id: libc::uid_t) -> Self {
        Self(id)
    }

    pub fn inner(&self) -> libc::uid_t {
        self.0
    }

    pub const ROOT: Self = Self(0);
}

impl ProcessId {
    pub fn new(id: libc::pid_t) -> Self {
        Self(id)
    }

    pub fn inner(&self) -> libc::pid_t {
        self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0 != 0
    }
}

impl DeviceId {
    pub fn new(id: libc::dev_t) -> Self {
        Self(id)
    }

    pub fn inner(&self) -> libc::dev_t {
        self.0
    }
}

impl Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for ProcessId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for GroupId {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<libc::gid_t>().map(GroupId::new)
    }
}

impl FromStr for UserId {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<libc::uid_t>().map(UserId::new)
    }
}
