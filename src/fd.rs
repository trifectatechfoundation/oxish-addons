use std::{
    io,
    os::{
        fd::{AsRawFd, RawFd},
        unix::net::UnixStream as StdUnixStream,
    },
    ptr::null_mut,
};

use tokio::{io::Interest, net::UnixStream};

fn make_msghdr() -> libc::msghdr {
    let mut iov = libc::iovec {
        iov_base: [0].as_mut_ptr().cast(),
        iov_len: 1,
    };

    let mut buf = [0; unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) } as _];

    libc::msghdr {
        msg_name: null_mut(),
        msg_namelen: 0,
        msg_iov: &raw mut iov,
        msg_iovlen: 1,
        msg_control: buf.as_mut_ptr().cast(),
        msg_controllen: buf.len(),
        msg_flags: 0,
    }
}

pub(crate) fn send_fd(socket: &mut StdUnixStream, mut fd: RawFd) -> io::Result<()> {
    let mut msgh = make_msghdr();

    let cmsgp = unsafe { libc::CMSG_FIRSTHDR(&raw mut msgh) };

    unsafe { (*cmsgp).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as _ };
    unsafe { (*cmsgp).cmsg_level = libc::SOL_SOCKET };
    unsafe { (*cmsgp).cmsg_type = libc::SCM_RIGHTS };
    unsafe {
        libc::memcpy(
            libc::CMSG_DATA(cmsgp).cast(),
            (&raw mut fd).cast(),
            size_of::<RawFd>(),
        )
    };

    if unsafe { libc::sendmsg(socket.as_raw_fd(), &raw mut msgh, 0) } == -1 {
        return Err(io::Error::last_os_error().into());
    }

    Ok(())
}

pub(crate) async fn recv_fd(socket: &mut UnixStream) -> anyhow::Result<RawFd> {
    let mut msgh = make_msghdr();

    socket
        .async_io(Interest::READABLE, || {
            if unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut msgh, 0) } == -1 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        })
        .await?;

    let cmsgp = unsafe { libc::CMSG_FIRSTHDR(&raw mut msgh) };

    anyhow::ensure!(!cmsgp.is_null());
    anyhow::ensure!(unsafe { (*cmsgp).cmsg_len == libc::CMSG_LEN(size_of::<RawFd>() as _) as _ });
    anyhow::ensure!(unsafe { (*cmsgp).cmsg_level == libc::SOL_SOCKET });
    anyhow::ensure!(unsafe { (*cmsgp).cmsg_type == libc::SCM_RIGHTS });

    let mut fd: RawFd = 0;

    unsafe {
        libc::memcpy(
            (&raw mut fd).cast(),
            libc::CMSG_DATA(cmsgp).cast(),
            size_of::<RawFd>(),
        )
    };

    Ok(fd)
}
