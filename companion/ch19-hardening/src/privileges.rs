use nix::unistd::{Gid, Uid, setgid, setgroups, setuid};

/// Drop supplementary groups, then GID, then UID before handling untrusted input.
pub fn drop_privileges(uid: u32, gid: u32) -> nix::Result<()> {
    setgroups(&[])?;
    setgid(Gid::from_raw(gid))?;
    setuid(Uid::from_raw(uid))?;
    Ok(())
}
