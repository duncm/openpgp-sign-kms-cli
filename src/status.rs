use anyhow::{Result, ensure};
use std::{fs::File, io::Write, os::fd::FromRawFd};
pub struct Status(Option<File>);
impl Status {
    pub fn new(fd: Option<i32>) -> Result<Self> {
        if let Some(fd) = fd {
            ensure!(fd >= 0, "status descriptor must be nonnegative");
            // Duplicate the inherited descriptor; never take ownership of the caller's fd.
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(Self(Some(unsafe { File::from_raw_fd(duplicate) })))
        } else {
            Ok(Self(None))
        }
    }
    pub fn emit(&mut self, line: &str) -> Result<()> {
        if let Some(f) = &mut self.0 {
            writeln!(f, "[GNUPG:] {line}")?;
            f.flush()?;
        }
        Ok(())
    }
}
