use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
pub struct Output {
    temp: NamedTempFile,
    path: Option<PathBuf>,
    overwrite: bool,
}
impl Output {
    pub fn prepare(path: Option<PathBuf>, input: Option<&Path>, overwrite: bool) -> Result<Self> {
        if let Some(p) = &path {
            if let (Ok(out), Some(input)) = (fs::metadata(p), input)
                && let Ok(input) = fs::metadata(input)
            {
                use std::os::unix::fs::MetadataExt;
                ensure!(
                    (out.dev(), out.ino()) != (input.dev(), input.ino()),
                    "output aliases input"
                );
            }
            ensure!(
                overwrite || fs::symlink_metadata(p).is_err(),
                "output already exists: {}",
                p.display()
            );
            ensure!(
                !fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()),
                "output must not be a symlink"
            );
        }
        let temp = if let Some(p) = &path {
            NamedTempFile::new_in(
                p.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?
        } else {
            NamedTempFile::new()?
        };
        Ok(Self {
            temp,
            path,
            overwrite,
        })
    }
    pub fn writer(&mut self) -> &mut File {
        self.temp.as_file_mut()
    }
    pub fn finish(mut self) -> Result<()> {
        self.temp.flush()?;
        if let Some(path) = self.path {
            self.temp.as_file().sync_all()?;
            if self.overwrite {
                self.temp.persist(path).context("publishing output")?;
            } else {
                self.temp
                    .persist_noclobber(path)
                    .context("publishing output")?;
            }
        } else {
            use std::io::{Seek, SeekFrom};
            self.temp.seek(SeekFrom::Start(0))?;
            let mut stdout = io::stdout().lock();
            io::copy(&mut self.temp, &mut stdout)?;
            stdout.flush()?;
        }
        Ok(())
    }
}
