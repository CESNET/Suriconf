use std::fs;
use std::io;
use std::path::{PathBuf};

use crate::{DEFAULT_CONFIG};

pub fn init(output: &PathBuf, force: bool) -> io::Result<()> {
    if output.exists() && !force {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to overwrite {:?} (use --force)", output),
        ));
    }
    fs::write(output, DEFAULT_CONFIG)?;
    Ok(())
}