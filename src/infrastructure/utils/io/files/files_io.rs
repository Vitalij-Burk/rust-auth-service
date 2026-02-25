use std::{
    fs::{read, remove_file, write},
    path::PathBuf,
};
use tracing::error;

#[derive(Debug, Clone)]
pub struct FileIO {
    file_path: PathBuf,
}

impl FileIO {
    pub fn new(path: &str) -> Self {
        Self {
            file_path: PathBuf::from(path),
        }
    }

    pub fn write(&self, data: &str) -> Result<(), std::io::Error> {
        let _ = write(&self.file_path, &data).map_err(|error| match error {
            err => {
                error!("IO error caused: {}", &err);
                err
            }
        })?;

        Ok(())
    }

    pub fn read(&self) -> Result<Vec<u8>, std::io::Error> {
        let data = read(&self.file_path).map_err(|error| match error {
            err => {
                error!("IO error caused: {}", &err);
                err
            }
        })?;

        Ok(data)
    }

    pub fn remove(&self) -> Result<(), std::io::Error> {
        let _ = remove_file(&self.file_path).map_err(|error| match error {
            err => {
                error!("IO error caused: {}", &err);
                err
            }
        })?;

        Ok(())
    }
}
