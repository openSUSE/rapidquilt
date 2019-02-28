// Licensed under the MIT license. See LICENSE.md

use std::io::{Error, Write};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::slice;
use std::fmt::Arguments;

#[cfg(feature = "iovec")]
use std::io::IoVec;


pub struct FallocateWriter<'a> {
    slice: &'a mut [u8],

    start: *mut libc::c_void,
    size: usize,
}

impl<'a> FallocateWriter<'a> {
    pub fn new(file: File, size: usize) -> Result<Self, Error> {
        let fd = file.as_raw_fd();

        let (slice, start) = unsafe {
            let err = libc::posix_fallocate(fd, 0, size as i64);
            if err != 0 {
                return Err(Error::from_raw_os_error(err));
            }

            let start = libc::mmap(ptr::null_mut(),
                                   size,
                                   libc::PROT_WRITE,
                                   libc::MAP_SHARED,
                                   fd,
                                   0
            );

            if start == libc::MAP_FAILED {
                return Err(Error::last_os_error());
            }

            let slice = slice::from_raw_parts_mut::<'a>(start as *mut u8, size);

            (slice, start)
        };

        Ok(Self {
            slice,
            start,
            size
        })
    }
}

impl<'a> Drop for FallocateWriter<'a> {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.start as *mut libc::c_void, self.size);
        }
    }
}

// We delegate all Write methods to the slice inside.
// TODO: Use delegation API when (and if) it gets into rust.
impl<'a> Write for FallocateWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.slice.write(buf)
    }

    #[cfg(feature = "iovec")]
    fn write_vectored(&mut self, bufs: &[IoVec]) -> Result<usize, Error> {
        self.slice.write_vectored(bufs)
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.slice.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.slice.write_all(buf)
    }

    fn write_fmt(&mut self, fmt: Arguments) -> Result<(), Error> {
        self.slice.write_fmt(fmt)
    }
}