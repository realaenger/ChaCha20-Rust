
use std::io::{Read, ErrorKind};
use std::io::Error;
use super::chacha20::ChaCha20;

pub struct DecryptingReader<R: Read> {
    decryptor: ChaCha20,
    source: R,
}

impl<R: Read> DecryptingReader<R> {

    /// Constructor using move semantics
    pub fn new(decryptor: ChaCha20, source: R) -> DecryptingReader<R> {
        DecryptingReader {
            decryptor,
            source
        }
    }
}

impl<R: Read> Read for DecryptingReader<R> {

    /// Reads bytes from the wrapped reader into the buffer and decrypts the result
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let res = self.source.read(buf);
        return match res {
            Ok(n) => {
                if n > buf.len() {
                    Err(Error::new(ErrorKind::Other, "n > buf.len()"))
                } else {
                    self.decryptor.process_inplace(&mut buf[..n]);
                    Ok(n)
                }
            },
            Err(e) => { Err(e) }
        }
    }
}

// Tested in conjunction with the writer in chacha20_writer.rs