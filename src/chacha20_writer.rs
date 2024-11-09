
use std::io::{Write, ErrorKind};
use std::io::Error;
use crate::chacha20::ChaCha20;

pub struct EncryptingWriter<W: Write> {
    encryptor: ChaCha20,
    sink: W,
    key_buffer: [u8; 1],
    has_buffered: bool
}

impl<W: Write> EncryptingWriter<W> {

    /// Constructor using move semantics
    pub fn new(encryptor: ChaCha20, sink: W) -> EncryptingWriter<W> {
        EncryptingWriter {
            encryptor,
            sink,
            key_buffer: [0],
            has_buffered: false
        }
    }
}

impl<W: Write> Write for EncryptingWriter<W> {

    /// Simple write wrapper processing byte after byte with a write call. To avoid performance
    /// penalties consider pre-wrapping the sink with a buffered writer
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        for n in 0..buf.len() {
            if !self.has_buffered {
                self.encryptor.key_stream(&mut self.key_buffer);
                self.has_buffered = true;
            }
            let encrypted = &self.key_buffer[0] ^ buf[n];
            let res = self.sink.write(&[encrypted]);
            match res {
                Ok(x) => {
                    if x > 1 {
                        return Err(Error::new(ErrorKind::Other, "wrote too much"));
                    } else if x == 0 {
                        return Ok(n);
                    } else {
                        self.has_buffered = false;
                    }
                },
                Err(e) => { return Err(e); }
            }
        }
        Ok(buf.len())
    }

    /// The flush() method is called on the wrapped sink
    fn flush(&mut self) -> Result<(), Error> {
        self.sink.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use crate::chacha20_reader::DecryptingReader;
    use crate::hex_parsing::from_hex_string;

    #[test]
    fn test_ietf_a_2_2() {
        let mut key = [0; 32];
        key[31] = 1;
        let mut n = [0; 12];
        n[11] = 2;
        let plaintext = b"Any submission to the IETF intended by the Contributor for publ\
        ication as all or part of an IETF Internet-Draft or RFC and any statement made within the c\
        ontext of an IETF activity is considered an \"IETF Contribution\". Such statements include \
        oral statements in IETF sessions, as well as written and electronic communications made at \
        any time or place, which are addressed to";
        let chacha = ChaCha20::new(&key, &n);
        let mut stream = Vec::new();
        let mut wrapped = EncryptingWriter::new(chacha, &mut stream);
        let expected = "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a979\
        48bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e\
        20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87b\
        ea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7\
        f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765\
        989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b19\
        3bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2\
        dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7a\
        c61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221";
        let res = wrapped.write(plaintext);
        assert_eq!(res.is_ok(), true);
        let expected_arr = from_hex_string(expected);
        for i in 0..expected_arr.len() {
            assert_eq!(stream[i], expected_arr[i]);
        }
        // Tests decryption too
        let chacha = ChaCha20::new(&key, &n);
        let mut decry = [0; 375];
        let x = &mut stream.as_slice();
        let mut wrapped = DecryptingReader::new(chacha, x);
        wrapped.read(&mut decry).unwrap();
        for i in 0..375 {
            assert_eq!(decry[i], plaintext[i]);
        }
    }
}