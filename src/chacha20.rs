//! A ChaCha20 stream cipher implementation based on RFC7539. The cipher is fully online and can
//! encrypt or decrypt bytes on the fly not needing to buffer an entire message. This also implies
//! that the caller should increment the nonce when what is defined as a message is processed.
//!
//! The nonce will automatically increment if the counter reaches the max value, which it does after
//! processing 256 GB with the same nonce. If the nonce overflows, it will reset to 0, which means
//! that in theory this cipher may process 2^128 64-byte data chunks before the key stream repeats.
use std::convert::TryInto;

pub struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    key_stream: [u8; 64],
    ctr: u32,
    byte_ctr: usize,
}

/// The initial value for the counter. In RFC7539 this is set to 1
const INITIAL_CTR: u32 = 1;

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> ChaCha20 {
        let mut res = ChaCha20 {
            key: *key,
            nonce: *nonce,
            key_stream: [0; 64],
            ctr: INITIAL_CTR,
            byte_ctr: 0,
        };
        res.init_key_stream();
        res
    }

    /// Resets the counters and calls the ChaCha20 block function to fill the key_stream buffer
    fn init_key_stream(&mut self) {
        self.ctr = INITIAL_CTR;
        self.byte_ctr = 0;
        chacha20_block(&self.key, self.ctr, &self.nonce, &mut self.key_stream);
    }

    /// Increments the nonce and reinitializes the key stream
    pub fn increment_nonce(&mut self) {
        let mut b = [0; 16];
        b[..12].copy_from_slice(&self.nonce);
        let mut n = u128::from_le_bytes(b);
        n += 1;
        let b = n.to_le_bytes();
        self.nonce.copy_from_slice(&b[..12]);
        self.init_key_stream();
    }

    /// Processes (encryption/decryption is symmetric) input bytes into the output byte array
    pub fn key_stream(&mut self, bytes: &mut [u8]) {
        let len = bytes.len();
        for i in 0..len {
            bytes[i] = self.key_stream[self.byte_ctr];
            self.byte_ctr += 1;
            if self.byte_ctr == 64 {
                // If 'ctr' overflows the max value the keystream will repeat which breaks security.
                // Therefore the nonce is incremented as an alternative to panic! or error handling.
                if self.ctr == u32::MAX {
                    self.increment_nonce();
                } else {
                    self.ctr += 1;
                    self.byte_ctr = 0;
                    chacha20_block(&self.key, self.ctr, &self.nonce, &mut self.key_stream);
                }
            }
        }
    }

    /// Processes (encryption/decryption is symmetric) input bytes into the output byte array
    pub fn process_inplace(&mut self, bytes: &mut [u8]) {
        let len = bytes.len();
        for i in 0..len {
            bytes[i] = bytes[i] ^ self.key_stream[self.byte_ctr];
            self.byte_ctr += 1;
            if self.byte_ctr == 64 {
                // If 'ctr' overflows the max value the keystream will repeat which breaks security.
                // Therefore the nonce is incremented as an alternative to panic! or error handling.
                if self.ctr == u32::MAX {
                    self.increment_nonce();
                } else {
                    self.ctr += 1;
                    self.byte_ctr = 0;
                    chacha20_block(&self.key, self.ctr, &self.nonce, &mut self.key_stream);
                }
            }
        }
    }

    /// Processes (encryption/decryption is symmetric) input bytes into the output byte array
    pub fn process(&mut self, bytes: &[u8], out: &mut [u8]) {
        let mut len = bytes.len();
        if len > out.len() {
            len = out.len();
        }
        for i in 0..len {
            out[i] = bytes[i] ^ self.key_stream[self.byte_ctr];
            self.byte_ctr += 1;
            if self.byte_ctr == 64 {
                // If 'ctr' overflows the max value the keystream will repeat which breaks security.
                // Therefore the nonce is incremented as an alternative to panic! or error handling.
                if self.ctr == u32::MAX {
                    self.increment_nonce();
                } else {
                    self.ctr += 1;
                    self.byte_ctr = 0;
                    chacha20_block(&self.key, self.ctr, &self.nonce, &mut self.key_stream);
                }
            }
        }
    }
}

/// ChaCha20 block function
fn chacha20_block(key: &[u8; 32], ctr: u32, nonce: &[u8; 12], output: &mut [u8; 64]) {
    const CONST0: u32 = 0x61707865;
    const CONST1: u32 = 0x3320646e;
    const CONST2: u32 = 0x79622d32;
    const CONST3: u32 = 0x6b206574;
    let key0 = u32::from_le_bytes(key[0..4].try_into().unwrap());
    let key1 = u32::from_le_bytes(key[4..8].try_into().unwrap());
    let key2 = u32::from_le_bytes(key[8..12].try_into().unwrap());
    let key3 = u32::from_le_bytes(key[12..16].try_into().unwrap());
    let key4 = u32::from_le_bytes(key[16..20].try_into().unwrap());
    let key5 = u32::from_le_bytes(key[20..24].try_into().unwrap());
    let key6 = u32::from_le_bytes(key[24..28].try_into().unwrap());
    let key7 = u32::from_le_bytes(key[28..32].try_into().unwrap());
    let nonce0= u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    let nonce1 = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    let nonce2 = u32::from_le_bytes(nonce[8..12].try_into().unwrap());
    let state = [
        CONST0, CONST1, CONST2, CONST3,
        key0, key1, key2, key3,
        key4, key5, key6, key7,
        ctr, nonce0, nonce1, nonce2
    ];
    let mut x = state;
    for _i in 0..10 {
        q_round(&mut x, 0, 4, 8,12);
        q_round(&mut x, 1, 5, 9,13);
        q_round(&mut x, 2, 6,10,14);
        q_round(&mut x, 3, 7,11,15);
        q_round(&mut x, 0, 5,10,15);
        q_round(&mut x, 1, 6,11,12);
        q_round(&mut x, 2, 7, 8,13);
        q_round(&mut x, 3, 4, 9,14);
    }
    // "...we add the original input words to the output words, and serialize
    // the result by sequencing the words one-by-one in little-endian order."
    for i in 0..16 {
        output[4*i..4*i+4].copy_from_slice(&state[i].wrapping_add(x[i]).to_le_bytes());
    }
}

/// ChaCha20 quarter round function
fn q_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);  x[d] ^= x[a];  x[d] = x[d].rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);  x[b] ^= x[c];  x[b] = x[b].rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);  x[d] ^= x[a];  x[d] = x[d].rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);  x[b] ^= x[c];  x[b] = x[b].rotate_left(7);
}

#[cfg(test)]
mod tests {
    use crate::hex_parsing::from_hex_string;
    use super::*;

    #[test]
    fn test_ietf_2_2_1() {
        let a = 0x11111111;
        let b = 0x01020304;
        let c = 0x9b8d6f43;
        let d = 0x01234567;
        let mut x: [u32; 16] = [0; 16];
        x[0] = a;
        x[1] = b;
        x[2] = c;
        x[3] = d;
        q_round(&mut x, 0, 1, 2, 3);
        let exp_a: u32 = 0xea2a92f4;
        let exp_b: u32 = 0xcb1cf8ce;
        let exp_c: u32 = 0x4581472e;
        let exp_d: u32 = 0x5881c4bb;
        assert_eq!(x[0], exp_a);
        assert_eq!(x[1], exp_b);
        assert_eq!(x[2], exp_c);
        assert_eq!(x[3], exp_d);
    }

    #[test]
    fn test_ietf_2_3_2() {
        let mut key = [0; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let n = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];
        let ctr = 1;
        let mut out = [0; 64];
        chacha20_block(&key, ctr, &n, &mut out);
        let exp: [u32; 16] = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
            0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
            0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
            0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
        ];
        for i in 0..16 {
            assert_eq!(exp[i], u32::from_le_bytes(out[4*i..4*i+4].try_into().unwrap()));
        }
    }

    #[test]
    fn test_ietf_2_4_2() {
        let mut key = [0; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let n = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
        only one tip for the future, sunscreen would be it.";
        let mut chacha = ChaCha20::new(&key, &n);
        let expected = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b6\
        5c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e\
        52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";
        let mut result = [0; 114];
        //chacha.key_stream(&mut result);
        //println!("{}", to_hex_string(&result));
        chacha.process(plaintext, &mut result);
        let expected_arr = from_hex_string(expected);
        for i in 0..114 {
            assert_eq!(result[i], expected_arr[i]);
        }
    }
}