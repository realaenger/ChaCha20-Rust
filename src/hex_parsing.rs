//! Used only for test cases

pub fn to_hex_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    strs.join("")
}

const HEX_VALUES: [char; 16] = ['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'];
pub fn from_hex_string(string: &str) -> Vec<u8> {
    let string = string.to_ascii_uppercase();
    let mut result = Vec::new();
    let mut odd = false;
    let mut byte = 0;
    for char in string.chars() {
        let value = HEX_VALUES.binary_search(&char).expect(
            &("Not hexadecimal: ".to_owned()+&char.to_string())
        ) as u8;
        if odd {
            byte |= value;
            result.push(byte);
            odd = false;
        } else {
            byte = value << 4;
            odd = true;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex() {
        let bytes: [u8; 6] = [0, 0, 2, 5, 7, 11];
        let hex = to_hex_string(&Vec::from(bytes));
        assert_eq!(hex, "00000205070B");
        let new_bytes = from_hex_string(&*hex);
        for i in 0..6 {
            assert_eq!(bytes[i], new_bytes[i]);
        }
    }
}