use sha2::*;

pub fn hmac_sha256(message: &str, secret_key: &str) -> String
{
  let mut key = secret_key.as_bytes().to_vec();
  let message = message.as_bytes().to_vec();
  if key.len() > 64
  {
    key = sha256_bytes(&key);
  }
  if key.len() < 64
  {
    key.extend(vec![0 as u8; 64 - key.len()]);
  }
  let mut o_key_pad = vec![0 as u8; key.len()];
  let mut i_key_pad = vec![0 as u8; key.len()];
  let switch_1 = "\\".as_bytes()[0];
  let switch_2 = "6".as_bytes()[0];
  for i in 0..key.len()
  {
    o_key_pad[i] = key[i] ^ switch_1;
    i_key_pad[i] = key[i] ^ switch_2;
  }
  let mut i_key_pad_concat_message = std::vec::Vec::<u8>::new();
  i_key_pad_concat_message.extend(&i_key_pad);
  i_key_pad_concat_message.extend(&message);

  let mut hashed_i = sha256_bytes(&i_key_pad_concat_message);

  o_key_pad.append(&mut hashed_i);
  println!("{:?}", o_key_pad);

  let hash = sha256_bytes(&o_key_pad);
  let mut hex = vec![0 as u32; hash.len()/4];
  for x in 0..hash.len()
  {
    hex[x/4] += (hash[x] as u32) << (24 - (x % 4)*8);
  }
  let output = vec![format!("{:08X}", hex[0]),
                   format!("{:08X}", hex[1]),
                   format!("{:08X}", hex[2]),
                   format!("{:08X}", hex[3]),
                   format!("{:08X}", hex[4]),
                   format!("{:08X}", hex[5]),
                   format!("{:08X}", hex[6]),
                   format!("{:08X}", hex[7])].join("");
  output
}

#[cfg(test)]
mod tests
{
  use super::*;

  #[test]
  fn hmac_sha256_tests()
  {
      assert_eq!(hmac_sha256("jakfosdu9f012ej03nf3r80i2jf", "rm21kogj9HH($YHNINIFY"), "F0456C8CE42EA69816CF04AA89166D318C0ABF35486076E1FA423B093AB817B7");
      assert_eq!(hmac_sha256("1234567890".repeat(8).as_str(), "rm21kogj9HH($YHNINIFY"), "79C17A90DDCC83B9003D8D75FAAF84F80B605EA97847F24ED60BBD0E03B7F13A");
      assert_eq!(hmac_sha256("abcdefghijklmn$@!@#$%%^&&**()_+=_-1234567890".repeat(8).as_str(), "rm21kogj9HH($YHNINIFY"), "7ADF6FC2B27EFC8DEC5EC086DC68E8AC7F2FB478E64850B131B35DF429EBD514");
      assert_eq!(hmac_sha256("0", "rm21kogj9HH($YHNINIFY"), "78D2950307B633C4F388E4F3282FE53E35DE4E53DC666A5EB15369C7212F6DB7");
      assert_eq!(hmac_sha256("fasjkdfq890r12jnm$#!$#!FDQCDEQ", "abcdefghijklmopqrstuvwxyzz!@#$%^&*()_+=-;:/.,"), "ADC79FAE419F9EDD5063396EEFB7A9E3B58CA7049219BE66A7B0BAC04E240291");
      assert_eq!(hmac_sha256("a", "abcdefghijklmopqrstuvwxyzz!@#$%^&*()_+=-;:/.,"), "DAF961DA6F28B041A7B0EED51D6006432EB53579DD80997379837D8D1919C479");
      assert_eq!(hmac_sha256("a", "a"), "3ECF5388E220DA9E0F919485DEB676D8BEE3AEC046A779353B463418511EE622");      
  }
}
