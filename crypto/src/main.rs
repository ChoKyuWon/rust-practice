use std::iter::repeat;
use crypto::pbkdf2::pbkdf2;
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;
use rand::{thread_rng, Rng};

fn create_key(pass: String, dklen:usize, iter:u32) -> (Vec<u8>, Vec<u8>) {
    let password = pass.into_bytes();
    let mut result: Vec<u8> = repeat(0).take(dklen/8).collect();
    let mut mac = Hmac::new(Sha256::new(), &password[..]);
    let mut rng = thread_rng();
    let salt = rng.gen_iter::<u8>().take(dklen/8).collect::<Vec<u8>>();
    pbkdf2(&mut mac, &salt, iter, &mut result);
    return (result, salt)
}

fn main(){
    //let mut message = String::from("message!");
    let pass = String::from("secret");
    let (key, salt) = create_key(pass, 128, 0x3000);

    println!("key: {}", base64::encode(&key));
    println!("salt: {}", base64::encode(&salt));
}