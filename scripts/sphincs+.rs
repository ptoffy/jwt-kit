use base64::engine::{general_purpose, Engine};
use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes, Signer};
use hex::decode;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::to_string;

#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
}

#[derive(Serialize, Deserialize)]
struct Payload {
    sub: String,
    name: String,
    admin: bool,
    exp: u64,
}

struct TestRng {
    data: Vec<Vec<u8>>,
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let x = self.data.pop().expect("TestRng problem");
        out.copy_from_slice(&x)
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

impl TestRng {
    fn new() -> Self {
        TestRng { data: Vec::new() }
    }

    fn push(&mut self, new_data: &[u8]) {
        let x = new_data.to_vec();
        self.data.push(x);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a header and payload
    let header = Header {
        alg: "SPHINCS+128s".to_string(),
        typ: "JWT".to_string(),
    };

    let payload = Payload {
        sub: "vapor".to_string(),
        name: "Foo".to_string(),
        admin: false,
        exp: 2000000000,
    };

    // Encode the header and payload
    let header_str = to_string(&header).unwrap();
    let payload_str = to_string(&payload).unwrap();

    let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header_str.as_bytes());
    let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload_str.as_bytes());

    // Serialize the header and payload
    let message = format!("{}.{}", header_b64, payload_b64);

    // Create public and private keys with a seed
    let seed: [u8; 48] = [
        0x3f, 0x00, 0xff, 0x1c, 0x9c, 0x5e, 0xaa, 0xfe, 0x09, 0xc3, 0x08, 0x0d, 0xac, 0xc1, 0x83,
        0x2b, 0x35, 0x8a, 0x40, 0xd5, 0xf3, 0x8c, 0xcb, 0x97, 0xe3, 0xa6, 0xc1, 0xb3, 0xb7, 0x5f,
        0x42, 0xab, 0x17, 0x34, 0xe6, 0x41, 0x89, 0xe1, 0x57, 0x93, 0x12, 0x74, 0xdb, 0xbd, 0xb4,
        0x28, 0xd0, 0xfb,
    ];
    let mut rng = TestRng::new();

    let sk_seed = &seed[0..16];
    let sk_prf = &seed[16..32];
    let pk_seed = &seed[32..48];

    rng.push(&pk_seed); // Use the pk_seed as opt_random so we have a deterministic keygen
    rng.push(&pk_seed);
    rng.push(&sk_prf);
    rng.push(&sk_seed);
    let (pk1, sk) = slh_dsa_sha2_128s::try_keygen_with_rng_vt(&mut rng).expect("Keygen failed");

    // Sign the message
    let signature = sk
        .try_sign_with_rng_ct(&mut rng, message.as_bytes(), true)
        .unwrap();

    // Encode the signature and create the JWT
    let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&signature);
    let jwt = format!("{}.{}", message, signature_b64);

    println!("{}", jwt);

    // Create 48 byte u8 seed from sk_seed, sk_prf, and pk_seed
    let mut combined = Vec::with_capacity(48);
    combined.extend_from_slice(&sk_seed);
    combined.extend_from_slice(&sk_prf);
    combined.extend_from_slice(&pk_seed);

//    println!("Combined: {:?}", combined);
//    println!("Private key bytes: {:?}", sk.into_bytes());

    Ok(())
}
