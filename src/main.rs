use std::path::PathBuf;
use sgx::{Keyname, Keypolicy, Keyrequest};

mod sgx;

fn main() {
    println!("mrsigner egetkey: {:?}", egetkey(Keypolicy::MRSIGNER));
    println!("mrenclave egetkey: {:?}", egetkey(Keypolicy::MRENCLAVE));

    let key = "/sealed/key";
    let keyfile = PathBuf::from(key);
    if keyfile.exists() {
        let content = std::fs::read_to_string(&keyfile).unwrap();
        println!("read: {content}");
    } else {
        std::fs::write(key, "foobar").unwrap();
        println!("written");
    }
}

fn egetkey(keypolicy: Keypolicy) -> Result<[u8; 16], u32> {
    Keyrequest {
        keyname: Keyname::Seal as _,
        keypolicy,
        isvsvn: 0,
        cpusvn: [0; 16],
        attributemask: [0xffffffff; 2],
        miscmask: 1,
        keyid: [1; 32],
        _reserved1: 0,
        _reserved2: [0; 436],
    }
    .egetkey()
    .map(|x| x.0)
}
