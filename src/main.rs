use std::path::PathBuf;

fn main() {
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
