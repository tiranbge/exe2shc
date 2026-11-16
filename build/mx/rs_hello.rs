use std::env;
fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    println!("RS-HELLO args={}", args.len());
    for (i, a) in args.iter().enumerate() {
        println!("  arg[{}]={}", i + 1, a);
    }
    std::process::exit(6);
}
