// jkcoxson

use std::fs::canonicalize;

fn main() {
    let root_path = std::env::current_dir().unwrap();
    let external_path = root_path.join("external");
    println!(
        "cargo:rustc-link-search={}",
        canonicalize(&external_path).unwrap().display()
    );
    println!("cargo:rustc-link-lib=static=altsign");

    // Set current directory to external
    std::env::set_current_dir(&external_path).unwrap();
    // Run clang
    let _ = std::process::Command::new("clang++")
        .arg("-o")
        .arg("altsign.o")
        .arg("-c")
        .arg("altsign.cpp")
        .arg("-std=c++17")
        .spawn()
        .unwrap();

    // Get list of .o files in AltSign-Linux
    let mut o_files = std::fs::read_dir("./AltSign-Linux").unwrap();
    let mut o_files_vec = Vec::new();
    while let Some(o_file) = o_files.next() {
        let o_file = o_file.unwrap();
        if match o_file.path().extension() {
            Some(ext) => ext,
            None => continue,
        } == "o"
        {
            o_files_vec.push(o_file.path());
        }
    }

    let _ = std::process::Command::new("ar")
        .arg("rcs")
        .arg("libaltsign.a")
        .arg("altsign.o")
        .args(o_files_vec)
        .spawn()
        .unwrap();
}
