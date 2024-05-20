use std::io::{self, Read, BufReader};
use std::{env};
use std::fs::{File};
use sha2::{Sha256, Digest};

fn main() {
    let args: Vec<String> = env::args().collect();
    if &args[1].to_lowercase() != "-s" && &args[1].to_lowercase() != "-c" && &args[1].to_lowercase() != "-h" {
        println!("Use hasher -h for help");
        return;
    }
    if &args[1] == "-h" {
        println!("Usage: hasher [option] [input_file] <sha256>");
        println!("-s prints the computed sha256 checksum");
        println!("-c compares the provided checksum in the <sha256> section to the file's computed checksum");
        println!("-c also tries to look after a .sha256 file, if it's found it's going to read that instead of the <sha256>");
        return;
    }
    if args.len() < 3 {
        println!("Use hasher -h for help");
        return;
    }


    let file_name = &args[2];

    let file = match File::open(file_name) {
        Ok(file) => file,
        Err(_) => {
            println!("Failed to open the file {}", &file_name);
            return;
        }
    };
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let bytes_read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => {
                println!("Failed to read the file");
                return;
            }
        };
        hasher.update(&buffer[..bytes_read]);
    }

    let computed_hash = format!("{:x}", hasher.finalize());
    let lower_computed_hash = computed_hash.to_lowercase();
    let sha256_file_name = format!("{}.sha256", file_name);

    if &args[1] == "-s" {
        println!("{lower_computed_hash}");
        return;
    }

    if &args[1] == "-c" {
        if args.len() == 4 && args[3].len() == 64 {
            let arg_hash = &args[3];
            let lower_arg_hash = arg_hash.to_lowercase();
            println!("{lower_computed_hash}");
            println!("{lower_arg_hash}");
            if lower_computed_hash == lower_arg_hash {
                println!("Checksums match!");
            } else {
                println!("Checksums do not match!");
            }
        } else {
            if let Ok(sha256_content) = read_sha256_file(&sha256_file_name) {
                let hash_from_external_file: String = sha256_content.trim().chars().take(64).collect();
                let lower_hash_from_external_file = hash_from_external_file.to_lowercase();
                println!("{lower_computed_hash}");
                println!("{lower_hash_from_external_file}");
                if lower_hash_from_external_file == lower_computed_hash {
                    println!("Checksums match!");
                } else {
                    println!("Checksums do not match!");
                }
            } else {
                println!("Failed to read the .sha256 file")
            }
        }
    }

}

fn read_sha256_file(file_name: &str) -> io::Result<String> {
    let mut sha256_file = File::open(file_name)?;
    let mut sha256_content = String::new();
    sha256_file.read_to_string(&mut sha256_content)?;
    Ok(sha256_content)
}