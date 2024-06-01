use std::io::{self, Read, BufReader};
use std::{env};
use std::fs::{File};
use sha2::{Sha256, Digest};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1].is_empty() {
        println!("Use hasher -h for help");
        return;
    }
    let arg = &args[1].to_lowercase();
    if arg != "-s" && arg != "-c" && arg != "-h" {
        println!("Use hasher -h for help");
        return;
    }
    if &args[1] == "-h" {
        println!("Usage: hasher [option] [input_file] [sha256_hash]");
        println!("-s prints the computed sha256 checksum");
        println!("-c compares the computed checksum to the [sha256_hash] where you can input your own hash or a filename");
        println!("-c also tries to look after a .sha256 file if nothing is typed in the [sha256_hash] section");
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

    if &args[1] == "-c" && args.len() == 4 {
        if args[3].len() == 64 {
            let arg_hash = &args[3];
            let lower_arg_hash = arg_hash.to_lowercase();
            println!("{lower_computed_hash}");
            println!("{lower_arg_hash}");
            if lower_computed_hash == lower_arg_hash {
                println!("Checksums match!");
            } else {
                println!("Checksums do not match!");
            }
        } 
    if &args[1] == "-c" && args.len() == 4 && args[3].len() > 3 && args[3].len() < 60 {
              let file_name2 = &args[3];
              let file2 = match File::open(file_name2) {
                  Ok(file2) => file2,
                  Err(_) => {
                      println!("Failed to open the second file {}", &file_name2);
                      return;
                  }
              };
              let mut reader2 = BufReader::new(file2);
              let mut hasher2 = Sha256::new();
              let mut buffer2 = [0; 8192];
              loop {
                  let bytes_read2 = match reader2.read(&mut buffer2) {
                      Ok(0) => break,
                      Ok(n) => n,
                      Err(_) => {
                          println!("Failed to read the second file");
                          return;
                      }
                  };
                  hasher2.update(&buffer2[..bytes_read2]);
              }
              let computed_hash2 = format!("{:x}", hasher2.finalize());
              let lower_computed_hash2 = computed_hash2.to_lowercase();
              println!("{lower_computed_hash}");
              println!("{lower_computed_hash2}");
              if lower_computed_hash == lower_computed_hash2 {
                  println!("Checksums match!");
              } else {
                  println!("Checksums do not match!");
              }
          }
        }
    if &args[1] == "-c" && args[3].len() == 0 {
      if let Ok(sha256_content) = read_sha256_file(&sha256_file_name) {
          println!("[sha256_hash] was left empty but hasher found an external .sha256 file and will use that instead");
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

fn read_sha256_file(file_name: &str) -> io::Result<String> {
    let mut sha256_file = File::open(file_name)?;
    let mut sha256_content = String::new();
    sha256_file.read_to_string(&mut sha256_content)?;
    Ok(sha256_content)
}
