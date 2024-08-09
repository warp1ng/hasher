use std::io::{self, BufReader, Read, Write};
use std::env;
use std::fs::File;
use sha2::{Sha256, Digest};
use colored::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1].is_empty() {
        println!("Use hasher -h for help");
        return;
    }
    let arg = &args[1].to_lowercase();
    if arg != "-s" && arg != "-c" && arg != "-h" && arg != "-w" {
        println!("Use hasher -h for help");
        return;
    }
    if &args[1] == "-h" {
        println!("Usage: hasher [switch] [filename] [sha256/sha256file/otherfile]");
        println!("-s prints the computed sha256 checksum");
        println!("-w writes the computed sha256 checksum to a .sha256 file named after the input file");
        println!("-c compares the computed checksum to the [sha256] where you can input your own hash, a .sha256 file or another filename");
        println!("-c also tries to look after a .sha256 file if nothing is typed in the [sha256] section");
        return;
    }
    if args.len() < 3 {
        println!("Use hasher -h for help");
        return;
    }

    let file_name = &args[2].trim().replace(".\\", "");
    
    let file = match File::open(file_name) {
        Ok(file) => file,
        Err(_) => {
            eprintln!("Failed to open the file {}", &file_name);
            return;
        }
    };
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 16384];
    loop {
        let bytes_read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => {
                eprintln!("Failed to read the file {}", &file_name);
                return;
            }
        };
        hasher.update(&buffer[..bytes_read]);
    }

    let computed_hash = format!("{:x}", hasher.finalize());
    let lower_computed_hash = computed_hash.to_lowercase();
    let lower_computed_hash_and_filename = computed_hash + " " + file_name;
    let sha256_file_name = format!("{}.sha256", file_name);

    if &args[1] == "-s" {
        println!("{}", lower_computed_hash.bright_green());
        return;
    }

    if &args[1] == "-w" {
        let mut file = match File::create(&sha256_file_name) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Failed to create file '{}': {}", sha256_file_name.bright_red(), e);
                return;
            }
        };
        if let Err(e) = file.write_all(lower_computed_hash_and_filename.as_bytes(),) {
            eprintln!("Failed to write to file '{}': {}", sha256_file_name.bright_red(), e);
            return;
        }

        println!("File {} created and written to successfully.", sha256_file_name.bright_green());
        
    }

    if &args[1] == "-c" && args.len() == 4 && args[3].len() == 64 {
            let arg_hash = &args[3];
            let lower_arg_hash = arg_hash.to_lowercase();
            let (colored_lower_computed_hash, colored_lower_arg_hash) = highlight_differences(&lower_computed_hash, &lower_arg_hash);
            println!("{}", colored_lower_computed_hash);
            println!("{}", colored_lower_arg_hash);
            if lower_computed_hash == lower_arg_hash {
                println!("{}", "Checksums match!".bright_green());
            } else {
                println!("{}", "Checksums do not match!".bright_red());
            }
        }
    if &args[1] == "-c" && args.len() == 4 && args[3].len() < 60 && !args[3].as_str().to_lowercase().contains(&sha256_file_name.to_lowercase()) {
              let file_name2 = &args[3];
              let file2 = match File::open(file_name2) {
                  Ok(file2) => file2,
                  Err(_) => {
                      eprintln!("Failed to open the second file {}", file_name2);
                      return;
                  }
              };
              let mut reader2 = BufReader::new(file2);
              let mut hasher2 = Sha256::new();
              let mut buffer2 = [0; 16384];
              loop {
                  let bytes_read2 = match reader2.read(&mut buffer2) {
                      Ok(0) => break,
                      Ok(n) => n,
                      Err(_) => {
                          eprintln!("Failed to read the second file {}", file_name2);
                          return;
                      }
                  };
                  hasher2.update(&buffer2[..bytes_read2]);
              }
              let computed_hash2 = format!("{:x}", hasher2.finalize());
              let lower_computed_hash2 = computed_hash2.to_lowercase();
              let (colored_lower_computed_hash, colored_lower_computed_hash2) = highlight_differences(&lower_computed_hash, &lower_computed_hash2);
              println!("{}", colored_lower_computed_hash);
              println!("{}", colored_lower_computed_hash2);
              if lower_computed_hash == lower_computed_hash2 {
                  println!("{}", "Checksums match!".bright_green());
              } else {
                  println!("{}", "Checksums do not match!".bright_red());
              }
          }
    if &args[1] == "-c" && args.len() == 4 && args[3].to_string().to_lowercase().contains("sha256") {
         if let Ok(sha256_content) = read_sha256_file(&sha256_file_name) {
             let text: String = sha256_content;
             if let Some(hash_from_external_file) = find_sha256_for_filename(&text, &file_name) {
               let lower_hash_from_external_file = hash_from_external_file.to_lowercase();
               let (colored_lower_computed_hash, colored_lower_hash_from_external_file) = highlight_differences(&lower_computed_hash, &lower_hash_from_external_file);
               println!("Hasher read directly from {}", sha256_file_name);
               println!("{}", colored_lower_computed_hash);
               println!("{}", colored_lower_hash_from_external_file);
               if lower_hash_from_external_file == lower_computed_hash {
                   println!("{}", "Checksums match!".bright_green());
               } else {
                   println!("{}", "Checksums do not match!".bright_red());
               }
           }
         }
    }
}
fn read_sha256_file(file_name: &str) -> io::Result<String> {
    let file_metadata = std::fs::metadata(&file_name)?;
    const MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;
    if file_metadata.len() > MAX_FILE_SIZE_BYTES {
        eprintln!("{} size exceeds 100MB", file_name);
        return Ok(Default::default());
    }
    let mut sha256_file = File::open(file_name)?;
    let mut sha256_content = String::new();
    sha256_file.read_to_string(&mut sha256_content).map_err(|e| {
        eprintln!("Failed to read {} file content: {}", file_name, e);
        e
    })?;
    if sha256_content.is_empty() {
        eprintln!("{} file is empty", file_name);
        return Ok(Default::default());
    }
    Ok(sha256_content)
}

fn highlight_differences(a: &str, b: &str) -> (String, String) {
    let max_len = std::cmp::max(a.len(), b.len());
    let a_padded = format!("{:width$}", a, width = max_len);
    let b_padded = format!("{:width$}", b, width = max_len);

    let result_a: String = a_padded.chars().zip(b_padded.chars())
        .map(|(char_a, char_b)| {
            if char_a == char_b {
                char_a.to_string().bright_green().to_string()
            } else {
                char_a.to_string().bright_red().to_string()
            }
        })
        .collect();

    let result_b: String = a_padded.chars().zip(b_padded.chars())
        .map(|(char_a, char_b)| {
            if char_a == char_b {
                char_b.to_string().bright_green().to_string()
            } else {
                char_b.to_string().bright_red().to_string()
            }
        })
        .collect();

    (result_a, result_b)
}

fn find_sha256_for_filename<'a>(text: &'a str, filename: &'a str) -> Option<&'a str> {
    for line in text.lines() {
        if line.contains(filename) {
            for word in line.split_whitespace() {
                if word.len() == 64 && word.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(word);
                }
            }
        }
    }
    None
}