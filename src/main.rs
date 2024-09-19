use std::io::{self, BufReader, Read, Write};
use std::env;
use std::fs::File;
use sha2::{Sha256, Digest};
use colored::*;
use colored::control;
use spinoff::{Spinner, spinners, Color, Streams};

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
    
    if args.len() == 3 && arg == "-c" {
        println!("{} '-c' switch requires two files", "Error:".truecolor(173,127,172))
    }

    control::set_virtual_terminal(true).unwrap();

    let raw_file_name = &args[2].trim().replace("./", "");
    let processed_arg = raw_file_name
    .trim()
    .replace("./", "")
    .replace(".\\", "");
    let file_name = &processed_arg.replace("\\", "/");
    let file = match File::open(file_name) {
        Ok(file) => file,
        Err(_) => {
            eprintln!("{} failed to open the file '{}'","Error:".truecolor(173,127,172), &file_name.bold().white());
            return;
        }
    };

    let mut spinner = Spinner::new_with_stream(spinners::Line, "Loading...", Color::White, Streams::Stdout);

    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let bytes_read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => {
                spinner.clear();
                std::io::stdout().flush().unwrap();
                eprintln!("{} failed to read the file '{}'","Error:".truecolor(173,127,172), &file_name.bold().white());
                return;
            }
        };
        hasher.update(&buffer[..bytes_read]);
    }

    let computed_hash = format!("{:x}", hasher.finalize());
    let lower_computed_hash = computed_hash.to_lowercase();
    let lower_computed_hash_and_filename = computed_hash + " " + &file_name;
    let sha256_file_name_for_write = format!("{}.sha256", file_name);

    if arg == "-s" {
        spinner.clear();
        std::io::stdout().flush().unwrap();
        println!("{}", lower_computed_hash.truecolor(119,193,178));
        return;
    }

    spinner.clear();
    std::io::stdout().flush().unwrap();

    if arg == "-w" {
        let mut file = match File::create(&sha256_file_name_for_write) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("{} failed to create file '{}': {}","Error:".truecolor(173,127,172), sha256_file_name_for_write.white().bold(), e);
                return;
            }
        };
        if let Err(e) = file.write_all(lower_computed_hash_and_filename.as_bytes(),) {
            eprintln!("{} failed to write to file '{}': {}","Error:".truecolor(173,127,172), sha256_file_name_for_write.white().bold(), e);
            return;
        }
        println!("{} file '{}' created and written to successfully", "Status:".truecolor(119,193,178), sha256_file_name_for_write.bold().white());
        
    }

    if arg == "-c" && args.len() == 4 && args[3].len() == 64 {
        let arg_hash = &args[3];
        let lower_arg_hash = arg_hash.to_lowercase();
        let squiggles = highlight_differences(&lower_computed_hash, &lower_arg_hash);
        // The colored vars no longer do anything. I now understand the jokes about legacy code.
        println!("{}", lower_computed_hash);
        if squiggles.contains('^') {
            println!("{}", squiggles);
        }
        println!("{}", lower_arg_hash);
            if lower_computed_hash == lower_arg_hash {
                println!("{} {}","Status:".truecolor(119,193,178), "Checksums match!");
            } else {
                println!("{} {}","Status:".truecolor(119,193,178), "Checksums do not match!");
            }
        }

    if arg == "-c" && args.len() == 4 && args[3].len() < 60 && !args[3].to_lowercase().contains(".sha256") {
        let file_name2 = &args[3];
        let file2 = match File::open(file_name2) {
                  Ok(file2) => file2,
                  Err(_) => {
                      eprintln!("{} failed to open the second file '{}'","Error:".truecolor(173,127,172), file_name2.bold().white());
                      return;
                  }
              };
        let mut reader2 = BufReader::new(file2);
        let mut hasher2 = Sha256::new();
        let mut buffer2 = [0; 65536];

        let mut spinner = Spinner::new_with_stream(spinners::Line, "Loading...", Color::White, Streams::Stdout);

              loop {
                  let bytes_read2 = match reader2.read(&mut buffer2) {
                      Ok(0) => break,
                      Ok(n) => n,
                      Err(_) => {
                          spinner.clear();
                          std::io::stdout().flush().unwrap();
                          eprintln!("{} failed to read the second file '{}'","Error:".truecolor(173,127,172), file_name2.bold().white());
                          return;
                      }
                  };
                  hasher2.update(&buffer2[..bytes_read2]);
              }

        spinner.clear();
        std::io::stdout().flush().unwrap();

        let computed_hash2 = format!("{:x}", hasher2.finalize());
        let lower_computed_hash2 = computed_hash2.to_lowercase();
        let squiggles = highlight_differences(&lower_computed_hash, &lower_computed_hash2);
        println!("{}", lower_computed_hash);
        if squiggles.contains('^') {
            println!("{}", squiggles);
        }
        println!("{}", lower_computed_hash2);
        if lower_computed_hash == lower_computed_hash2 {
            println!("{} {}","Status:".truecolor(119,193,178), "Checksums match!");
        } else {
            println!("{} {}","Status:".truecolor(119,193,178), "Checksums do not match!");
        }
    }
    
    if arg == "-c" && args.len() == 4 && args[3].to_lowercase().contains(".sha256") {
        let sha256_file_name = &args[3];
        let processed_sha256_file_name = sha256_file_name
         .trim()
         .replace("./", "")
         .replace(".\\", "");
        let sha256_file_name = &processed_sha256_file_name.replace("\\", "/");
         if let Ok(sha256_content) = read_sha256_file(&sha256_file_name) {
             let text: String = sha256_content;
             if let Some(hash_from_external_file) = find_sha256_for_filename(&text, &file_name) {
               let lower_hash_from_external_file = hash_from_external_file.to_lowercase();
               let squiggles = highlight_differences(&lower_computed_hash, &lower_hash_from_external_file);
               println!("{} hasher read directly from file '{}'","Warning:".truecolor(119,193,178), sha256_file_name.bold().white());
               println!("{}", lower_computed_hash);
                 if squiggles.contains('^') {
                     println!("{}", squiggles);
                 }
               println!("{}", lower_hash_from_external_file);

               if lower_hash_from_external_file == lower_computed_hash {
                   println!("{} {}","Status:".truecolor(119,193,178), "Checksums match!");
               } else {
                   println!("{} {}","Status:".truecolor(119,193,178), "Checksums do not match!");
               }
           }
         }
    }
}
fn read_sha256_file(file_name: &str) -> io::Result<String> {
    let mut spinner = Spinner::new_with_stream(spinners::Line, "Loading...", Color::White, Streams::Stdout);
    let file_metadata = match std::fs::metadata(&file_name) {
        Ok(metadata) => metadata,
        Err(e) => {
            spinner.clear();
            std::io::stdout().flush().unwrap();
            eprintln!("{} failed to open the file '{}'","Error:".truecolor(173,127,172), &file_name.bold().white());
            return Err(e);
        }
    };
    const MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;
    if file_metadata.len() > MAX_FILE_SIZE_BYTES {
        spinner.clear();
        std::io::stdout().flush().unwrap();
        eprintln!("{} File '{}' size exceeds 100MB","Error:".truecolor(173,127,172), file_name);
        return Ok(Default::default());
    }
    let mut sha256_file = File::open(file_name)?;
    let mut sha256_content = String::new();
    sha256_file.read_to_string(&mut sha256_content).map_err(|e| {
        spinner.clear();
        std::io::stdout().flush().unwrap();
        eprintln!("{} failed to read '{}' file content: {}","Error:".truecolor(173,127,172), file_name.bold().white(), e);
        e
    })?;
    if sha256_content.is_empty() {
        spinner.clear();
        std::io::stdout().flush().unwrap();
        eprintln!("{} file '{}' is empty", "Error:".truecolor(173,127,172), file_name);
        return Ok(Default::default());
    }
    spinner.clear();
    std::io::stdout().flush().unwrap();
    Ok(sha256_content)
}

fn highlight_differences(a: &str, b: &str) -> String {
    let max_len = std::cmp::max(a.len(), b.len());

    let a_padded = format!("{:width$}", a, width = max_len);
    let b_padded = format!("{:width$}", b, width = max_len);
    
    let mut squiggles = String::new();

    for (char_a, char_b) in a_padded.chars().zip(b_padded.chars()) {
        if char_a == char_b {
            squiggles.push_str(&"|".truecolor(119,193,178).to_string());
        } else {
            squiggles.push_str(&"^".truecolor(173,127,172).to_string());
        }
    }

    squiggles
}


fn find_sha256_for_filename<'a>(text: &'a str, filename: &'a str) -> Option<&'a str> {
    for line in text.lines() {
        if line.contains(filename) {
            for word in line.split_whitespace() {
                if word.len() == 64 && word.chars().all(|c| c.is_alphanumeric()) {
                    return Some(word);
                }
            }
        }
    }
    None
}