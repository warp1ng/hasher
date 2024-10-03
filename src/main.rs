use std::io::{self, BufReader, Read, Write};
use std::env;
use std::fs::File;
use sha2::{Sha256, Digest};
use colored::*;
use spinoff::{Spinner, spinners, Color, Streams};
use std::path::{PathBuf};
use walkdir::WalkDir;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1].is_empty() {
        println!("Use hasher -h for help");
        return;
    }

    let arg = &args[1].to_lowercase();

    if arg != "-s" && arg != "-c" && arg != "-h" && arg != "-w" && arg != "-wr" && arg != "-cr" {
        println!("Use hasher -h for help");
        return;
    }
    if &args[1] == "-h" {
        println!("Usage:");
        println!("-s [filename] to compute the sha256 checksum of the file");
        println!("-c [filename] [input] to compare the input's computed checksum against your own [input] which can be a checksums, a .sha256 file or another file");
        println!("-w [filename] to compute and write the checksum to a file (automatically named after the input file)");
        println!("-wr [directory] to compute and write the checksums of all files in a directory to a file");
        println!("cr [directory] to compare the checksums of a .sha256 file located inside the directory to all the files there");
        return;
    }
    if args.len() < 3 {
        println!("Use hasher -h for help");
        return;
    }
    
    if args.len() == 3 && arg == "-c" {
        println!("{} '-c' switch requires two files", "Error:".truecolor(173,127,172));
        return;
    }

    let dir = PathBuf::from(&args[2]);

    if arg == "-wr" && !dir.is_dir() {
        println!("{} '-wr' switch requires a directory", "Error:".truecolor(173,127,172));
        return;
    }

    if arg == "-cr" && !dir.is_dir() {
        println!("{} '-cr' switch requires a directory", "Error:".truecolor(173,127,172));
        return;
    }


    if arg == "-cr" && dir.is_dir() {
        let dir_name = dir.file_name().unwrap().to_str().unwrap();
        let checksums_file_name = format!("{}.sha256", dir_name);
        let checksums_path = dir.join(checksums_file_name.clone());
        let mut count_good = 0;
        let mut count_bad = 0;
        let mut bad_files: Vec<String> = Vec::new();
        if let Ok(sha256_content) = read_sha256_file(&checksums_path, dir_name) {
            let text: String = sha256_content.to_lowercase();
             let mut spinner = Spinner::new_with_stream(spinners::Line, "Loading...", Color::White, Streams::Stdout);
            for entry in WalkDir::new(dir.clone()).into_iter().filter_map(Result::ok) {
                let path = entry.path();
                if path.is_file() {
                    if let Some(file_name) = path.file_name() {
                        if *file_name == *checksums_file_name {
                            continue;
                        }
                    }
                    let file_hash = compute_sha256_for_file(&path.to_path_buf(), &checksums_file_name, false);
                    let relative_path = strip_prefix(path, &dir);
                    if let Some(hash_from_external_raw) = find_sha256_for_filename(&text, &file_hash) {
                        let hash_from_external_file = hash_from_external_raw.to_lowercase();
                        if file_hash == hash_from_external_file {
                            count_good += 1;
                        }
                    } else {
                        count_bad += 1;
                        bad_files.push(relative_path.to_string_lossy().to_string());
                    }
                }
            }
             clear_spinner_and_flush(&mut spinner);
        }
        let total_count = count_good + count_bad;
        if count_bad == 0 {
            println!("{} {}", "Status:".truecolor(119, 193, 178), "All checksums match!");
            return;
        }
        if count_good == 0 {
            println!("{} {}", "Status:".truecolor(173, 127, 172), "No checksums match!");
            return;
        }

        if count_good > count_bad {
            println!("{} {} out of {} checksums match!", "Status:".truecolor(119, 193, 178), count_good.to_string().white().bold(), total_count.to_string().white().bold());
        } else {
            println!("{} {} out of {} checksums match!", "Status:".truecolor(173, 127, 172), count_good.to_string().white().bold(), total_count.to_string().white().bold());
        }
        println!("Files with mismatched hashes:");
        for file in bad_files {
            println!("{}", file);
        }
        return;
    }


    if arg == "-wr" && dir.is_dir() {
        let dir_name = dir.file_name().unwrap().to_str().unwrap();
        let checksums_file_name = format!("{}.sha256", dir_name);
        let output_file = dir.join(&checksums_file_name);
        let mut checksums_file = match File::create(&output_file) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("{} failed to create file '{}': {}","Error:".truecolor(173,127,172), dir_name.white().bold(), e);
                return;
            }
        };
        let mut spinner = Spinner::new_with_stream(spinners::Line, "Loading...", Color::White, Streams::Stdout);
        for entry in WalkDir::new(dir.clone()).into_iter().filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() {
                if let Some(file_name) = path.file_name() {
                    if *file_name == *checksums_file_name {
                        continue;
                    }
                }
                let result = compute_sha256_for_file(&path.to_path_buf(), &checksums_file_name,false);
                let relative_path = strip_prefix(path, &dir);
                let text_to_write = format!("{} {}", result, relative_path.display());
                writeln!(checksums_file, "{}", text_to_write).unwrap();
            }
        }
        clear_spinner_and_flush(&mut spinner);
        println!("{} file '{}' created and written to successfully", "Status:".truecolor(119,193,178), checksums_file_name.bold().white());
        return;
    }

    let raw_first_file_path = PathBuf::from(&args[2]);
    let first_filename = raw_first_file_path.file_name().unwrap().to_str().unwrap();
    let computed_hash = compute_sha256_for_file(&raw_first_file_path, first_filename, true);
    let lower_computed_hash = computed_hash.to_lowercase();
    let lower_computed_hash_and_filename = computed_hash + " " + &first_filename;
    let checksum_file_name = format!("{}.sha256", first_filename);

    if arg == "-s" {
        println!("{} {}", lower_computed_hash.bold().white(), first_filename.bold().white());
        return;
    }

    if arg == "-w" {
        let sha256_file_name_raw = format!("{}.sha256", raw_first_file_path.to_str().unwrap());
        let mut checksum_file = match File::create(&sha256_file_name_raw) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("{} failed to create file '{}': {}","Error:".truecolor(173,127,172), checksum_file_name.white().bold(), e);
                return;
            }
        };
        if let Err(e) = checksum_file.write_all(lower_computed_hash_and_filename.as_bytes(),) {
            eprintln!("{} failed to write to file '{}': {}","Error:".truecolor(173,127,172), checksum_file_name.white().bold(), e);
            return;
        }
        println!("{} file '{}' created and written to successfully", "Status:".truecolor(119,193,178), checksum_file_name.bold().white());
        return;
    }

    if arg == "-c" && args.len() == 4 && args[3].len() == 64 {
        let arg_hash = &args[3];
        let lower_arg_hash = arg_hash.to_lowercase();
        let squiggles = highlight_differences(&lower_computed_hash, &lower_arg_hash);
        println!("{}", lower_computed_hash.bold().white());
        if squiggles.contains('^') {
            println!("{}", squiggles);
        }
        println!("{}", lower_arg_hash.bold().white());
            if lower_computed_hash == lower_arg_hash {
                println!("{} {}","Status:".truecolor(119,193,178), "Checksums match!");
            } else {
                println!("{} {}","Status:".truecolor(173,127,172), "Checksums do not match!");
            }
        return;
        }

    if arg == "-c" && args.len() == 4 && !args[3].to_lowercase().contains(".sha256") {
        let raw_second_file_path = PathBuf::from(&args[3]);
        let second_filename = raw_second_file_path.file_name().unwrap().to_str().unwrap();
        let computed_hash2 = compute_sha256_for_file(&raw_second_file_path, second_filename, true);
        let lower_computed_hash2 = computed_hash2.to_lowercase();
        let squiggles = highlight_differences(&lower_computed_hash, &lower_computed_hash2);
        println!("{}", lower_computed_hash.bold().white());
        if squiggles.contains('^') {
            println!("{}", squiggles);
        }
        println!("{}", lower_computed_hash2.bold().white());
        if lower_computed_hash == lower_computed_hash2 {
            println!("{} {}","Status:".truecolor(119,193,178), "Checksums match!");
        } else {
            println!("{} {}","Status:".truecolor(173,127,172), "Checksums do not match!");
        }
        return;
    }
    
    if arg == "-c" && args.len() == 4 && args[3].to_lowercase().contains(".sha256") {
        let sha256_file_path = PathBuf::from(&args[3]);
        let sha256_file_name = sha256_file_path.file_name().unwrap().to_str().unwrap();
         if let Ok(sha256_content) = read_sha256_file(&sha256_file_path, sha256_file_name) {
             let text: String = sha256_content.to_lowercase();
             if let Some(hash_from_external_file) = find_sha256_for_filename(&text, &lower_computed_hash) {
               let lower_hash_from_external_file = hash_from_external_file.to_lowercase();
               let squiggles = highlight_differences(&lower_computed_hash, &lower_hash_from_external_file);
               println!("{} hasher read directly from file '{}'","Warning:".truecolor(119,193,178), sha256_file_name.bold().white());
               println!("{}", lower_computed_hash.bold().white());
                 if squiggles.contains('^') {
                     println!("{}", squiggles);
                 }
               println!("{}", lower_hash_from_external_file.bold().white());

               if lower_hash_from_external_file == lower_computed_hash {
                   println!("{} {}","Status:".truecolor(119,193,178), "Checksums match!");
               } else {
                   println!("{} {}","Status:".truecolor(173,127,172), "Checksums do not match!");
               }
           }
         }
        return;
    }
}

fn compute_sha256_for_file(filepath: &PathBuf, filename: &str, spinner_switch: bool) -> String {
    let file = match File::open(filepath) {
        Ok(file) => file,
        Err(_e) => {
             eprintln!("{} failed to open the file '{}'","Error:".truecolor(173,127,172), filename.bold().white());
            std::process::exit(0);
        }
    };

    let mut reader = BufReader::new(&file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];

    if spinner_switch {
        let mut spinner = Spinner::new_with_stream(spinners::Line, "Loading...", Color::White, Streams::Stdout);
        loop {
            let bytes_read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => bytes_read,
                Err(_e) => {
                    clear_spinner_and_flush(&mut spinner);
                    eprintln!("{} failed to read the file '{}'","Error:".truecolor(173,127,172), &filename.bold().white());
                    std::process::exit(0);
                }
            };
            hasher.update(&buffer[..bytes_read]);
        }
        clear_spinner_and_flush(&mut spinner);
        let result = hasher.finalize();
        format!("{:x}", result)

    } else {

        loop {
            let bytes_read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => bytes_read,
                Err(_e) => {
                    eprintln!("{} failed to read the file '{}'","Error:".truecolor(173,127,172), &filename.bold().white());
                    std::process::exit(0);
                }
            };
            hasher.update(&buffer[..bytes_read]);
        }
        let result = hasher.finalize();
        format!("{:x}", result)
    }

}

fn read_sha256_file(file_path: &PathBuf, filename: &str) -> io::Result<String> {
    let file_metadata = match std::fs::metadata(&file_path) {
        Ok(metadata) => metadata,
        Err(e) => {
             eprintln!("{} failed to open the file '{}'","Error:".truecolor(173,127,172), &filename.bold().white());
            return Err(e);
        }
    };
    const MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;
    if file_metadata.len() > MAX_FILE_SIZE_BYTES {
         eprintln!("{} File '{}' size exceeds 100MB","Error:".truecolor(173,127,172), filename);
        return Ok(Default::default());
    }
    let mut sha256_file = File::open(file_path)?;
    let mut sha256_content = String::new();
    sha256_file.read_to_string(&mut sha256_content).map_err(|e| {
         eprintln!("{} failed to read '{}' file content: {}","Error:".truecolor(173,127,172), filename.bold().white(), e);
        e
    })?;
    if sha256_content.is_empty() {
         eprintln!("{} file '{}' is empty", "Error:".truecolor(173,127,172), filename);
        return Ok(Default::default());
    }
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

fn find_sha256_for_filename<'a>(text: &'a str, checksum: &str) -> Option<&'a str> {
    for line in text.lines() {
        for word in line.split_whitespace() {
            if word.starts_with(checksum) && word.len() >= 64 {
                return Some(&word[..64]);
            }
        }
    } None
}

fn clear_spinner_and_flush(spinner: &mut Spinner) {
    spinner.clear();
    io::stdout().flush().unwrap();
}

fn strip_prefix<'a>(full_path: &'a Path, base_path: &Path) -> &'a Path {
    full_path.strip_prefix(base_path).unwrap_or(full_path)
}
