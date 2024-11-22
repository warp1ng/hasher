use std::io::{self, BufReader, Read, Write};
use std::{env, fs};
use std::env::current_dir;
use std::fs::File;
use sha2::{Sha256, Digest};
use colored::*;
use spinoff::{Spinner, spinners, Color, Streams};
use std::path::{PathBuf};
use walkdir::WalkDir;
use std::path::Path;
use regex_lite::Regex;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1].is_empty() {
        println!("Use hasher -h for help");
        return;
    }

    let arg = &args[1].to_lowercase();

    if arg != "-s" && arg != "-c" && arg != "-h" && arg != "-w" && arg != "-wr" && arg != "-cr" && arg != "-t" {
        println!("Use hasher -h for help");
        return;
    }
    if &args[1] == "-h" {
        println!("Usage:");
        println!("-s [filename] to compute the sha256 checksum of the file");
        println!("-t ['text'] to compute the sha256 checksum of some text");
        println!("-c [filename] [input] to compare the input's computed checksum against your own [input] which can be a checksums, a .sha256 file or another file");
        println!("-w [filename] to compute and write the checksum to a file (automatically named after the input file)");
        println!("-wr / -wr [directory] to compute and write the checksums of all files in a directory to a file");
        println!("-cr / -cr [directory] to compare the checksums of a .sha256 file located inside the directory to all the files there");
        println!("note: both '-wr' and '-cr' switches can be run as is to use the current directory");
        return;
    }
    if args.len() < 3 && arg != "-cr" && arg != "-wr" {
        println!("Use hasher -h for help");
        return;
    }

    if args.len() == 3 && arg == "-c" {
        println!("{} '-c' switch requires two files", "Error:".truecolor(173, 127, 172));
        return;
    }

    let dir;
    if args.len() == 3 && (arg == "-wr" || arg == "-cr") {
        println!("{}", &args[2]);
        dir = PathBuf::from(&args[2]);
        if !dir.exists() {
            eprintln!("{} could not find '{}' directory", "Error:".truecolor(173, 127, 172), dir.display());
            return;
        }
    } else {
        dir = current_dir().unwrap();
    }

    if arg == "-wr" && !dir.is_dir() {
        println!("{} '-wr' switch requires a directory", "Error:".truecolor(173, 127, 172));
        return;
    }

    if arg == "-cr" && !dir.is_dir() {
        println!("{} '-cr' switch requires a directory", "Error:".truecolor(173, 127, 172));
        return;
    }

    if arg == "-t" {
        let raw_input = args.iter().skip(2).map(|s| s.as_str()).collect::<Vec<_>>().join(" ");
        let input = raw_input.to_string();
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let checksum = format!("{:x}", hasher.finalize());
        let shortened_input = shorten_str(&input, 18);
        println!("{} : '{}'", checksum.bold().white(), shortened_input);
        return;
    }

    if arg == "-cr" && dir.is_dir() {
        if let Some(dir_name_check) = dir.file_name() {
            if let Some(dir_name) = dir_name_check.to_str() {
                let checksums_file_name = format!("{}.sha256", dir_name);
                let checksums_path = dir.join(checksums_file_name.clone());
                if !checksums_path.exists() {
                    eprintln!("{} file '{}' is missing", "Error:".truecolor(173, 127, 172), checksums_file_name);
                    return;
                }
                let mut count_good = 0;
                let mut count_bad = 0;
                let mut bad_files: Vec<String> = Vec::new();
                if let Ok(sha256_content) = read_sha256_file(&checksums_path, dir_name) {
                    let text: String = sha256_content.to_lowercase();
                    let loading_message = format!("Verifying checksums for directory '{}'", dir_name);
                    let mut spinner = Spinner::new_with_stream(spinners::Line, loading_message, Color::White, Streams::Stdout);
                    for entry in WalkDir::new(dir.clone()).into_iter().filter_map(Result::ok) {
                        let path = entry.path();
                        if path.is_file() {
                            if let Some(file_name) = path.file_name() {
                                if *file_name.to_ascii_lowercase() == *checksums_file_name.to_ascii_lowercase() {
                                    continue;
                                }
                            }
                            let file_hash = compute_sha_for_file(&path.to_path_buf(), &checksums_file_name, false).to_lowercase();
                            let relative_path = strip_prefix(path, &dir);
                            match find_matching_sha256_for_filename(&text, &file_hash) {
                                Some(_) => {
                                    count_good += 1;
                                }
                                _ => {
                                    count_bad += 1;
                                    bad_files.push(relative_path.to_string_lossy().to_string());
                                }
                            }
                        }
                    }
                    clear_spinner_and_flush(&mut spinner);
                }
                let total_count = count_good + count_bad;
                if count_bad == 0 {
                    println!("{} All checksums passed!", "Status:".truecolor(119, 193, 178));
                    return;
                }
                if count_good == 0 {
                    println!("{} All checksums failed!", "Status:".truecolor(173, 127, 172));
                    return;
                }
                println!("Files with mismatched hashes:");
                for file in bad_files {
                    println!("{}", file);
                }

                if count_good > count_bad {
                    println!("{} {} out of {} checksums passed!", "Status:".truecolor(119, 193, 178), count_good, total_count);
                } else {
                    println!("{} {} out of {} checksums passed!", "Status:".truecolor(173, 127, 172), count_good, total_count);
                }
                return;
            }
        } else {
            eprintln!("{} directory has no file name", "Error:".truecolor(173, 127, 172));
            return;
        }
    }

    if arg == "-wr" && dir.is_dir() {
        if let Some(dir_name_check) = dir.file_name() {
            if let Some(dir_name) = dir_name_check.to_str() {
                let checksums_file_name = format!("{}.sha256", dir_name);
                let output_file = dir.join(&checksums_file_name);
                let mut checksums_file = match File::create(output_file) {
                    Ok(file) => file,
                    Err(e) => {
                        eprintln!("{} failed to create file '{}': {}", "Error:".truecolor(173, 127, 172), dir_name, e);
                        return;
                    }
                };
                let loading_message = format!("Computing checksums for directory '{}'", dir_name);
                let mut spinner = Spinner::new_with_stream(spinners::Line, loading_message, Color::White, Streams::Stdout);
                for entry in WalkDir::new(dir.clone()).into_iter().filter_map(Result::ok) {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(file_name) = path.file_name() {
                            if *file_name.to_ascii_lowercase() == *checksums_file_name.to_ascii_lowercase() {
                                continue;
                            }
                        }
                        let result = compute_sha_for_file(&path.to_path_buf(), &checksums_file_name, false).to_lowercase();
                        let relative_path = strip_prefix(path, &dir);
                        let text_to_write = format!("{} {}", result, relative_path.display());
                        writeln!(checksums_file, "{}", text_to_write).unwrap();
                    }
                }
                clear_spinner_and_flush(&mut spinner);
                println!("{} file '{}' created and written to successfully", "Status:".truecolor(119, 193, 178), checksums_file_name.bold().white());
                return;
            }
        } else {
            eprintln!("{} directory has no file name", "Error:".truecolor(173, 127, 172));
            return;
        }
    }

    let raw_first_file_path = PathBuf::from(&args[2]);
    if raw_first_file_path.is_dir() {
        eprintln!("{} the '{}' switch does not work with directories. use '-wr' or '-cr' instead", "Error:".truecolor(173, 127, 172), &arg.bold().white());
        return;
    }

    if arg == "-s" || arg == "-w" {
        let first_filename = raw_first_file_path.file_name().unwrap().to_string_lossy();
        let computed_hash = compute_sha_for_file(&raw_first_file_path, &first_filename, true);
        let lower_computed_hash = computed_hash.to_lowercase();
        let lower_computed_hash_and_filename = computed_hash + " " + &first_filename;
        let checksum_file_name = format!("{}.sha256", &first_filename);

        if arg == "-s" {
            let shortened_first_filename = shorten_str(&first_filename, 18);
            println!("{} : '{}'", lower_computed_hash.bold().white(), shortened_first_filename);
            return;
        }

        if arg == "-w" {
            let sha256_file_name_raw = format!("{}.sha256", raw_first_file_path.to_str().unwrap());
            let mut checksum_file = match File::create(sha256_file_name_raw) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("{} failed to create file '{}': {}", "Error:".truecolor(173, 127, 172), checksum_file_name, e);
                    return;
                }
            };
            if let Err(e) = checksum_file.write_all(lower_computed_hash_and_filename.as_bytes(), ) {
                eprintln!("{} failed to write to file '{}': {}", "Error:".truecolor(173, 127, 172), checksum_file_name, e);
                return;
            }
            println!("{} file '{}' created and written to successfully", "Status:".truecolor(119, 193, 178), checksum_file_name.bold().white());
            return;
        }
    }

    if arg == "-c" && args.len() >= 4 {
        if args[2].len() == 64 && args[3].len() == 64 {
            let checksum_1 = args[2].to_lowercase();
            let checksum_2 = args[3].to_lowercase();
            let squiggles = highlight_differences(&checksum_1, &checksum_2);
            output_result(&checksum_1, &checksum_2, "USER-SHA-1", "USER-SHA-2", &squiggles)
        }
        let first_file_path = PathBuf::from(&args[2]);
        let second_file_path = PathBuf::from(&args[3]);
        let first_filename = first_file_path.file_name().unwrap().to_str().unwrap();
        let second_filename = second_file_path.file_name().unwrap().to_str().unwrap();
        let shortened_first_filename = shorten_str(&first_filename, 18);
        let shortened_second_filename = shorten_str(&second_filename, 18);
        let file_1_result = is_file_sha(&first_file_path);
        let file_2_result = is_file_sha(&second_file_path);
        match (file_1_result, file_2_result) {
            (Ok((Some(_sha), true)), Ok((Some(_sha2), true))) => { // both contain checksum
                let checksum_1 = compute_sha_for_file(&first_file_path, &first_filename, true).to_lowercase();
                match return_checksum(&second_file_path, &shortened_second_filename, &checksum_1) {
                    Some((checksum_2, squiggles)) => {
                        println!("{} hasher read directly from file '{}'", "Warning:".truecolor(119, 193, 178), shortened_second_filename.bold().white());
                        output_result(&checksum_1, &checksum_2, &shortened_first_filename, &shortened_second_filename, &squiggles)
                    }
                    None => {eprintln!("{} processing file {} failed", "Error:".truecolor(173, 127, 172), shortened_second_filename.bold().white());}
                }
            } 
            (Ok((Some(_sha), true)), Ok((None, false))) => { // file 1 contains checksum
                let checksum_1 = compute_sha_for_file(&second_file_path, &shortened_second_filename, true);
                match return_checksum(&first_file_path, &shortened_first_filename, &checksum_1) {
                    Some((checksum_2, squiggles)) => {
                        println!("{} hasher read directly from file '{}'", "Warning:".truecolor(119, 193, 178), shortened_first_filename.bold().white());
                        output_result(&checksum_2, &checksum_1, &shortened_first_filename, &shortened_second_filename, &squiggles)
                    }
                    None => {eprintln!("{} processing file {} failed", "Error:".truecolor(173, 127, 172), shortened_first_filename.bold().white());}
                }
            }
            (Ok((None, false)), Ok((Some(_sha), true))) => { // file 2 contains checksum
                let checksum_1 = compute_sha_for_file(&first_file_path, &first_filename, true).to_lowercase();
                match return_checksum(&second_file_path, &shortened_second_filename, &checksum_1) {
                    Some((checksum_2, squiggles)) => {
                        println!("{} hasher read directly from file '{}'", "Warning:".truecolor(119, 193, 178), shortened_second_filename.bold().white());
                        output_result(&checksum_1, &checksum_2, &shortened_first_filename, &shortened_second_filename, &squiggles)
                    }
                    None => {eprintln!("{} processing file {} failed", "Error:".truecolor(173, 127, 172), shortened_second_filename.bold().white());}
                }
            }
            (Ok((None, false)), Ok((None, false))) => { // neither contain checksum
                let checksum_1 = compute_sha_for_file(&first_file_path, &first_filename, true).to_lowercase();
                let checksum_2 = compute_sha_for_file(&second_file_path, &second_filename, true).to_lowercase();
                let squiggles = highlight_differences(&checksum_1, &checksum_2);
                output_result(&checksum_1, &checksum_2, &shortened_first_filename, &shortened_second_filename, &squiggles)
            }
            _ => {}
        } 

    }
}

    fn compute_sha_for_file(filepath: &PathBuf, filename: &str, spinner_switch: bool) -> String {
    let file = match File::open(filepath) {
        Ok(file) => file,
        Err(_e) => {
            eprintln!("{} failed to open the file '{}'", "Error:".truecolor(173, 127, 172), filename.bold().white());
            std::process::exit(0);
        }
    };

    let mut reader = BufReader::new(&file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];

    if spinner_switch {
        let loading_message = format!("Loading file '{}'", filename);
        let mut spinner = Spinner::new_with_stream(spinners::Line, loading_message, Color::White, Streams::Stdout);
        loop {
            let bytes_read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => bytes_read,
                Err(_e) => {
                    clear_spinner_and_flush(&mut spinner);
                    eprintln!("{} failed to read the file '{}'", "Error:".truecolor(173, 127, 172), &filename.bold().white());
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
                    eprintln!("{} failed to read the file '{}'", "Error:".truecolor(173, 127, 172), &filename.bold().white());
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
    let file_metadata = match fs::metadata(file_path) {
        Ok(metadata) => metadata,
        Err(e) => {
            eprintln!("{} failed to open the file '{}'", "Error:".truecolor(173, 127, 172), &filename.bold().white());
            return Err(e);
        }
    };
    const MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;
    if file_metadata.len() > MAX_FILE_SIZE_BYTES {
        eprintln!("{} File '{}' size exceeds 100MB", "Error:".truecolor(173, 127, 172), filename);
        return Ok(Default::default());
    }
    let mut sha256_file = File::open(file_path)?;
    let mut sha256_content = String::new();
    sha256_file.read_to_string(&mut sha256_content).map_err(|e| {
        eprintln!("{} failed to read '{}' file content: {}", "Error:".truecolor(173, 127, 172), filename.bold().white(), e);
        e
    })?;
    if sha256_content.is_empty() {
        eprintln!("{} file '{}' is empty", "Error:".truecolor(173, 127, 172), filename);
        return Ok(Default::default());
    }
    Ok(sha256_content)
}


fn is_file_sha(filepath: &PathBuf) -> io::Result<(Option<String>, bool)> {
    let file_metadata = fs::metadata(filepath)?;
    if file_metadata.len() > 10 * 1024 * 1024 {
        return Ok((None, false));
    }

    let file_content = fs::read(filepath)?;

    let file_str = match String::from_utf8(file_content) {
        Ok(content) => content,
        Err(_) => {
            return Ok((None, false));
        }
    };

    let sha256_regex = Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap();
    if let Some(mat) = sha256_regex.find(&file_str) {
        return Ok((Some(mat.as_str().to_string()), true));
    }

    Ok((None, false))
}

fn highlight_differences(a: &str, b: &str) -> String {
    let max_len = std::cmp::max(a.len(), b.len());
    let a_padded = format!("{:width$}", a, width = max_len);
    let b_padded = format!("{:width$}", b, width = max_len);
    let mut squiggles = String::new();
    for (char_a, char_b) in a_padded.chars().zip(b_padded.chars()) {
        if char_a == char_b {
            squiggles.push_str(&"|".truecolor(119, 193, 178).to_string());
        } else {
            squiggles.push_str(&"^".truecolor(173, 127, 172).to_string());
        }
    }

    squiggles
}

fn find_matching_sha256_for_filename<'a>(text: &'a str, checksum: &str) -> Option<&'a str> {
    let re = Regex::new(&format!(r"\b{}[0-9a-fA-F]{{{}}}\b", regex_lite::escape(checksum), 64 - checksum.len())).unwrap();
    if let Some(capture) = re.find(text) {
        Some(capture.as_str())
    } else {
        let re_any = Regex::new(r"\b[0-9a-fA-F]{64}\b").unwrap();
        if let Some(capture) = re_any.find(text) {
            Some(capture.as_str())
        } else {
            None
        }
    }
}

fn clear_spinner_and_flush(spinner: &mut Spinner) {
    spinner.clear();
    io::stdout().flush().unwrap();
}

fn strip_prefix<'a>(full_path: &'a Path, base_path: &Path) -> &'a Path {
    full_path.strip_prefix(base_path).unwrap_or(full_path)
}

fn shorten_str(file_name: &str, max_len: usize) -> String {
    if file_name.len() > max_len {
        let start = &file_name[..9];
        let end = &file_name[file_name.len() - 9..];
        format!("{}...{}", start, end)
    } else {
        file_name.to_string()
    }
}

fn return_checksum(file_path: &PathBuf, shortened_filename: &str, checksum_1: &str, ) -> Option<(String, String)> {
    let content = read_sha256_file(&file_path, shortened_filename);
    let file_str = content.unwrap().to_string();
    let re = Regex::new(&format!(
        r"\b{}[0-9a-fA-F]{{{}}}\b",
        regex_lite::escape(checksum_1),
        64 - checksum_1.len()
    )).ok()?;
    let checksum_2 = if let Some(mat) = re.find(&file_str) {
        mat.as_str().trim().to_string()
    } else {
        let re_any = Regex::new(r"\b[0-9a-fA-F]{64}\b").unwrap();
        re_any.find(&file_str)?.as_str().trim().to_string()
    };

    let squiggles = highlight_differences(checksum_1, &checksum_2);
    Some((checksum_2, squiggles))
    
}

 fn output_result(lower_checksum_1: &str, lower_checksum_2: &str, padded_filename_1: &str, padded_filename_2: &str, squiggles: &str) {
     println!("{} : '{}'", lower_checksum_1.bold().white(), padded_filename_1.trim());
     if squiggles.contains('^') {
         println!("{}", squiggles)
     }
     println!("{} : '{}'", lower_checksum_2.bold().white(), padded_filename_2.trim());
     if lower_checksum_1 == lower_checksum_2 {
         println!("{} Integrity check passed", "Status:".truecolor(119, 193, 178));
     } else {
         println!("{} Integrity check failed", "Status:".truecolor(173, 127, 172));
     }
 }
