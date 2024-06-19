## Usage
Download the executable from the [releases](https://github.com/warp1ng/hasher/releases) page or build with the instructions below

Use `hasher -h` for a list of the command line arguments

Use `hasher -s [filename]` to calculate the sha256 hash of the file

Use `hasher -c [filename] [sha256_hash]` to compare a file's calculated hash against your own; you can input your own checksum or a filename in the [sha256_hash] section.
If you don't input anything in the [sha256_hash] section hasher will try to find a .sha256 file and use that instead.

## How to build
1. Run `git clone https://github.com/warp1ng/hasher`
2. Run `cd path-to-directory`
3. Run `cargo build --release`
4. Then you can use the executable generated in `/target/release`

[![Rust](https://github.com/warp1ng/hasher/actions/workflows/rust.yml/badge.svg)](https://github.com/warp1ng/hasher/actions/workflows/rust.yml)
