## Usage
Download the executable from the [releases](https://github.com/warp1ng/hasher/releases) page or build with the instructions below:

Use `hasher -h` for a list of the command line arguments

Use `hasher -s [filename]` to compute the sha256 hash of the file

Use `hasher -w [filename]` to compute and write the hash to a file (automatically named after the input file)

Use `hasher -wr [directory]` to compute and write the hash of a directory to a file

Use `hasher -c [filename] [input]` to compare the input's computed checksum against your own `[input]` which can be a checksum, a .sha256 file or another file.

## How to build
1. Run `git clone https://github.com/warp1ng/hasher`
2. Run `cd path-to-directory`
3. Run `cargo build --release`
4. Then you can use the executable generated in `/target/release`

[![Rust](https://github.com/warp1ng/hasher/actions/workflows/rust.yml/badge.svg)](https://github.com/warp1ng/hasher/actions/workflows/rust.yml)
