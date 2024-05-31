## Usage
Download the executable from the [releases](https://github.com/warp1ng/hasher/releases) page or build with the instructions below

Use `hasher -h` for a list of the command line arguments

Use `hasher -s [filename]` to calculate the sha256 hash of the file

Use `hasher -c [filename] [hash]` to compare a file's calculated hash against your own; you can input your own checksum or a filename in the `[hash]` section.

## How to build
1. Run `git clone https://github.com/warp1ng/hasher`
2. Run `cd path-to-directory`
3. Run `cargo build --release`
4. Then you can use the executable generated in `/target/release`
