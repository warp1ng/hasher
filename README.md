## Usage
Download the executable from the [releases](https://github.com/warp1ng/hasher/releases) page or build with the instructions below

Use `hasher -s [filename]` to calculate the sha256 hash of the file

Use `hasher -c [filename] [hash]` to compare a file's calculated hash against your own

`hasher -c` will first try to find a matching file (ex. file.txt and file.txt.sha256) and use that instead of the user given hash

## How to build
1. Run `git clone https://github.com/warp1ng/hasher`
2. Run `cd path-to-directory`
3. Run `cargo build --release`
4. Then you can use the executable generated in `/target/release`
