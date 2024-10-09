## Usage
Download the executable from the releases page or [build](#building-instructions)

Use `hasher -h` for a list of the command line arguments

Use `hasher -s [filename]` to compute the sha256 checksum of the file

Use `hasher -c [filename] [input]` to compare the input's computed checksum against your own `[input]` which can be a checksums, a .sha256 file or another file

Use `hasher -w [filename]` to compute and write the checksum to a file (automatically named after the input file)

Use `hasher -wr / -wr [directory]` to compute and write the checksums of all files in a directory to a file

Use `hasher -cr / -cr [directory]` to compare the checksums of a .sha256 file located inside the directory to all the files there

Note: if a directory is not provided for `-wr` and `-cr` switches then the program will use the current directory instead 

## How to build <a name="building-instructions"></a>
1. Run `git clone https://github.com/warp1ng/hasher`
2. Run `cd path-to-directory`
3. Run `cargo build --release`
4. Then you can use the executable generated in `/target/release`
