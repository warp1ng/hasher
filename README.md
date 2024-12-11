# hasher

A command-line SHA256 utility

<img src="./assets/demo.svg" alt="demo" style="zoom: 50%;" />

## Commands

### File and text Operations

- `-s <filename>`: Prints the SHA256 of a file
  Example: `hasher -s file.txt`

- `-t <text>`: Prints the SHA256 of input text
  Example: `hasher -t "Hello, World!"`

- `-c <input> <input>`: Compares two inputs, which can be files, hashes, or a mix. Supports the following:  
  - File vs. file: `hasher -c file1.txt file2.txt`  
  - File vs. `.sha256`: `hasher -c file.txt file.sha256`  
  - Hash vs. file: `hasher -c <hash> file.txt`  
  - Hash vs. hash: `hasher -c <hash1> <hash2>`

- `-w <filename>`: Generates and writes the SHA256 of a file to a `.sha256` file 
  Example: `hasher -w file.txt`

### Directory operations

- `-wr [<directory>]`: Generates SHA256 hashes for all files in a directory and writes them to a `.sha256` file. Defaults to the current directory.  
  Example: `hasher -wr` or `hasher -wr /path/to/dir`

- `-cr [<directory>]`: Verifies all files in a directory against a `.sha256` file. Defaults to the current directory.  
  Example: `hasher -cr` or `hasher -cr /path/to/dir`

## Notes

- Both `-wr` and `-cr` default to the current directory if no path is specified.  
- A `.sha256` file must exist in the directory for `-cr` to work.