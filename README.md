# hasher

A command-line SHA256 utility

<img src="./assets/demo.svg" alt="demo" style="zoom: 50%;" />

## Commands

### File and text operations

- `s <filename>`: Prints the checksum of a file

  

  Example: `hasher s file.txt`

- `t <text>`: Prints the checksum of input text

  

  Example: `hasher t "Hello, World!"`

- `c <input> <input>`: Compares two inputs, which can be files, checksums, or a mix. Supports the following:  

  - file vs. file: `hasher c file1.txt file2.txt`  
  - file vs. sha file: `hasher -c file.png file.png.sha256`  
  - hash vs. file: `hasher c <hash> file.txt`  
  - hash vs. hash: `hasher c <hash1> <hash2>`

- `w <filename>`: Generates and writes the checksum of a file to a `.sha256` file 

  

  Example: `hasher w file.txt`

### Directory operations

- `wr [<directory>]`: Generates checksums for all files in a directory and writes them to a `.sha256` file. Defaults to the current directory. 

  

  Example: `hasher wr` or `hasher wr /path/to/dir`

- `cr [<directory>]`: Verifies all files in a directory against a `.sha256` file. Defaults to the current directory. 

  

  Example: `hasher cr` or `hasher cr /path/to/dir`

## Notes

- Using the `c` option with a `.sha256` or `.txt` file will attempt to read the file instead of computing a checksum
- Both `wr` and `cr` default to the current directory if no path is specified
- A `.sha256` file must exist in the directory for `cr` to work