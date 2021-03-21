# Revy - Windows Display & Keyboard Data Exfiltration

This program is designed to be a demonstration of how vulnerable windows is to data exfiltration to a remote server.  
It reads the target's screen, compresses the raw data 100:1 for data extraction, and simultaneously captures the key inputs during this time as well. These two things are sent to a remote server over SSL to prevent IDS detection. To my knowledge this __isn't detected__ by windows defender as malware, it __doesn't require__ admin escalation, and isn't susceptible to __PPI__ or other IDS exfil prevention techniques.

## TODO
- At the moment this program works but development environments are difficult to set up with SSL.
- Setup custom build files for better cross-platform support
- Set up an environment variable for differentiation between client and server so main.rs doesn't need modification

## Installation

__To compile for Windows__
- Download OpenSSL
- Set OPENSSL_DIR to the OpenSSL install location
- Set the domain constants in client.rs (line 19)
```
cargo build
```
__To compile for a remote server__
- Generate key files for your domain
- Remove line 10 from "Cargo.toml" if compiling for Linux
- Point lines 43 and 44 in server.rs to your key and certificate files.

## Usage
Start the remote server and start the client process on the target machine.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
