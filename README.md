# Simpliest

### Features
* API Hashing using CRC32
* Indirect syscalls, utilizing HellHall
* The encrypted payload is saved in the resource section and retrieved via custom code
* AES256-CBC Payload encryption using custom no table/data-dependent branches using ctaes
* Aes Key & Iv Encryption
* No CRT library imports

### Usage
* Hasher to calculate API hashes
* PayloadBuilder is compiled and executed with the specified payload, it will output a Payload.pc file, that contains the encrypted payload, and its encrypted key and iv

### Credits
* Maldev Academy (https://maldevacademy.com/)
* HellsGate (https://github.com/am0nsec/HellsGate)
* TartarusGate (https://github.com/trickster0/TartarusGate)
* HellsHall (https://github.com/Maldev-Academy/HellHall)
* AtomLdr (https://github.com/NUL0x4C/AtomLdr)

## Disclaimer
This repository is created for educational purposes only. Any legal responsibility belongs to the person or organization that uses it.
