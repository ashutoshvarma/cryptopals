# cryptopals
Challenges from https://cryptopals.com/.

WARNING: This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Methodoly
_DIY, build everything from scratch_
- minimum dependencies (crates).
- implement each and every thing.
- should be modular and can be used outside this project.

## Project Structure
This project is organised as a Cargo Workspace with two types of crates, challenges and utiltiy crates.

- [`challenges`](./challenges) - Crates for individual Problem Set and each crate contain only tests which represent the challanges and no other logic.
- [`packages`](./packages) - Utility crates like, aes, hex, base64, etc.

## `packages`
Utiltiy crates which are complelety functional on thier own to be used outside the scope of this project.
- ### [`aes`](./packages/aes)
  Implementations for AES128, AES192, AES256.
  - Complete AES Cipher & Inver Cipher implementation. (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
  - Supports multiple padding schemes and block modes.
  - Supports PKCS7 Padding Scheme.
  - Supports CBC & ECB Block modes.

- ### [`enscoring`](./packages/enscoring)
  English text scoring & metric utilites.
  - Based on English character frequency table. (https://en.wikipedia.org/wiki/Letter_frequency)
  - Use _Bhattacharyya coefficient_ for calculating score for given english text. (https://en.wikipedia.org/wiki/Bhattacharyya_distance)

- ### [`naivebase64`](./packages/naivebase64)
  Naive Base64 encoding & decoding implementation.

- ### [`hex`](./packages/hex)
  Hex encoding and decoding from hex string implementation.

- ### [`xor`](./packages/xor)
  Utiltiy methods for XOR based key encryptions.
  - Break Single XOR Key
  - Break Repeating XOR Key


## Run Challanges
- To run all challenges and utility tests
  ```
  cargo test
  ```
  
## License
The crates in this repository are licensed under MIT license (LICENSE or opensource.org license link).

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be licensed as above, without any additional terms or conditions.

