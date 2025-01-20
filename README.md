# Overview
![ChraypTor](https://github.com/user-attachments/assets/4a0bd819-895b-455a-8827-003d51373ecb)
A command-line communication software focused on human rights, utilizing advanced algorithms to protect your privacy and security. It’s the international version of Chraypt, with integrated Tor support.

# Development Objectives
## Overview
We firmly believe that everyone has their own human rights.
## Program Dev
- Developers must adhere to the principles of human rights
- Prohibit the collection of all information about Chrayptor users.
- Adhere to Chrayptor's P2P, decentralized, and Tor features.
- Adhere to the security and privacy of Chrayptor.
- Adhere to the principles of high open source and free modification of source code.

# Objective Standard
## Languages
- **Rust**: After Python prototyping, rewrite Chrayptor in Rust.
- **Python**: may retain some Python parts.
- **Go**: possibly use Chrayptor for key parts of network concurrency.
## Algorithms
### Symmetric encryption: used to encrypt large amounts of data, fast speeds
- **AES** (Advanced Encryption Standard): widely used in communication protocols (e.g., TLS) **(implemented)**
- **ChaCha20**: a stream cipher, often used in conjunction with Poly1305 message authentication codes to provide efficient and secure encryption and authentication
- **SM4**: a commercial cryptographic algorithm released by the State Cryptography Administration of China (SCCA) and widely used in the financial and government sectors in China **(Implemented)**

### Asymmetric encryption
- **ECC** (Elliptic Curve Cryptography): more efficient than RSA, suitable for mobile devices **(Implemented)**
- **SM2**: an elliptic curve public key cryptography algorithm standard published by the State Cryptography Administration of China (SCCA) **(canceled, because it is not widely used and documented at present)**
- **NTRU** (Nth Degree Truncated Polynomial Ring Units): a Lattice-based public key cryptography algorithm.
- **Lattice-based Cryptography**: Lattice-based Cryptography
- **Code-based Cryptography**: is a post-quantum cryptography approach that uses the difficulties of error-correcting code theory to construct cryptosystems

## Key exchange algorithms
- **Diffie-Hellman** (DH): used to securely generate shared keys **(canceled because of the high efficiency of the key ECDH and the low quantum security)**
- **ECDH** (Elliptic Curve Diffie-Hellman): based on elliptic curves, more efficient **(implemented)**
- **Kyber**: is a lattice-based key exchange protocol that is a candidate for the NIST Post-Quantum Cryptography Standardization Project
- **Curve25519**: is an elliptic curve for efficient and secure cryptographic protocols, especially in the implementation of public-key cryptography and key exchange protocols **(Implemented)**
- **CSIDH** (Commutative Supersingular Isogeny Diffie-Hellman) is a post-quantum key exchange protocol based on the homology of supersingular elliptic curves **(canceled, since there is currently no mature CSIDH library)**

## Digital signature algorithms
- **ECDSA** (Elliptic Curve Digital Signature Algorithm): is a widely used digital signature algorithm based on elliptic curve cryptography (ECC)
- **SM2**: based on the elliptic curve discrete logarithm puzzle
- **EdDSA** (Edwards-curve Digital Signature Algorithm): digital signature algorithm based on Edwards curves **(implemented)**

## Hash Algorithm
- **SHA3-512**, **SHA2-512**,: high security, widely used for data integrity verification, signature verification **(Implemented)**
- **Argon2**: specifically designed to resist brute-force attacks on hardware acceleration such as GPUs and ASICs **(Implemented)**
- **BLAKE3**: very modern and high performance **(Implemented)**
- **SM3**: standard for cryptographic hashing algorithms published by the Chinese State Cryptography Bureau **(canceled, as it is not widely used and documented at the moment)**

## Random number generation algorithm
- **CSPRNG** (Cryptographically Secure Pseudo-Random Number Generator) **(realized)**

## Communication protocols
- **TLS**: (Transport Layer Security): implements encrypted transport, authentication **(implemented, but client-side authentication is temporarily disabled because SSL does not trust self-signed certificates)** **Noise Protocol Framework**: (Transport Layer Security).
- **Noise Protocol Framework**: for modern communication software
- **Tor**: access to the Tor network **(Implemented)**
- **I2P**: Access to I2P networks.

## Zero Knowledge Proofs
- zk-SNARKs, zk-STARKs
