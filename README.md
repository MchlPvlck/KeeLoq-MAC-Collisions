# KeeLoq MACs and Collision Finding  

This repository contains my implementation for an assignment focused on cryptographic techniques using the KeeLoq cipher. The tasks involve implementing Cipher Block Chaining (CBC) encryption, Message Authentication Codes (MACs), and collision attacks on cryptographic functions.

---

## **Overview**

This project is part of the Fundamentals of Cryptography course and consists of three main tasks:

1. **KeeLoq CBC and MAC Implementation**:
   - Implementation of the Cipher Block Chaining (CBC) mode for the KeeLoq block cipher.
   - Creation of a vanilla CBC-based Message Authentication Code (MAC) function using the KeeLoq cipher.

2. **Collision Finding**:
   - Finding collisions for the MAC function and combining techniques to generate special SHA1 collisions.
   - Developing an attack on a combined MAC scheme that uses KeeLoq-based MACs and SHA1 hashes.

3. **Cryptographic Analysis**:
   - Providing insights into the principles and runtime of the implemented attacks and comparing collision resistance between different MAC schemes.

---

## **Features**

- **KeeLoq CBC Encryption**:
  - Implements the CBC mode for KeeLoq with PKCS#7 padding.
  - Verified using provided test vectors (`keeloq_cbc_test_vectors.json`).

- **Message Authentication Code (MAC)**:
  - Vanilla CBC MAC with customizable tag size.
  - Uses KeeLoq cipher as the cryptographic primitive.

- **Collision Attacks**:
  - Collision finder for KeeLoq-based MACs.
  - SHA1 collision generator utilizing precomputed attack data from [Shattered.io](https://shattered.io/).
  - Combined MAC collision finder leveraging both KeeLoq MACs and SHA1.

- **Performance**:
  - Optimized for quick collision finding (under a few minutes for 4-byte MACs).
  - Tested for smaller tag sizes to ensure reasonable runtime.

---

## **Files and Structure**

- `code.py`: Implementation of all tasks, including KeeLoq CBC, MACs, and collision finding.
- `keeloq.py`, `utils.py`, `macs.py`: Provided library files used as dependencies for KeeLoq operations and utilities.
- `keeloq_cbc_test_vectors.json`, `mac_keeloq_test_vectors.json`: Test vectors for validating CBC and MAC functionality.
- `description.txt`: Explanations of the attacks, principles, and collision resistance analysis.

---

## **Tasks and Implementation Details**

### Task 1: KeeLoq CBC and MAC Implementation
- **CBC Mode**: The `keeloq_cbc_enc` function encrypts messages using KeeLoq in Cipher Block Chaining mode.
- **MAC**: The `mac_keeloq` function computes a vanilla CBC-based MAC, with support for variable-length tags up to 4 bytes.

### Task 2: Collision Finding
- **MAC Collision**: Implements `mac_keeloq_collision` to find two distinct messages with the same MAC tag.
- **SHA1 Collision**: Uses precomputed SHA1 collision blocks to generate special collisions.
- **Combined MAC Attack**: Implements `mac_combined_collision` to find collisions in a scheme combining KeeLoq MACs and SHA1 hashes.

### Task 3: Cryptographic Analysis
- Discusses:
  - Runtime and principles of collision-finding attacks.
  - Special properties of SHA1 collisions.

---
