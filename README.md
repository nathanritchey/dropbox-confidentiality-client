# Dropbox Confidentiality Client

This project implements a smarter end to end encryption solution for files hosted on Dropbox. It aims to solve three problems with vanilla Dropbox and of existing encryption plugins for Dropbox:

1. Efficient encryption when changes are made
2. Ensure the integrity of all files
3. Prevent key rot by routine rotation and diversity of keys

## Efficient Encryption

Given a file of size n bits, we divide the file into blocks of q bits. Such that the number of blocks will be the cieling of n/q. Each block will be encrypted with the same key but separately. The idea is that when a file changes only the affected blocks are reencrypted.

### How to determine the optimal q-bits?

If q-bits is large enough too many blocks will be created rendering the encryption useless. We want to divide the files in such a way that we save on time to encrypt but still minimize the loss in security from having smaller pretext. The running idea is the q-bit value is less than having the encryption easily broken and more than enough to have a benefit in savings of less rigorous encryption.

## Integrity

Given a file we want to ensure that when it is put together the user can verify that the file was not modified in any way. We do this prior to the encryption. We want to derive a keyed hash of the file using SHA3.

## Key Rot

Given many files we want to use different keys. The number of keys in the brute force approach will be equal to the number of files. In the more optimized approach we want at minimum 2 keys. The question to answer is what is the optimal number of keys. Further we want to prevent key rot, such that keys should be changed after a certain interval. The idea is to reasonably reduce the probability that an adversary can derive the key in this time interval.

## Key derivation

To ensure confidentiality and integrity we need at least two keys. PBKDF2 can be used to derive keys. The idea is as followed, consider a key file. The key file will contiain two AES keys which are for signing and encrypting respectively. The key file is encrypted using AES where the key is derived from a user provided password. This is done by combining the password with a unique token generated randomly and running PBKDF2 on this string. This randomly unique token is something the user will need to have. Used properly this ensures two factors of authentication. Further this token ensures that the required amount of entropy has been met. Iterations for PBKDF2 do not have to be confidential but we will make this the case by including it in the preamble of the unique token.

## Further Work

1. How to encrypt and integrity-protect data when sharing between multiple users in Dropbox?
2. Can we distribute files across users who are not running this special client yet retain confidentiality?
