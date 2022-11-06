Task A [Key Derivation Function (KDF)]

In this task there is the implementation of an RSA key-pair generation algorithm. 
The key generation process is the following:
1. Generate a pool of primes using the Sieve Of Eratosthenes. The sieve’s limit is defined 
    in the provided file, rsa.h.
2. Pick two random primes from the pool, p and q.
3. Compute n where n = p * q.
4. Calculate fi(n) where fi(n) = (p - 1) * (q - 1). This is Euler’s totient function, as described
in the original RSA paper "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems”.
5. Choose a prime number e where (e % fi(n) != 0) AND (gcd(e, fi(n)) == 1) where gcd() is
    the Greatest Common Denominator.
6. Choose d where d is the modular inverse of (e,fi(n)).
7. The public key consists of n and d, in this order .
8. The private key consists of n and e, in this order.



Task B [Data Encryption]

Implementation of a function that provides RSA encryption functionality, using the keys generated in the
previous step. This function reads the data of an input file and encrypts them using one of the
generated keys. Then, it stores the ciphertext to an output file. For each character (1-byte) of
the plaintext, the tool generates an 8-byte ciphertext (size_t on 64-bit machines). For
example, if the plaintext is “hello” then the 5 bytes (5 chars) of the plaintext will produce 40-
bytes (5 * sizeof(size_t)) of ciphertext. The encryption uses the mod_exp() function that was developed 
for modular exponentiation.



Task C [Data Decryption]

Implementation of a function that reads a ciphertext from an input file and performs RSA decryption
using the appropriate one of the two keys, depending on which one was used for the ciphertext
encryption. The keys will be generated using the KDF described in Task A. When the decryption
is over, the function stores the plaintext in an appropriate output file. The decryption uses also 
the mod_exp() function for modular exponentiation.



Task D [Using the tool]

0) Generate public and private keys
./assign_3 -g

1) Encrypt using public key 
./assign_3 -i hpy414_encryptme_pub.txt -o TUC2016030032_encrypted_pub.txt -k hpy414_public.key -e

2) Decrypt using public key  
./assign_3 -i hpy414_decryptme_pub.txt -o TUC2016030032_decrypted_pub.txt -k hpy414_public.key -d

3) Encrypt using private key 
./assign_3 -i hpy414_encryptme_priv.txt -o TUC2016030032_encrypted_priv.txt -k hpy414_private.key -e

4) Decrypt using private key  
./assign_3 -i hpy414_decryptme_priv.txt -o TUC2016030032_decrypted_priv.txt -k hpy414_private.key -d



gcc --version: (Ubuntu 9.3.0-17ubuntu1~20.04)

Useful links:
https://en.wikipedia.org/wiki/RSA_(cryptosystem)
https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/
