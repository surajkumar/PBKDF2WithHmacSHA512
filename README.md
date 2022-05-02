# PBKDF2WithHmacSHA512

## Introduction
The PBKDF2WithHmacSHA512 is a cryptographic function that turns a plaintext into an encrypted ciper text that cannot be understood by a normal person or machine. This is perfect for when data needs to be transmitted or stored securely.

[PBKDF](https://en.wikipedia.org/wiki/PBKDF2):
> Password-based-Key-Derivative-Function used to implement a a pseudorandom function.

In essense, this takes our cryptographic [Hash](https://en.wikipedia.org/wiki/Hash_function) and [HMAC](https://en.wikipedia.org/wiki/HMAC) 
alongside a randomly generated [Salt](https://en.wikipedia.org/wiki/Salt_(cryptography)) value to derive a cryptographic key for encryption.

[HMAC](https://en.wikipedia.org/wiki/HMAC)
> Keyed-Hash Message Authentication Code
> 
HMAC is a specific construction for calculating [MAC](https://en.wikipedia.org/wiki/Message_authentication_code) to be used in combination with our hash function and secret cryptographic key. In this case, we use the SHA512 for calculating our hash.

### Usage:
To use the small snippet of code that is part of this repository. You must first add the PBKDF2WithHmacSHA512.java to your project. This class uses no dependencies and relies on the ciper to already be present on your system.

See the following code for the entire usage:

```
/** Create a random salt for encryption */
byte[] salt = PBKDF2WithHmacSHA512.salt();
/** Generate a Hash using the generated salt */
byte[] hash = PBKDF2WithHmacSHA512.hash(password, salt);

// The hash and salt must be persisted together. If we lose the salt or hash, the encrypted text will never be recoverable.

/** Authentication */
boolean authenticated = PBKDF2WithHmacSHA512.authenticate(attemptedPassword, salt, hash);
```

## Contributing
Contributions are welcome whether it is for small bug fixes or new pieces of major functionality. To contribute changes, you should first fork the upstream repository to your own GitHub account. You can then add a new remote for `upstream` and rebase any changes you make and keep up-to-date with the upstream.

`git remote add upstream https://github.com/skdev/RuneScape-Private-Server.git`

## Acknowledgements
The code provided is a wrapper of the existing functions built into the JDK. The PBKDF2WithHmacSHA512 is not re-created from scratch in this repository. As such, the cryptographic cipher must be available on your system.

