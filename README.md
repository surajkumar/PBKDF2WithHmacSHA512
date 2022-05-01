# PBKDF2WithHmacSHA512
This small and simple repository contains code that allows you to encrypt strings using a strong cryptographic cipher. The utility is perfect for encrypting sentitive data such as cryptographic keys or user passwords.

It uses a "salt" and "hash" method for cryptography.

To generate a salt:

  byte[] salt = PBKDF2WithHmacSHA512.salt();
  
Then to generate the hash:

  byte[] hash = PBKDF2WithHmacSHA512.hash(password, salt);
  
To authenticate:

  boolean authenticated = PBKDF2WithHmacSHA512.authenticate(attemptedPassword, salt, hash);
  
If you lose the salt, you cannot ever authenticate the password.
