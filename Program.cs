using System.Security.Cryptography;
using System.Text;
using System;
using Isopoh.Cryptography.Argon2;

class Program
{
    #region Cryptographically Secure Random Number Generator
    /// <summary>
    /// Cryptographically Secure Random Number Generator
    /// Use secure random generate to generate a 256 bit value that can be used as encryption key
    /// Note: Produces higher quality of randomness, but is slower and more CPU intensive than a PRNG.
    /// For C# use Random() and RandomNumberGenerator() classes.
    /// Documentation: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator?view=net-9.0
    /// </summary>
    //static void Main()
    //{
    //    byte[] key = new byte[32]; //256 bits
    //    using (var rng = RandomNumberGenerator.Create())
    //    {
    //        rng.GetBytes(key);
    //    }
    //    Console.WriteLine(BitConverter.ToString(key).Replace("-", ""));
    //}
    #endregion Cryptographically Secure Random Number Generator

    #region AES-256-GCM Encryption/Decryption

    /// <summary>
    /// Shared-Key Encryption using AES-256-GCM or AES-256-CBC to encrypt and decrypt a message.
    /// AES: Advanced Encryption Standard, key size of 256bit, used in Galois/counter(GCM) or CBC(Cipher Block Chaining) mode.
    /// Example has to encrypt a message and decrypt it after.
    /// IV: Initialization Vector, a random value that is used to ensure that the same plaintext will encrypt to a different ciphertext.
    /// </summary>
    //static void Main()
    //{
    //    using (var aes = new AesGcm(GenerateKey()))
    //    {
    //        byte[] iv = GenerateIV();
    //        byte[] plaintext = Encoding.UTF8.GetBytes("Hello World!");
    //        byte[] ciphertext = new byte[plaintext.Length];
    //        byte[] tag = new byte[16]; 

    //        aes.Encrypt(iv, plaintext, ciphertext, tag);
    //        Console.WriteLine($"Encrypted: {Convert.ToBase64String(ciphertext)}");
    //        //Encrypted: dd/6+0VJggBqDsUx


    //        byte[] decrypted = new byte[plaintext.Length];
    //        aes.Decrypt(iv, ciphertext, tag, decrypted);
    //        Console.WriteLine($"Decrypted: {Encoding.UTF8.GetString(decrypted)}");
    //        //Decrypted: Hello World!
    //    }
    //}

    //private static byte[] GenerateKey() => RandomNumberGenerator.GetBytes(32); 
    //private static byte[] GenerateIV() => RandomNumberGenerator.GetBytes(12);
    #endregion AES-256-GCM Encryption/Decryption

    #region SHA512 Hashing
    /// <summary>
    /// SHA512 to generate hash of an input message.
    /// </summary>
    //static void Main()
    //{
    //    string message = "Hello World!";
    //    byte[] hash = SHA512.HashData(Encoding.UTF8.GetBytes(message));
    //    Console.WriteLine($"SHA512 Hash: {BitConverter.ToString(hash).Replace("-", "")}");

    //}
    #endregion SHA512 Hasing

    #region HMAC-SHA256
    /// <summary>
    /// Function an example that have a function to generate a hash based message auth(HMAC) using HMAC-SHA256 and function to verify HMAC
    /// </summary>
    //static void Main()
    //{
    //    byte[] key = RandomNumberGenerator.GetBytes(32);
    //    string message = "Hello World!";
    //    using (var hmac = new HMACSHA256(key))
    //    {
    //        byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
    //        Console.WriteLine($"HMAC-SHA256: {BitConverter.ToString(hash).Replace("-", "")}");
    //    }   
    //}
    #endregion HMAC-SHA256

    #region Curve25519 ECDH Key Exchange
    /// <summary>
    /// Use Curve25519 to perform ECDH key exchange between two parties to compute the same shared secret.
    /// ECDH: Elliptic Curve Diffie-Hellman, a key exchange algorithm that allows two parties to securely compute a shared secret.
    /// Curve25519: An elliptic curve that is used in ECDH key exchange.
    /// </summary>
    //static void Main()
    //{
    //    using (var steve = ECDiffieHellman.Create(ECCurve.CreateFromFriendlyName("curve25519"))) 
    //    using (var bob = ECDiffieHellman.Create(ECCurve.CreateFromFriendlyName("curve25519")))
    //    {
    //        byte[] steveKey = steve.DeriveKeyMaterial(bob.PublicKey);
    //        byte[] bobKey = bob.DeriveKeyMaterial(steve.PublicKey);
    //        Console.WriteLine(Convert.ToBase64String(steveKey) == Convert.ToBase64String(bobKey) ? "Shared keys match!" : "Error");
    //    } 

    //}
    #endregion Curve25519 ECDH Key Exchange

    #region ED25519 Digital Signature
    /// <summary>
    /// Example of how to use ED25519 to sign a message and verify the signature.
    /// ED25519: Short for Edwards-curve Digital Signature Algorithm(EdDSA) with curve25519.
    /// </summary>
    //static void Main()
    //{
    //    using(var ed25519 = ECDsa.Create(ECCurve.CreateFromFriendlyName("ed25519")))
    //    {
    //        byte[] message = Encoding.UTF8.GetBytes("Sign me");
    //        byte[] signature = ed25519.SignData(message, HashAlgorithmName.SHA512);
    //        Console.WriteLine(Convert.ToBase64String(signature));
    //    }
    //}
    #endregion ED25519 Digital Signature

    #region RSA Encryption/Decryption
    /// <summary>
    /// Encrypt with RSA and decrypt with RSA.
    /// </summary>
    //static void Main()
    //{
    //    using (RSA rsa = RSA.Create(2048))
    //    {
    //        byte[] data = Encoding.UTF8.GetBytes("Hello World!");
    //        byte[] encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    //        Console.WriteLine($"Encrypted: {Convert.ToBase64String(encrypted)}");

    //        byte[] decrypted = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
    //        Console.WriteLine($"Decrypted: {Encoding.UTF8.GetString(decrypted)}");
    //    }

    //}
    #endregion RSA Encryption/Decryption

    #region PBKDF2-HMAC-SHA256 Key Derivation
    /// <summary>
    /// Use PBKDF2-HMAC-SHA256 to derive a key from a password using Argon2id.
    /// PBKDF2: Password-Based Key Derivation Function 2, uses HMAC-SHA512 as the underlaying algorithm.
    /// OWASP recommends 600.000 iterations for password hashing.
    /// Rasmus recommends Argon2id for password storage, it is not part of .NET
    /// Install: Isopoh.Cryptography.Argon2 with dotnet add package Isopoh.Cryptography.Argon2
    /// </summary>
    static void Main()
    {
        string password = "securepassword";
        string hashedPassword = HashPasswordArgon2id(password);
        Console.WriteLine($"Hashed Password: {hashedPassword}");
        //Hashed Password: $argon2id$v=19$m=65536,t=3,p=1$a8dFk75BRVCgUEYQYbGwuQ$KF+xIPxP1Y3JRKJ8zdvOwbl5/bI9F2Ntm8haj4zgI0Q

        bool isMatch = VerifyPasswordArgon2id(password, hashedPassword);
        Console.WriteLine($"Password Match: {isMatch}");
        //Password Match: True

        byte[] salt = GenerateSalt(16);

        int iterations = 600000;
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, 32);
        Console.WriteLine($"Key: {BitConverter.ToString(key).Replace("-", "")}");
        //Key: 8F7F42646CA93A0B673374A54980D99B9C54DFE2DC7421F7D59FC5DEC0E7B665
    }
    static byte[] GenerateSalt(int size)
    {
        byte[] salt = new byte[size];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        return salt;
    }
    static string HashPasswordArgon2id(string password)
    {
        return Argon2.Hash(password, type: Argon2Type.HybridAddressing);
    }
    static bool VerifyPasswordArgon2id(string password, string hashPassword)
    {
        return Argon2.Verify(hashPassword, password);
    }
    #endregion PBKDF2-HMAC-SHA256 Key Derivation
}
