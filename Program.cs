using System.Security.Cryptography;
using System.Text;
using System;
using Isopoh.Cryptography.Argon2;
using NSec.Cryptography;

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
    //        // IV: Initialization Vector, a random value that is so the same plaintext will encrypt to a different ciphertext.
    //        byte[] iv = GenerateIV();
    //        // Plaintext: Original message that will be encrypted.
    //        byte[] plaintext = Encoding.UTF8.GetBytes("Durial123 was a Legendary Player");
    //        // Ciphertext: Encrypted message that will be decrypted.
    //        byte[] ciphertext = new byte[plaintext.Length];
    //        // Tag: Authentication tag that is used to verify the integrity of the message.
    //        byte[] tag = new byte[16];

    //        // Encrypt the plaintext message.
    //        aes.Encrypt(iv, plaintext, ciphertext, tag);
    //        Console.WriteLine($"Encrypted: {Convert.ToBase64String(ciphertext)}");
    //        //Encrypted: Sggx6WyHuopR3hSBncIzvqkqxfoAK+JDkE/6zXPvOTo=

    //        byte[] decrypted = new byte[plaintext.Length];
    //        aes.Decrypt(iv, ciphertext, tag, decrypted);
    //        Console.WriteLine($"Decrypted: {Encoding.UTF8.GetString(decrypted)}");
    //        //Decrypted: Durial123 was a Legendary Player
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
    //    string message = "Æbler er bedre end appelsiner";
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
    //    string message = "Kunne skrive Hello World, men det ville da være lidt kedeligt";
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
    /// Steve and Bob each generate a private key and a public key.
    /// Each person uses their private key and the other person's public key to compute the same shared secret key
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
    /// Library needed: NSec.Cryptography - dotnet add package NSec.Cryptography
    /// </summary>
    //static void Main()
    //{
    //    //ED25519 key pair
    //    var algorithm = SignatureAlgorithm.Ed25519;
    //    using var key = Key.Create(algorithm);

    //    //Sign a message
    //    byte[] message = Encoding.UTF8.GetBytes("You know you want to sign me..!");
    //    //Sign the message
    //    byte[] signature = algorithm.Sign(key, message);
    //    Console.WriteLine($"Signature: {Convert.ToBase64String(signature)}");

    //    //Verify the signature
    //    bool isValid = algorithm.Verify(key.PublicKey, message, signature);
    //    Console.WriteLine($"Signature is valid: {isValid}");

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
    //        byte[] data = Encoding.UTF8.GetBytes("Man har en plan...til man laver en ny!");
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
        string hashedPassword = Argon2.Hash(password, type: Argon2Type.HybridAddressing);
        Console.WriteLine($"Hashed Password: {hashedPassword}");
        //Hashed Password: $argon2id$v=19$m=65536,t=3,p=1$LosKGmDJ7o+WXGdAgE9Maw$y9JnepM3DZgvchVBaV4TfHLKh/oltfw3bFDaQdZuo9Y

        Console.WriteLine($"Password Match: {Argon2.Verify(hashedPassword, password)}");
        //Password Match: True

        byte[] salt = GenerateSalt();

        int iterations = 600000;
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, 32);
        Console.WriteLine($"Key: {BitConverter.ToString(key).Replace("-", "")}");
        //Key: 78FE829ECC36E454E47E82C6E766298FF7350C003E4E007EBC8F4D4CED06F7C1
    }
    static byte[] GenerateSalt(int size = 16)
    {
        byte[] salt = new byte[size];
        RandomNumberGenerator.Fill(salt);
        return salt;
    }
    #endregion PBKDF2-HMAC-SHA256 Key Derivation
}
