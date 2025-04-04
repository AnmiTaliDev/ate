// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2025 AnmiTaliDev

using System.Security.Cryptography;
using System.Text;
using ATE.Models;

namespace ATE.Crypto;

/// <summary>
/// Provides cryptographic transformations for file encryption
/// </summary>
internal static class CryptoEngines
{
    private const int KeySize = 32; // 256 bits
    private const int IvSize = 16;  // 128 bits
    private static readonly byte[] Salt = new byte[] { 
        0x43, 0x87, 0x23, 0x72, 0x45, 0x56, 0x89, 0x12,
        0x34, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
    };

    /// <summary>
    /// Encrypts a file using the specified algorithm
    /// </summary>
    public static async Task EncryptFileAsync(
        string inputPath,
        string outputPath,
        string password,
        string masterKey,
        CipherAlgorithm algorithm)
    {
        // Generate key and IV
        using var keyDerivation = new Rfc2898DeriveBytes(
            password,
            Salt,
            10000,
            HashAlgorithmName.SHA256);

        byte[] key = keyDerivation.GetBytes(KeySize);
        byte[] iv = GenerateIV(masterKey);

        await using var input = File.OpenRead(inputPath);
        await using var output = File.Create(outputPath);
        
        // Write IV at the beginning of the file
        await output.WriteAsync(iv);

        using var transform = CreateTransform(key, iv, algorithm, forEncryption: true);
        using var cryptoStream = new CryptoStream(output, transform, CryptoStreamMode.Write, leaveOpen: true);
        
        await input.CopyToAsync(cryptoStream);
        await cryptoStream.FlushFinalBlockAsync(); // Important for proper padding
    }

    /// <summary>
    /// Decrypts a file using the specified algorithm
    /// </summary>
    public static async Task DecryptFileAsync(
        string inputPath,
        string outputPath,
        string password,
        string masterKey,
        CipherAlgorithm algorithm)
    {
        // Generate key (IV will be read from file)
        using var keyDerivation = new Rfc2898DeriveBytes(
            password,
            Salt,
            10000,
            HashAlgorithmName.SHA256);

        byte[] key = keyDerivation.GetBytes(KeySize);
        
        await using var input = File.OpenRead(inputPath);
        await using var output = File.Create(outputPath);

        // Read IV from the beginning of the file
        byte[] iv = new byte[IvSize];
        await input.ReadAsync(iv.AsMemory(0, IvSize));

        using var transform = CreateTransform(key, iv, algorithm, forEncryption: false);
        using var cryptoStream = new CryptoStream(input, transform, CryptoStreamMode.Read);
        
        await cryptoStream.CopyToAsync(output);
    }

    /// <summary>
    /// Creates encryption transform based on algorithm
    /// </summary>
    private static ICryptoTransform CreateTransform(byte[] key, byte[] iv, CipherAlgorithm algorithm, bool forEncryption)
    {
        return algorithm switch
        {
            CipherAlgorithm.AES => CascadeCryptoTransform.CreateAesTransform(key, iv, forEncryption),
            CipherAlgorithm.Twofish => CascadeCryptoTransform.CreateTwofishTransform(key, iv, forEncryption),
            CipherAlgorithm.Serpent => CascadeCryptoTransform.CreateSerpentTransform(key, iv, forEncryption),
            CipherAlgorithm.AES_Twofish => new CascadeCryptoTransform(new[]
            {
                CascadeCryptoTransform.CreateAesTransform(key, iv, forEncryption),
                CascadeCryptoTransform.CreateTwofishTransform(key, iv, forEncryption)
            }),
            CipherAlgorithm.AES_Serpent => new CascadeCryptoTransform(new[]
            {
                CascadeCryptoTransform.CreateAesTransform(key, iv, forEncryption),
                CascadeCryptoTransform.CreateSerpentTransform(key, iv, forEncryption)
            }),
            CipherAlgorithm.Maximum => new CascadeCryptoTransform(new[]
            {
                CascadeCryptoTransform.CreateAesTransform(key, iv, forEncryption),
                CascadeCryptoTransform.CreateTwofishTransform(key, iv, forEncryption),
                CascadeCryptoTransform.CreateSerpentTransform(key, iv, forEncryption)
            }),
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}", nameof(algorithm))
        };
    }

    /// <summary>
    /// Generates IV from master key
    /// </summary>
    private static byte[] GenerateIV(string masterKey)
    {
        using var sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(masterKey));
        return hash[..IvSize];
    }
}