// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2025 AnmiTaliDev

namespace ATE.Models;

/// <summary>
/// Encryption operation mode
/// </summary>
public enum OperationMode
{
    /// <summary>
    /// File encryption mode
    /// </summary>
    Encrypt,

    /// <summary>
    /// File decryption mode
    /// </summary>
    Decrypt
}

/// <summary>
/// Parameters for encryption/decryption operation
/// </summary>
public class EncryptionParameters
{
    /// <summary>
    /// Path to input file
    /// </summary>
    public required string InputPath { get; set; }

    /// <summary>
    /// Path to output file
    /// </summary>
    public required string OutputPath { get; set; }

    /// <summary>
    /// User password for encryption/decryption
    /// </summary>
    public required string Password { get; set; }

    /// <summary>
    /// Master key for IV generation
    /// </summary>
    public required string MasterKey { get; set; }

    /// <summary>
    /// Selected encryption algorithm
    /// </summary>
    public CipherAlgorithm Algorithm { get; set; }

    /// <summary>
    /// Operation mode (encrypt/decrypt)
    /// </summary>
    public OperationMode Mode { get; set; }

    /// <summary>
    /// Validates encryption parameters
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrEmpty(InputPath))
            throw new ArgumentException("Input file path is required", nameof(InputPath));

        if (string.IsNullOrEmpty(OutputPath))
            throw new ArgumentException("Output file path is required", nameof(OutputPath));

        if (string.IsNullOrEmpty(Password))
            throw new ArgumentException("Password is required", nameof(Password));

        if (string.IsNullOrEmpty(MasterKey))
            throw new ArgumentException("Master key is required", nameof(MasterKey));

        if (!File.Exists(InputPath))
            throw new FileNotFoundException("Input file not found", InputPath);

        var outputDir = Path.GetDirectoryName(OutputPath);
        if (!string.IsNullOrEmpty(outputDir) && !Directory.Exists(outputDir))
            throw new DirectoryNotFoundException("Output directory not found");
    }
}