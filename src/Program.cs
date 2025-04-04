// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2025 AnmiTaliDev

using System.CommandLine;
using ATE.Models;
using ATE.Utils;

namespace ATE;

/// <summary>
/// Main application entry point
/// </summary>
internal static class Program
{
    /// <summary>
    /// Application entry point
    /// </summary>
    private static Task<int> Main(string[] args)
    {
        // Initialize logging and handle unhandled exceptions
        AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
        {
            Console.Error.WriteLine($"Fatal error: {e.ExceptionObject}");
            Environment.Exit(1);
        };

        // Set up console
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.Title = "AnmiTali Encryption";

        try
        {
            return FileEncryptor.ProcessCommandLine(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unhandled error: {ex.Message}");
            return Task.FromResult(1);
        }
    }

    /// <summary>
    /// Shows application help
    /// </summary>
    private static void ShowHelp()
    {
        Console.WriteLine(@"
AnmiTali Encryption (ATE) Tool
===================================

Commands:
  encrypt - Encrypt a file
    Options:
      -i, --input <file>      Input file to encrypt (required)
      -o, --output <file>     Output encrypted file (required)  
      -p, --password <text>   Encryption password (required)
      -m, --master-key <text> Master encryption key (required)
      -a, --algorithm <alg>   Encryption algorithm (default: Maximum)
                             Supported algorithms: AES, Twofish, Serpent,
                             AES_Twofish, AES_Serpent, Maximum

  decrypt - Decrypt a file  
    Options:
      -i, --input <file>      Input file to decrypt (required)
      -o, --output <file>     Output decrypted file (required)
      -p, --password <text>   Decryption password (required) 
      -m, --master-key <text> Master decryption key (required)
      -a, --algorithm <alg>   Decryption algorithm (default: Maximum)

Examples:
  ate encrypt -i secret.doc -o secret.enc -p mypass -m masterkey
  ate decrypt -i secret.enc -o secret.doc -p mypass -m masterkey -a AES_Twofish

For more information visit: https://github.com/AnmiTaliDev/ate
");
    }

    /// <summary>
    /// Gets application version
    /// </summary>
    private static string GetVersion()
    {
        var assembly = typeof(Program).Assembly;
        var version = assembly.GetName().Version;
        return version?.ToString() ?? "1.0.0";
    }

    /// <summary>
    /// Shows program version
    /// </summary>
    private static void ShowVersion()
    {
        Console.WriteLine($"AnmiTali Encryption v{GetVersion()}");
        Console.WriteLine("Copyright (c) 2025 AnmiTaliDev");
    }
}