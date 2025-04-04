// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2025 AnmiTaliDev

using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Binding;
using ATE.Models;
using ATE.Utils;
using ATE.Crypto;

namespace ATE;

/// <summary>
/// Command-line interface for file encryption
/// </summary>
internal static class FileEncryptor
{
    /// <summary>
    /// Creates and processes command line arguments
    /// </summary>
    internal static async Task<int> ProcessCommandLine(string[] args)
    {
        var rootCommand = new RootCommand("AnmiTali Encryption tool")
        {
            CreateEncryptCommand(),
            CreateDecryptCommand()
        };

        return await rootCommand.InvokeAsync(args);
    }

    private static Command CreateEncryptCommand()
    {
        var inputOption = new Option<FileInfo>(
            new[] { "-i", "--input" },
            "Input file to encrypt"
        ) { IsRequired = true };

        var outputOption = new Option<FileInfo>(
            new[] { "-o", "--output" },
            "Output encrypted file"
        ) { IsRequired = true };

        var passwordOption = new Option<string>(
            new[] { "-p", "--password" },
            "Encryption password"
        ) { IsRequired = true };

        var masterKeyOption = new Option<string>(
            new[] { "-m", "--master-key" },
            "Master encryption key"
        ) { IsRequired = true };

        var algorithmOption = new Option<CipherAlgorithm>(
            new[] { "-a", "--algorithm" },
            () => CipherAlgorithm.Maximum,
            "Encryption algorithm"
        );

        var command = new Command("encrypt", "Encrypt a file");
        command.AddOption(inputOption);
        command.AddOption(outputOption);
        command.AddOption(passwordOption);
        command.AddOption(masterKeyOption);
        command.AddOption(algorithmOption);

        command.SetHandler(async (context) =>
        {
            var parameters = new EncryptionParameters
            {
                InputPath = context.ParseResult.GetValueForOption(inputOption)!.FullName,
                OutputPath = context.ParseResult.GetValueForOption(outputOption)!.FullName,
                Password = context.ParseResult.GetValueForOption(passwordOption)!,
                MasterKey = context.ParseResult.GetValueForOption(masterKeyOption)!,
                Algorithm = context.ParseResult.GetValueForOption(algorithmOption),
                Mode = OperationMode.Encrypt
            };

            await Process(parameters);
        });

        return command;
    }

    private static Command CreateDecryptCommand()
    {
        var inputOption = new Option<FileInfo>(
            new[] { "-i", "--input" },
            "Input file to decrypt"
        ) { IsRequired = true };

        var outputOption = new Option<FileInfo>(
            new[] { "-o", "--output" },
            "Output decrypted file"
        ) { IsRequired = true };

        var passwordOption = new Option<string>(
            new[] { "-p", "--password" },
            "Decryption password"
        ) { IsRequired = true };

        var masterKeyOption = new Option<string>(
            new[] { "-m", "--master-key" },
            "Master decryption key"
        ) { IsRequired = true };

        var algorithmOption = new Option<CipherAlgorithm>(
            new[] { "-a", "--algorithm" },
            () => CipherAlgorithm.Maximum,
            "Decryption algorithm"
        );

        var command = new Command("decrypt", "Decrypt a file");
        command.AddOption(inputOption);
        command.AddOption(outputOption);
        command.AddOption(passwordOption);
        command.AddOption(masterKeyOption);
        command.AddOption(algorithmOption);

        command.SetHandler(async (context) =>
        {
            var parameters = new EncryptionParameters
            {
                InputPath = context.ParseResult.GetValueForOption(inputOption)!.FullName,
                OutputPath = context.ParseResult.GetValueForOption(outputOption)!.FullName,
                Password = context.ParseResult.GetValueForOption(passwordOption)!,
                MasterKey = context.ParseResult.GetValueForOption(masterKeyOption)!,
                Algorithm = context.ParseResult.GetValueForOption(algorithmOption),
                Mode = OperationMode.Decrypt
            };

            await Process(parameters);
        });

        return command;
    }

    private static async Task Process(EncryptionParameters parameters)
    {
        try
        {
            parameters.Validate();

            using var progress = new ProgressBar();
            var fileInfo = new FileInfo(parameters.InputPath);
            var totalBytes = fileInfo.Length;

            if (parameters.Mode == OperationMode.Encrypt)
            {
                await CryptoEngines.EncryptFileAsync(
                    parameters.InputPath,
                    parameters.OutputPath,
                    parameters.Password,
                    parameters.MasterKey,
                    parameters.Algorithm);
            }
            else
            {
                await CryptoEngines.DecryptFileAsync(
                    parameters.InputPath,
                    parameters.OutputPath,
                    parameters.Password,
                    parameters.MasterKey,
                    parameters.Algorithm);
            }

            Console.WriteLine($"\nDone! Output file: {parameters.OutputPath}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            Environment.Exit(1);
        }
    }
}