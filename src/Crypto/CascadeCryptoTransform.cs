// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2025 AnmiTaliDev

using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace ATE.Crypto;

/// <summary>
/// Implements cascading encryption transforms
/// </summary>
internal sealed class CascadeCryptoTransform : ICryptoTransform
{
    private readonly ICryptoTransform[] _transforms;
    private bool _disposed;

    /// <summary>
    /// Creates a new cascade transform with the given transforms
    /// </summary>
    public CascadeCryptoTransform(ICryptoTransform[] transforms)
    {
        _transforms = transforms ?? throw new ArgumentNullException(nameof(transforms));
        
        if (transforms.Length == 0)
            throw new ArgumentException("At least one transform required", nameof(transforms));
    }

    /// <summary>
    /// Creates AES transform
    /// </summary>
    public static ICryptoTransform CreateAesTransform(byte[] key, byte[] iv, bool forEncryption)
    {
        using var aes = Aes.Create();
        return forEncryption
            ? aes.CreateEncryptor(key, iv)
            : aes.CreateDecryptor(key, iv);
    }

    /// <summary>
    /// Creates Twofish transform
    /// </summary>
    public static ICryptoTransform CreateTwofishTransform(byte[] key, byte[] iv, bool forEncryption)
    {
        var engine = new TwofishEngine();
        var blockCipher = new CbcBlockCipher(engine);
        var paddedCipher = new PaddedBufferedBlockCipher(blockCipher);
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);
        
        paddedCipher.Init(forEncryption, parameters);
        return new BufferedTransform(paddedCipher);
    }

    /// <summary>
    /// Creates Serpent transform
    /// </summary>
    public static ICryptoTransform CreateSerpentTransform(byte[] key, byte[] iv, bool forEncryption)
    {
        var engine = new SerpentEngine();
        var blockCipher = new CbcBlockCipher(engine);
        var paddedCipher = new PaddedBufferedBlockCipher(blockCipher);
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);
        
        paddedCipher.Init(forEncryption, parameters);
        return new BufferedTransform(paddedCipher);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        
        foreach (var transform in _transforms)
            transform.Dispose();
            
        _disposed = true;
    }

    /// <inheritdoc/>
    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(CascadeCryptoTransform));

        var tempBuffer = new byte[inputCount];
        Buffer.BlockCopy(inputBuffer, inputOffset, tempBuffer, 0, inputCount);
        
        for (var i = 0; i < _transforms.Length; i++)
        {
            var transform = _transforms[i];
            var isLast = i == _transforms.Length - 1;
            
            if (isLast)
            {
                return transform.TransformBlock(tempBuffer, 0, tempBuffer.Length, outputBuffer, outputOffset);
            }
            
            var nextBuffer = new byte[tempBuffer.Length];
            transform.TransformBlock(tempBuffer, 0, tempBuffer.Length, nextBuffer, 0);
            tempBuffer = nextBuffer;
        }

        return inputCount;
    }

    /// <inheritdoc/>
    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(CascadeCryptoTransform));

        var tempBuffer = new byte[inputCount];
        Buffer.BlockCopy(inputBuffer, inputOffset, tempBuffer, 0, inputCount);
        
        for (var i = 0; i < _transforms.Length; i++)
        {
            var transform = _transforms[i];
            tempBuffer = transform.TransformFinalBlock(tempBuffer, 0, tempBuffer.Length);
        }

        return tempBuffer;
    }

    /// <inheritdoc/>
    public bool CanReuseTransform => false;

    /// <inheritdoc/> 
    public bool CanTransformMultipleBlocks => true;

    /// <inheritdoc/>
    public int InputBlockSize => _transforms[0].InputBlockSize;

    /// <inheritdoc/>
    public int OutputBlockSize => _transforms[^1].OutputBlockSize;

    /// <summary>
    /// Adapter for BouncyCastle block ciphers
    /// </summary>
    private sealed class BufferedTransform : ICryptoTransform 
    {
        private readonly IBufferedCipher _cipher;
        private bool _disposed;

        public BufferedTransform(IBufferedCipher cipher)
        {
            _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        }

        public void Dispose()
        {
            _disposed = true;
        }

        public bool CanReuseTransform => false;
        public bool CanTransformMultipleBlocks => true;
        public int InputBlockSize => _cipher.GetBlockSize();
        public int OutputBlockSize => _cipher.GetBlockSize();

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(BufferedTransform));

            return _cipher.ProcessBytes(
                inputBuffer, inputOffset, inputCount,
                outputBuffer, outputOffset);
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(BufferedTransform));

            return _cipher.DoFinal(inputBuffer, inputOffset, inputCount);
        }
    }
}