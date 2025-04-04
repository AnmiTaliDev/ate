// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2025 AnmiTaliDev

namespace ATE.Models;

/// <summary>
/// Supported encryption algorithms
/// </summary>
public enum CipherAlgorithm
{
    /// <summary>
    /// AES-256 in CBC mode
    /// </summary>
    AES,

    /// <summary>
    /// Twofish-256 in CBC mode
    /// </summary>
    Twofish,

    /// <summary>
    /// Serpent-256 in CBC mode
    /// </summary>
    Serpent,

    /// <summary>
    /// Cascaded AES + Twofish
    /// </summary>
    AES_Twofish,

    /// <summary>
    /// Cascaded AES + Serpent
    /// </summary>
    AES_Serpent,

    /// <summary>
    /// Maximum security - AES + Twofish + Serpent
    /// </summary>
    Maximum
}