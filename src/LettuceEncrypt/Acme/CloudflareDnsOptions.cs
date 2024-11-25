// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Acme;

/// <summary>
/// Options for Cloudflare DNS challenge provider.
/// </summary>
public class CloudflareDnsOptions
{
    private string _key = string.Empty;
    private string _zoneId = string.Empty;

    /// <summary>
    /// API key for Cloudflare API.
    /// </summary>
    public string Key
    {
        get => _key;
        set => _key = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// DNS zone ID for the domain.
    /// </summary>
    public string ZoneId
    {
        get => _zoneId;
        set => _zoneId = value ?? throw new ArgumentNullException(nameof(value));
    }
}
