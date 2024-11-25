// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt;
using LettuceEncrypt.Acme;
using LettuceEncrypt.Internal;
using Microsoft.Extensions.DependencyInjection.Extensions;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extensions to integrate Cloudflare with LettuceEncrypt.
/// </summary>
public static class CloudflareLettuceEncryptExtensions
{
    /// <summary>
    /// Use Cloudflare DNS challenge provider.
    /// </summary>
    public static ILettuceEncryptServiceBuilder CloudflareDnsChallenge(this ILettuceEncryptServiceBuilder builder)
    {
        builder.Services.RemoveAll<IDnsChallengeProvider>();
        builder.Services.AddSingleton<IDnsChallengeProvider, CloudflareDnsChallengeProvider>();
        return builder;
    }
}
