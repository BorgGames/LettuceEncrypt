// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Text;
using System.Text.Json;
using LettuceEncrypt.Acme;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal;

/// <summary>
/// DNS challenge provider for Cloudflare.
/// </summary>
internal sealed class CloudflareDnsChallengeProvider : IDnsChallengeProvider, IDisposable
{
    private readonly HttpClient _http;
    private readonly IOptions<CloudflareDnsOptions> _options;
    private readonly ILogger<CloudflareDnsChallengeProvider> _logger;
    private string? _rootDomain;
    private const string BaseUrl = "https://api.cloudflare.com/client/v4";

    public CloudflareDnsChallengeProvider(IOptions<CloudflareDnsOptions> options,
        ILogger<CloudflareDnsChallengeProvider> logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        _http = new HttpClient();
        _http.DefaultRequestHeaders.Authorization = new("Bearer", _options.Value.Key);
        _http.DefaultRequestHeaders.Accept.Add(new("application/json"));
    }

    public async Task<DnsTxtRecordContext> AddTxtRecordAsync(string domainName, string txt,
        CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(domainName))
            throw new ArgumentNullException(nameof(domainName));
        if (string.IsNullOrEmpty(txt))
            throw new ArgumentNullException(nameof(txt));

        var relativeDomain = await GetRelativeDomainAsync(domainName, ct);

        _logger.LogInformation("Adding TXT record for domain {DomainName} in {Zone} with value {Txt}",
            domainName, _options.Value.ZoneId, txt);

        var recordData = new
        {
            type = "TXT",
            name = relativeDomain,
            content = txt,
            ttl = 120
        };

        var json = JsonSerializer.Serialize(recordData);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await _http.PostAsync(
            $"{BaseUrl}/zones/{_options.Value.ZoneId}/dns_records",
            content,
            ct
        );

        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync(ct);
            throw new HttpRequestException(
                $"Failed to add TXT record. Status: {response.StatusCode}, Error: {errorContent}"
            );
        }

        _logger.LogInformation("Added TXT record for domain {DomainName} in {Zone} with value {Txt}",
            domainName, _options.Value.ZoneId, txt);

        return new DnsTxtRecordContext(domainName, txt);
    }

    public async Task RemoveTxtRecordAsync(DnsTxtRecordContext context, CancellationToken ct = default)
    {
        if (context == null)
            throw new ArgumentNullException(nameof(context));

        _logger.LogInformation("Removing TXT record for domain {DomainName} in {Zone} with value {Txt}",
            context.DomainName, _options.Value.ZoneId, context.Txt);

        var relativeDomain = await GetRelativeDomainAsync(context.DomainName, ct);

        // First, find the record ID
        var recordsResponse = await _http.GetAsync(
            $"{BaseUrl}/zones/{_options.Value.ZoneId}/dns_records?type=TXT&name={relativeDomain}&content={context.Txt}",
            ct
        );

        if (!recordsResponse.IsSuccessStatusCode)
        {
            var errorContent = await recordsResponse.Content.ReadAsStringAsync(ct);
            throw new HttpRequestException(
                $"Failed to find TXT record. Status: {recordsResponse.StatusCode}, Error: {errorContent}"
            );
        }

        var responseContent = await recordsResponse.Content.ReadAsStringAsync(ct);
        using var document = JsonDocument.Parse(responseContent);

        var records = document.RootElement.GetProperty("result").EnumerateArray();
        var record = records.FirstOrDefault();

        if (record.ValueKind == JsonValueKind.Undefined)
        {
            throw new InvalidOperationException($"TXT record not found for domain {context.DomainName}");
        }

        var recordId = record.GetProperty("id").GetString();

        // Delete the record
        var deleteResponse = await _http.DeleteAsync(
            $"{BaseUrl}/zones/{_options.Value.ZoneId}/dns_records/{recordId}",
            ct
        );

        if (!deleteResponse.IsSuccessStatusCode)
        {
            var errorContent = await deleteResponse.Content.ReadAsStringAsync(ct);
            throw new HttpRequestException(
                $"Failed to delete TXT record. Status: {deleteResponse.StatusCode}, Error: {errorContent}"
            );
        }

        _logger.LogInformation("Removed TXT record for domain {DomainName} in {Zone} with value {Txt}",
            context.DomainName, _options.Value.ZoneId, context.Txt);
    }

    private async Task<string> GetRelativeDomainAsync(string domainName, CancellationToken ct = default)
    {
        var rootDomain = await GetRootDomainAsync(ct);
        if (domainName == rootDomain)
            return "@";
        if (!domainName.EndsWith($".{rootDomain}"))
            throw new ArgumentOutOfRangeException($"Domain {domainName} is not a subdomain of {rootDomain}");
        return domainName[..(domainName.Length - rootDomain.Length - 1)];
    }

    private async Task<string> GetRootDomainAsync(CancellationToken ct = default)
    {
        // Cache the root domain to avoid unnecessary API calls
        if (!string.IsNullOrEmpty(_rootDomain))
            return _rootDomain;

        _logger.LogInformation("Getting root domain for {Zone}", _options.Value.ZoneId);

        var response = await _http.GetAsync($"{BaseUrl}/zones/{_options.Value.ZoneId}", ct);

        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync(ct);
            throw new HttpRequestException(
                $"Failed to get zone information. Status: {response.StatusCode}, Error: {errorContent}"
            );
        }

        var responseContent = await response.Content.ReadAsStringAsync(ct);
        using var document = JsonDocument.Parse(responseContent);

        var result = document.RootElement.GetProperty("result");
        _rootDomain = result.GetProperty("name").GetString()!;

        _logger.LogInformation("{Zone} root domain is {Root}", _options.Value.ZoneId, _rootDomain);

        return _rootDomain;
    }

    public void Dispose()
    {
        _http.Dispose();
    }
}
