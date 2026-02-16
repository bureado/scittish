using System.Formats.Cbor;
using System.Net.Http.Headers;
using System.Text.Json;
using Scittish.Api.Models;

namespace Scittish.Api.Services;

/// <summary>
/// Submits signed COSE statements to a SCITT ledger (scitt-ccf-ledger compatible).
/// Uses the HTTP API directly: POST /entries, poll GET /operations/{id}, GET /entries/{id}/statement.
/// The ledger returns CBOR responses (application/cbor).
/// </summary>
public class ScittSubmissionService
{
    private readonly ILogger<ScittSubmissionService> _logger;
    private readonly HttpClient _httpClient;
    private readonly string _scittUrl;
    private readonly bool _development;

    public ScittSubmissionService(ILogger<ScittSubmissionService> logger, IConfiguration configuration)
    {
        _logger = logger;
        _scittUrl = configuration.GetValue<string>("SCITT_URL")
            ?? Environment.GetEnvironmentVariable("SCITT_URL")
            ?? "https://localhost:8000";
        _development = (configuration.GetValue<string>("SCITT_DEVELOPMENT")
            ?? Environment.GetEnvironmentVariable("SCITT_DEVELOPMENT")
            ?? "true").Equals("true", StringComparison.OrdinalIgnoreCase);

        HttpClientHandler handler = new();
        if (_development)
        {
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        }
        _httpClient = new HttpClient(handler) { BaseAddress = new Uri(_scittUrl) };
    }

    /// <summary>
    /// Submit a signed statement and wait for the transparent statement (receipt).
    /// </summary>
    public async Task<byte[]> SubmitAndWaitAsync(byte[] signedStatement, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Submitting signed statement to SCITT ledger at {Url} ({Bytes} bytes)...", _scittUrl, signedStatement.Length);

        // POST /entries
        using ByteArrayContent content = new(signedStatement);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/cose");

        HttpResponseMessage response = await _httpClient.PostAsync("/entries", content, cancellationToken);

        if ((int)response.StatusCode == 202)
        {
            // Accepted - extract operation URL from Location header or CBOR body
            string? operationUrl = response.Headers.Location?.ToString();
            if (string.IsNullOrEmpty(operationUrl))
            {
                byte[] body = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                Dictionary<string, string> cborMap = DecodeCborMap(body);
                if (cborMap.TryGetValue("OperationId", out string? opId))
                {
                    operationUrl = $"/operations/{opId}";
                }
            }

            if (string.IsNullOrEmpty(operationUrl))
            {
                throw new InvalidOperationException("No operation URL returned from SCITT ledger");
            }

            // Use relative path for polling
            Uri opUri = new(operationUrl, UriKind.RelativeOrAbsolute);
            string relativePath = opUri.IsAbsoluteUri ? opUri.PathAndQuery : operationUrl;

            // Poll operation until complete
            string entryId = await PollOperationAsync(relativePath, cancellationToken);

            // Fetch the transparent statement
            return await FetchStatementAsync(entryId, cancellationToken);
        }
        else if (response.IsSuccessStatusCode)
        {
            return await response.Content.ReadAsByteArrayAsync(cancellationToken);
        }
        else
        {
            byte[] errorBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            string errorInfo = TryDescribeError(errorBytes);
            throw new InvalidOperationException($"SCITT submission failed ({response.StatusCode}): {errorInfo}");
        }
    }

    private async Task<string> PollOperationAsync(string operationUrl, CancellationToken cancellationToken)
    {
        int maxAttempts = 60;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);

            HttpResponseMessage response = await _httpClient.GetAsync(operationUrl, cancellationToken);
            byte[] body = await response.Content.ReadAsByteArrayAsync(cancellationToken);

            if (response.IsSuccessStatusCode && (int)response.StatusCode == 200)
            {
                Dictionary<string, string> cborMap = DecodeCborMap(body);
                if (cborMap.TryGetValue("EntryId", out string? entryId))
                {
                    _logger.LogInformation("SCITT operation completed (entry={EntryId})", entryId);
                    return entryId;
                }
                // Fallback: extract from operation URL
                return operationUrl.Replace("/operations/", "");
            }

            if ((int)response.StatusCode != 202)
            {
                string errorInfo = TryDescribeError(body);
                throw new InvalidOperationException($"SCITT operation poll failed ({response.StatusCode}): {errorInfo}");
            }

            _logger.LogDebug("Polling SCITT operation (attempt {Attempt})...", attempt);
        }

        throw new TimeoutException("SCITT operation did not complete in time");
    }

    private async Task<byte[]> FetchStatementAsync(string entryId, CancellationToken cancellationToken)
    {
        int maxAttempts = 10;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            HttpResponseMessage response = await _httpClient.GetAsync($"/entries/{entryId}/statement", cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                byte[] receipt = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                _logger.LogInformation("Received transparent statement from SCITT ledger (tx={EntryId})", entryId);
                return receipt;
            }

            if ((int)response.StatusCode == 503)
            {
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                continue;
            }

            byte[] errorBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            string errorInfo = TryDescribeError(errorBytes);
            throw new InvalidOperationException($"Failed to fetch statement ({response.StatusCode}): {errorInfo}");
        }

        throw new TimeoutException("Failed to fetch statement after retries");
    }

    /// <summary>
    /// Decode a CBOR map with text string keys and text string values.
    /// </summary>
    private static Dictionary<string, string> DecodeCborMap(byte[] data)
    {
        Dictionary<string, string> result = new();
        try
        {
            CborReader reader = new(data);
            int? mapLength = reader.ReadStartMap();
            int count = mapLength ?? 0;
            for (int i = 0; i < count; i++)
            {
                string key = reader.ReadTextString();
                string value = reader.ReadTextString();
                result[key] = value;
            }
            reader.ReadEndMap();
        }
        catch
        {
            // If CBOR parsing fails, return empty map
        }
        return result;
    }

    /// <summary>
    /// Try to produce a human-readable error description from CBOR or text response bytes.
    /// </summary>
    private static string TryDescribeError(byte[] data)
    {
        // Try CBOR map first
        Dictionary<string, string> cborMap = DecodeCborMap(data);
        if (cborMap.Count > 0)
        {
            return string.Join("; ", cborMap.Select(kv => $"{kv.Key}={kv.Value}"));
        }
        // Fall back to raw text
        return System.Text.Encoding.UTF8.GetString(data);
    }
}
