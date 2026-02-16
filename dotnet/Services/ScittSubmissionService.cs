using System.Net.Http.Headers;
using System.Text.Json;
using Scittish.Api.Models;

namespace Scittish.Api.Services;

/// <summary>
/// Submits signed COSE statements to a SCITT ledger (scitt-ccf-ledger compatible).
/// Uses the HTTP API directly: POST /entries, poll GET /operations/{id}, GET /entries/{id}/statement.
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
            // Accepted - need to poll for completion
            string? operationUrl = response.Headers.Location?.ToString();
            if (string.IsNullOrEmpty(operationUrl))
            {
                string body = await response.Content.ReadAsStringAsync(cancellationToken);
                JsonDocument doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("operationId", out JsonElement opId))
                {
                    operationUrl = $"/operations/{opId.GetString()}";
                }
            }

            if (string.IsNullOrEmpty(operationUrl))
            {
                throw new InvalidOperationException("No operation URL returned from SCITT ledger");
            }

            // Poll operation until complete
            string entryId = await PollOperationAsync(operationUrl, cancellationToken);

            // Fetch the transparent statement
            return await FetchStatementAsync(entryId, cancellationToken);
        }
        else if (response.IsSuccessStatusCode)
        {
            // Direct success - read receipt
            return await response.Content.ReadAsByteArrayAsync(cancellationToken);
        }
        else
        {
            string errorBody = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new InvalidOperationException($"SCITT submission failed ({response.StatusCode}): {errorBody}");
        }
    }

    private async Task<string> PollOperationAsync(string operationUrl, CancellationToken cancellationToken)
    {
        int maxAttempts = 60;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);

            HttpResponseMessage response = await _httpClient.GetAsync(operationUrl, cancellationToken);
            string body = await response.Content.ReadAsStringAsync(cancellationToken);

            if (response.IsSuccessStatusCode && (int)response.StatusCode == 200)
            {
                JsonDocument doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("entryId", out JsonElement entryId))
                {
                    string id = entryId.GetString() ?? throw new InvalidOperationException("entryId is null");
                    _logger.LogInformation("SCITT operation completed (entry={EntryId})", id);
                    return id;
                }
                // Operation complete, extract entry path from operationUrl
                return operationUrl.Replace("/operations/", "");
            }

            if ((int)response.StatusCode != 202)
            {
                throw new InvalidOperationException($"SCITT operation poll failed ({response.StatusCode}): {body}");
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

            string body = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new InvalidOperationException($"Failed to fetch statement ({response.StatusCode}): {body}");
        }

        throw new TimeoutException("Failed to fetch statement after retries");
    }
}
