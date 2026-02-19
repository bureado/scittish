using System.Text.Json;
using Scittish.Api.Models;

namespace Scittish.Api.Services;

/// <summary>
/// Manages signing jobs: creation, status tracking, payload persistence.
/// </summary>
public class JobService
{
    private readonly ILogger<JobService> _logger;
    private readonly string _jobsDir;

    public JobService(ILogger<JobService> logger, IConfiguration configuration)
    {
        _logger = logger;
        _jobsDir = configuration.GetValue<string>("SCITT_JOBS_DIR")
            ?? Environment.GetEnvironmentVariable("SCITT_JOBS_DIR")
            ?? "/var/cache/scittish/jobs";
        Directory.CreateDirectory(_jobsDir);
    }

    public JobInfo? GetJob(string jobId)
    {
        string path = Path.Combine(_jobsDir, $"{jobId}.job");
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            string json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<JobInfo>(json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load job {JobId}", jobId);
            return null;
        }
    }

    public void SaveJob(JobInfo job)
    {
        Directory.CreateDirectory(_jobsDir);
        job.UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
        string path = Path.Combine(_jobsDir, $"{job.JobId}.job");
        string json = JsonSerializer.Serialize(job);
        File.WriteAllText(path, json);
    }

    public void SaveJobPayload(string jobId, byte[] payload, string contentType, string? clientSubject, Dictionary<string, string> headers, bool isHashOnly = false)
    {
        Directory.CreateDirectory(_jobsDir);
        string path = Path.Combine(_jobsDir, $"{jobId}.payload");
        var data = new
        {
            metadata = new
            {
                content_type = contentType,
                client_subject = clientSubject,
                headers,
                is_hash_only = isHashOnly,
            },
            payload = Convert.ToBase64String(payload),
        };
        File.WriteAllText(path, JsonSerializer.Serialize(data));
    }

    public JobPayload? LoadJobPayload(string jobId)
    {
        string path = Path.Combine(_jobsDir, $"{jobId}.payload");
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            string json = File.ReadAllText(path);
            using JsonDocument doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;
            JsonElement meta = root.GetProperty("metadata");

            Dictionary<string, string> headers = new();
            if (meta.TryGetProperty("headers", out JsonElement headersEl))
            {
                foreach (JsonProperty prop in headersEl.EnumerateObject())
                {
                    headers[prop.Name] = prop.Value.GetString() ?? "";
                }
            }

            return new JobPayload
            {
                Payload = Convert.FromBase64String(root.GetProperty("payload").GetString() ?? ""),
                ContentType = meta.GetProperty("content_type").GetString() ?? "application/octet-stream",
                ClientSubject = meta.TryGetProperty("client_subject", out JsonElement cs) ? cs.GetString() : null,
                Headers = headers,
                IsHashOnly = meta.TryGetProperty("is_hash_only", out JsonElement iho) && iho.GetBoolean(),
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load payload for job {JobId}", jobId);
            return null;
        }
    }

    public void CleanupJobPayload(string jobId)
    {
        string path = Path.Combine(_jobsDir, $"{jobId}.payload");
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
