using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Scittish.Api.Indexers;
using Scittish.Api.Models;
using Scittish.Api.Resolvers;
using Scittish.Api.Services;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// --- Register services ---
builder.Services.AddSingleton<CertificateService>();
builder.Services.AddSingleton<CacheService>();
builder.Services.AddSingleton<JobService>();
builder.Services.AddSingleton<SigningService>();
builder.Services.AddSingleton<ScittSubmissionService>();
builder.Services.AddSingleton(ResolverRegistry.CreateDefault());
builder.Services.AddSingleton<OciIndexer>(sp =>
    new OciIndexer(sp.GetRequiredService<ILogger<OciIndexer>>(), builder.Configuration));
builder.Services.AddSingleton(Channel.CreateUnbounded<string>());
builder.Services.AddSingleton<SigningWorker>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<SigningWorker>());

WebApplication app = builder.Build();

// Initialize certificate chain on startup
CertificateService certService = app.Services.GetRequiredService<CertificateService>();
certService.GetChain();

// --- Configuration helpers ---
string scittUrl = builder.Configuration.GetValue<string>("SCITT_URL")
    ?? Environment.GetEnvironmentVariable("SCITT_URL")
    ?? "https://localhost:8000";
string maaEndpoint = Environment.GetEnvironmentVariable("MAA_ENDPOINT") ?? "sharedeus.eus.attest.azure.net";
string attestHelperPath = Environment.GetEnvironmentVariable("ATTEST_HELPER_PATH") ?? "/app/attest-helper";
bool allowFakeAttestation = (Environment.GetEnvironmentVariable("ALLOW_FAKE_ATTESTATION") ?? "false").Equals("true", StringComparison.OrdinalIgnoreCase);

// --- GET /health ---
app.MapGet("/health", () => Results.Json(new { status = "ok" }));

// --- GET /properties ---
app.MapGet("/properties", (CertificateService certSvc, ResolverRegistry resolvers, OciIndexer ociIndexer) =>
{
    CertificateChain chain = certSvc.GetChain();
    return Results.Json(new
    {
        certificate_chain = chain.ChainPem,
        scitt_url = scittUrl,
        subject_resolvers = resolvers.ToDict(),
        indexers = new[] { ociIndexer.ToDict() },
    });
});

// --- POST /sign ---
app.MapPost("/sign", async (HttpContext ctx, CacheService cache, JobService jobs, SigningWorker worker) =>
{
    string? clientSubject = ctx.Request.Headers["X-Scittish-Subject"].FirstOrDefault();
    string? payloadHashHeader = ctx.Request.Headers["X-Scittish-Payload-Hash"].FirstOrDefault();
    string contentType = ctx.Request.ContentType ?? "application/octet-stream";

    // Capture relevant headers
    Dictionary<string, string> reqHeaders = new();
    foreach (KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues> h in ctx.Request.Headers)
    {
        if (h.Key.StartsWith("X-Scittish-", StringComparison.OrdinalIgnoreCase) || h.Key == "Authorization")
        {
            reqHeaders[h.Key] = h.Value.ToString();
        }
    }

    byte[]? payload = null;
    if (string.IsNullOrEmpty(payloadHashHeader))
    {
        using MemoryStream ms = new();
        await ctx.Request.Body.CopyToAsync(ms);
        payload = ms.ToArray();
    }

    if ((payload is null || payload.Length == 0) && string.IsNullOrEmpty(payloadHashHeader))
    {
        return Results.Json(new { error = "Either request body or X-Scittish-Payload-Hash header must be provided" }, statusCode: 400);
    }

    // Validate payload hash format
    if (!string.IsNullOrEmpty(payloadHashHeader))
    {
        if (payloadHashHeader.Length != 64)
        {
            return Results.Json(new { error = "X-Scittish-Payload-Hash must be a 64-character hex string (SHA256)" }, statusCode: 400);
        }
        try { _ = Convert.FromHexString(payloadHashHeader); } catch
        {
            return Results.Json(new { error = "X-Scittish-Payload-Hash must be a valid hex string" }, statusCode: 400);
        }
    }

    string computedHash = !string.IsNullOrEmpty(payloadHashHeader)
        ? payloadHashHeader.ToLowerInvariant()
        : Convert.ToHexStringLower(SHA256.HashData(payload!));

    string jobId = cache.ComputeCacheKey(computedHash, clientSubject);

    // Check cache
    byte[]? cachedReceipt = cache.GetCachedReceipt(jobId);
    if (cachedReceipt is not null)
    {
        ctx.Response.Headers["X-Scittish-Cache-Hit"] = "true";
        return Results.Bytes(cachedReceipt, "application/cose");
    }

    // Check existing job
    JobInfo? existingJob = jobs.GetJob(jobId);
    if (existingJob is not null)
    {
        if (existingJob.Status == JobStatus.Completed)
        {
            byte[]? receipt = cache.GetCachedReceipt(jobId);
            if (receipt is not null)
            {
                ctx.Response.Headers["X-Scittish-Cache-Hit"] = "true";
                return Results.Bytes(receipt, "application/cose");
            }
        }

        string locationUrl = $"{ctx.Request.Scheme}://{ctx.Request.Host}/sign/{jobId}";
        ctx.Response.Headers["Location"] = locationUrl;
        return Results.Json(new
        {
            job_id = jobId,
            status = existingJob.Status.ToString().ToLowerInvariant(),
            error = existingJob.Error,
        }, statusCode: existingJob.Status is JobStatus.Pending or JobStatus.Processing ? 202 : 200);
    }

    // Hash-only mode: sign the hash directly (endorsement)
    bool isHashOnly = !string.IsNullOrEmpty(payloadHashHeader) && (payload is null || payload.Length == 0);

    // Create job
    JobInfo job = new()
    {
        JobId = jobId,
        Status = JobStatus.Pending,
        CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0,
        UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0,
    };
    jobs.SaveJob(job);

    if (isHashOnly)
    {
        byte[] hashBytes = Convert.FromHexString(payloadHashHeader!);
        jobs.SaveJobPayload(jobId, hashBytes, contentType, clientSubject, reqHeaders, isHashOnly: true);
    }
    else
    {
        jobs.SaveJobPayload(jobId, payload!, contentType, clientSubject, reqHeaders, isHashOnly: false);
    }

    await worker.EnqueueAsync(jobId);

    string newJobLocationUrl = $"{ctx.Request.Scheme}://{ctx.Request.Host}/sign/{jobId}";
    ctx.Response.Headers["Location"] = newJobLocationUrl;
    return Results.Json(new { job_id = jobId, status = "pending" }, statusCode: 202);
});

// --- GET /sign/{jobId} ---
app.MapGet("/sign/{jobId}", (string jobId, CacheService cache, JobService jobs) =>
{
    // Check cache
    byte[]? cachedReceipt = cache.GetCachedReceipt(jobId);
    if (cachedReceipt is not null)
    {
        return Results.Bytes(cachedReceipt, "application/cose");
    }

    JobInfo? job = jobs.GetJob(jobId);
    if (job is null)
    {
        return Results.Json(new { error = "Job not found" }, statusCode: 404);
    }

    if (job.Status == JobStatus.Completed)
    {
        return Results.Json(new { error = "Job completed but receipt not found" }, statusCode: 500);
    }

    if (job.Status == JobStatus.Failed)
    {
        return Results.Json(new { job_id = jobId, status = "failed", error = job.Error });
    }

    return Results.Json(new { job_id = jobId, status = job.Status.ToString().ToLowerInvariant() }, statusCode: 202);
});

// --- POST /attest ---
app.MapPost("/attest", async (HttpContext ctx, CertificateService certSvc) =>
{
    AttestRequest? data = null;
    try
    {
        data = await ctx.Request.ReadFromJsonAsync<AttestRequest>();
    }
    catch { }
    data ??= new AttestRequest();

    string maaEp = data.MaaEndpoint ?? maaEndpoint;
    string? nonceB64 = data.Nonce;

    byte[] nonceBytes = Array.Empty<byte>();
    if (!string.IsNullOrEmpty(nonceB64))
    {
        try
        {
            nonceBytes = Convert.FromBase64String(nonceB64);
        }
        catch
        {
            return Results.Json(new { error = "Invalid nonce encoding" }, statusCode: 400);
        }
    }

    // Build runtime data
    CertificateChain chain = certSvc.GetChain();
    string runtimeData = JsonSerializer.Serialize(new
    {
        nonce = nonceB64 ?? "",
        signature = "",  // Simplified - no nonce signing in .NET version
        certificate_chain = chain.ChainPem,
    });

    List<string> cmd = new()
    {
        attestHelperPath,
        "-runtime-data", Convert.ToBase64String(Encoding.UTF8.GetBytes(runtimeData)),
        "-maa-endpoint", maaEp,
    };
    if (allowFakeAttestation)
    {
        cmd.Add("-allow-fake");
    }

    try
    {
        ProcessStartInfo psi = new(cmd[0])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        for (int i = 1; i < cmd.Count; i++)
        {
            psi.ArgumentList.Add(cmd[i]);
        }

        using Process? proc = Process.Start(psi);
        if (proc is null)
        {
            return Results.Json(new { error = $"attest-helper not found at {attestHelperPath}" }, statusCode: 502);
        }

        string stdout = await proc.StandardOutput.ReadToEndAsync();
        await proc.WaitForExitAsync();

        if (proc.ExitCode != 0)
        {
            string stderr = await proc.StandardError.ReadToEndAsync();
            return Results.Json(new { error = $"attest-helper failed: {stderr}" }, statusCode: 502);
        }

        JsonDocument result = JsonDocument.Parse(stdout);
        if (result.RootElement.TryGetProperty("error", out JsonElement errorEl))
        {
            return Results.Json(new { error = errorEl.GetString() }, statusCode: 502);
        }

        string? token = result.RootElement.TryGetProperty("token", out JsonElement tokenEl) ? tokenEl.GetString() : null;
        if (token is null)
        {
            return Results.Json(new { error = "No token in attestation response" }, statusCode: 502);
        }

        ctx.Response.Headers["X-Scittish-Cache-Hit"] = "false";
        return Results.Json(new { token });
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 502);
    }
});

app.Run();
