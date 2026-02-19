using System.Text.Json.Serialization;

namespace Scittish.Api.Models;

public enum JobStatus
{
    Pending,
    Processing,
    Completed,
    Failed
}

public class JobInfo
{
    public string JobId { get; set; } = string.Empty;
    public JobStatus Status { get; set; } = JobStatus.Pending;
    public string? Error { get; set; }
    public double CreatedAt { get; set; }
    public double UpdatedAt { get; set; }
}

public class JobPayload
{
    public byte[] Payload { get; set; } = Array.Empty<byte>();
    public string ContentType { get; set; } = "application/octet-stream";
    public string? ClientSubject { get; set; }
    public Dictionary<string, string> Headers { get; set; } = new();
    /// <summary>
    /// When true, Payload contains only the raw hash bytes (not the original payload).
    /// </summary>
    public bool IsHashOnly { get; set; }
}

public class CertificateChain
{
    public string RootCertPem { get; set; } = string.Empty;
    public string LeafCertPem { get; set; } = string.Empty;
    public string LeafKeyPem { get; set; } = string.Empty;
    public string PfxPath { get; set; } = string.Empty;

    public string ChainPem => LeafCertPem + RootCertPem;
}

public class ResolverContext
{
    public byte[]? Payload { get; set; }
    public string PayloadHash { get; set; } = string.Empty;
    public string ContentType { get; set; } = string.Empty;
    public string? ClientSubject { get; set; }
    public Dictionary<string, string> Headers { get; set; } = new();
    public Dictionary<string, string> Metadata { get; set; } = new();
}

public class ResolverResult
{
    public string? Subject { get; set; }
    public string ResolverName { get; set; } = string.Empty;
    public double Confidence { get; set; } = 1.0;
    public Dictionary<string, string> ResolverMetadata { get; set; } = new();
    public bool Indexable { get; set; } = true;
}

public class IndexerContext
{
    public byte[] Receipt { get; set; } = Array.Empty<byte>();
    public string Subject { get; set; } = string.Empty;
    public string PayloadHash { get; set; } = string.Empty;
    public string ContentType { get; set; } = string.Empty;
    public Dictionary<string, string> ResolverMetadata { get; set; } = new();
}

public class IndexerResult
{
    public bool Success { get; set; }
    public string IndexerName { get; set; } = string.Empty;
    public string? Reference { get; set; }
    public string? Error { get; set; }
}

public class SignRequest
{
    public byte[]? Payload { get; set; }
    public string? PayloadHash { get; set; }
    public string ContentType { get; set; } = "application/octet-stream";
    public string? ClientSubject { get; set; }
    public Dictionary<string, string> Headers { get; set; } = new();
}

public class AttestRequest
{
    public string? Nonce { get; set; }
    public string? MaaEndpoint { get; set; }
}
