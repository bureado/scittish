using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Scittish.Api.Models;

namespace Scittish.Api.Indexers;

/// <summary>
/// Pushes receipts to an OCI registry as referrers using oras CLI.
/// </summary>
public class OciIndexer
{
    private readonly string _registry;
    private readonly string _namespace;
    private readonly string _username;
    private readonly string _password;
    private readonly bool _insecure;
    private readonly string _orasPath;
    private readonly ILogger<OciIndexer>? _logger;

    private const string ReceiptMediaType = "application/cose";
    private const string ArtifactType = "application/vnd.scitt.receipt";

    public OciIndexer(ILogger<OciIndexer>? logger = null, IConfiguration? configuration = null)
    {
        _logger = logger;
        _registry = configuration?.GetValue<string>("OCI_REGISTRY")
            ?? Environment.GetEnvironmentVariable("OCI_REGISTRY") ?? "";
        _namespace = configuration?.GetValue<string>("OCI_NAMESPACE")
            ?? Environment.GetEnvironmentVariable("OCI_NAMESPACE") ?? "scittish";
        _username = Environment.GetEnvironmentVariable("OCI_USERNAME") ?? "";
        _password = Environment.GetEnvironmentVariable("OCI_PASSWORD") ?? "";
        _insecure = (Environment.GetEnvironmentVariable("OCI_INSECURE") ?? "false").Equals("true", StringComparison.OrdinalIgnoreCase);
        _orasPath = Environment.GetEnvironmentVariable("ORAS_PATH") ?? "oras";
    }

    public string Name => "oci-registry";
    public string Description => $"Pushes receipts to OCI registry as referrers (registry: {(_registry.Length > 0 ? _registry : "not configured")})";

    public bool Enabled => !string.IsNullOrEmpty(_registry);

    private static string SubjectToRepoName(string subject)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(subject));
        return Convert.ToHexStringLower(hash);
    }

    private (bool success, string stdout, string stderr) RunOras(List<string> args, string? cwd = null)
    {
        ProcessStartInfo psi = new(_orasPath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        if (!string.IsNullOrEmpty(_username) && !string.IsNullOrEmpty(_password))
        {
            psi.ArgumentList.Add("--username");
            psi.ArgumentList.Add(_username);
            psi.ArgumentList.Add("--password");
            psi.ArgumentList.Add(_password);
        }

        if (_insecure)
        {
            psi.ArgumentList.Add("--plain-http");
        }

        if (cwd is not null)
        {
            psi.WorkingDirectory = cwd;
        }

        using Process? proc = Process.Start(psi);
        if (proc is null)
        {
            return (false, "", "Failed to start oras");
        }

        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(60000);

        return (proc.ExitCode == 0, stdout, stderr);
    }

    public IndexerResult Index(IndexerContext context)
    {
        if (!Enabled)
        {
            return new IndexerResult
            {
                Success = false,
                IndexerName = Name,
                Error = "OCI registry not configured",
            };
        }

        try
        {
            string subjectHash = SubjectToRepoName(context.Subject);
            string subjectRepo = $"{_registry}/{_namespace}/{subjectHash}";
            string subjectRef = $"{subjectRepo}:latest";

            string tempDir = Path.Combine(Path.GetTempPath(), $"scittish-oci-{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempDir);

            try
            {
                // Step 1: Check if subject artifact exists
                (bool success, string stdout, string stderr) = RunOras(
                    new List<string> { "manifest", "fetch", subjectRef, "--descriptor" }, tempDir);

                string? subjectDigest = null;
                if (success)
                {
                    try
                    {
                        using JsonDocument doc = JsonDocument.Parse(stdout);
                        subjectDigest = doc.RootElement.GetProperty("digest").GetString();
                    }
                    catch { }
                }

                // Create subject artifact if needed
                if (subjectDigest is null)
                {
                    File.WriteAllText(Path.Combine(tempDir, "subject.txt"), context.Subject);
                    (success, stdout, stderr) = RunOras(
                        new List<string>
                        {
                            "push", subjectRef,
                            "subject.txt:text/plain",
                            "--annotation", $"scittish.subject={context.Subject}",
                        }, tempDir);

                    if (!success)
                    {
                        return new IndexerResult { Success = false, IndexerName = Name, Error = $"Failed to push subject: {stderr}" };
                    }

                    (success, stdout, _) = RunOras(
                        new List<string> { "manifest", "fetch", subjectRef, "--descriptor" }, tempDir);
                    if (success)
                    {
                        try
                        {
                            using JsonDocument doc = JsonDocument.Parse(stdout);
                            subjectDigest = doc.RootElement.GetProperty("digest").GetString();
                        }
                        catch { }
                    }
                }

                if (subjectDigest is null)
                {
                    return new IndexerResult { Success = false, IndexerName = Name, Error = "Failed to get subject digest" };
                }

                // Step 2: Push receipt as referrer
                File.WriteAllBytes(Path.Combine(tempDir, "receipt.cose"), context.Receipt);
                (success, stdout, stderr) = RunOras(
                    new List<string>
                    {
                        "attach", subjectRef,
                        "--artifact-type", ArtifactType,
                        $"receipt.cose:{ReceiptMediaType}",
                        "--annotation", $"scittish.payload_hash={context.PayloadHash}",
                        "--annotation", $"scittish.subject={context.Subject}",
                    }, tempDir);

                if (!success)
                {
                    return new IndexerResult { Success = false, IndexerName = Name, Error = $"Failed to push receipt: {stderr}" };
                }

                string receiptRef = $"{subjectRepo}@{subjectDigest}";
                if (stdout.Contains("Digest:"))
                {
                    foreach (string line in stdout.Split('\n'))
                    {
                        if (line.Contains("Digest:"))
                        {
                            string digest = line.Split("Digest:").Last().Trim();
                            receiptRef = $"{subjectRepo}@{digest}";
                            break;
                        }
                    }
                }

                _logger?.LogInformation("Indexed receipt to {Repo} as referrer of {Ref}", subjectRepo, subjectRef);

                return new IndexerResult
                {
                    Success = true,
                    IndexerName = Name,
                    Reference = $"{subjectRepo}@{subjectDigest}",
                };
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
        catch (Exception ex)
        {
            return new IndexerResult { Success = false, IndexerName = Name, Error = ex.Message };
        }
    }

    public Dictionary<string, object?> ToDict() => new()
    {
        ["name"] = Name,
        ["description"] = Description,
        ["enabled"] = Enabled,
        ["registry"] = _registry.Length > 0 ? _registry : null,
        ["namespace"] = _registry.Length > 0 ? _namespace : null,
    };
}
