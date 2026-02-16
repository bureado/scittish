using Scittish.Api.Models;

namespace Scittish.Api.Resolvers;

/// <summary>
/// Abstract base for subject resolvers. Resolvers determine the canonical subject identifier.
/// </summary>
public abstract class SubjectResolver
{
    public abstract string Name { get; }
    public abstract int Priority { get; }
    public virtual string Description => "";
    public virtual List<string> SupportedContentTypes => new();

    public virtual bool CanResolve(ResolverContext context)
    {
        if (SupportedContentTypes.Count == 0)
        {
            return true;
        }
        return SupportedContentTypes.Contains(context.ContentType);
    }

    public abstract ResolverResult Resolve(ResolverContext context);

    public Dictionary<string, object> ToDict() => new()
    {
        ["name"] = Name,
        ["priority"] = Priority,
        ["description"] = Description,
        ["supported_content_types"] = SupportedContentTypes,
    };
}

/// <summary>
/// Registry that evaluates resolvers in priority order until one returns a subject.
/// </summary>
public class ResolverRegistry
{
    private readonly List<SubjectResolver> _resolvers = new();
    private bool _sorted;

    public void Register(SubjectResolver resolver)
    {
        _resolvers.Add(resolver);
        _sorted = false;
    }

    private void EnsureSorted()
    {
        if (!_sorted)
        {
            _resolvers.Sort((a, b) => a.Priority.CompareTo(b.Priority));
            _sorted = true;
        }
    }

    public ResolverResult Resolve(ResolverContext context)
    {
        EnsureSorted();

        foreach (SubjectResolver resolver in _resolvers)
        {
            if (!resolver.CanResolve(context))
            {
                continue;
            }

            try
            {
                ResolverResult result = resolver.Resolve(context);
                if (result.Subject is not null)
                {
                    return result;
                }
            }
            catch
            {
                // Skip failed resolvers
            }
        }

        return new ResolverResult
        {
            Subject = null,
            ResolverName = "none",
            Confidence = 0.0,
            Indexable = false,
        };
    }

    public List<Dictionary<string, object>> ToDict()
    {
        EnsureSorted();
        return _resolvers.Select(r => r.ToDict()).ToList();
    }

    /// <summary>
    /// Create the default registry with all built-in resolvers.
    /// </summary>
    public static ResolverRegistry CreateDefault()
    {
        ResolverRegistry registry = new();
        registry.Register(new ClientProvidedResolver());
        registry.Register(new SpdxSbomResolver());
        registry.Register(new SlsaInTotoResolver());
        registry.Register(new EkuFallbackResolver());
        registry.Register(new BearerTokenResolver());
        return registry;
    }
}

/// <summary>
/// Uses the client-provided subject from X-Scittish-Subject header. Priority 0.
/// </summary>
public class ClientProvidedResolver : SubjectResolver
{
    public override string Name => "client-provided";
    public override int Priority => 0;
    public override string Description => "Uses subject provided by client via X-Scittish-Subject header";

    public override ResolverResult Resolve(ResolverContext context)
    {
        if (!string.IsNullOrEmpty(context.ClientSubject))
        {
            return new ResolverResult
            {
                Subject = context.ClientSubject,
                ResolverName = Name,
                Confidence = 1.0,
                ResolverMetadata = new() { ["source"] = "X-Scittish-Subject header" },
            };
        }
        return new ResolverResult { Subject = null, ResolverName = Name };
    }
}

/// <summary>
/// Extracts subject from SPDX SBOM documentNamespace. Priority 100.
/// </summary>
public class SpdxSbomResolver : SubjectResolver
{
    public override string Name => "spdx-sbom";
    public override int Priority => 100;
    public override string Description => "Extracts subject from SPDX SBOM documentNamespace field";
    public override List<string> SupportedContentTypes => new() { "application/spdx+json", "application/json" };

    public override ResolverResult Resolve(ResolverContext context)
    {
        if (context.Payload is null)
        {
            return new ResolverResult { Subject = null, ResolverName = Name };
        }

        try
        {
            using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(context.Payload);
            System.Text.Json.JsonElement root = doc.RootElement;

            // Check for SPDX indicators
            bool isSpdx = false;
            if (root.TryGetProperty("spdxVersion", out System.Text.Json.JsonElement ver) && ver.GetString()?.StartsWith("SPDX-") == true)
            {
                isSpdx = true;
            }
            if (!isSpdx)
            {
                string[] spdxFields = { "documentNamespace", "SPDXID", "creationInfo" };
                isSpdx = spdxFields.Any(f => root.TryGetProperty(f, out _));
            }

            if (!isSpdx)
            {
                return new ResolverResult { Subject = null, ResolverName = Name };
            }

            if (root.TryGetProperty("documentNamespace", out System.Text.Json.JsonElement ns))
            {
                string? namespaceStr = ns.GetString();
                if (!string.IsNullOrEmpty(namespaceStr))
                {
                    return new ResolverResult
                    {
                        Subject = namespaceStr,
                        ResolverName = Name,
                        Confidence = 0.9,
                        ResolverMetadata = new() { ["source"] = "SPDX documentNamespace", ["format"] = "spdx-json" },
                    };
                }
            }
        }
        catch
        {
            // Not valid JSON
        }

        return new ResolverResult { Subject = null, ResolverName = Name };
    }
}

/// <summary>
/// Extracts subject from SLSA/in-toto attestation subject. Priority 110.
/// </summary>
public class SlsaInTotoResolver : SubjectResolver
{
    public override string Name => "slsa-intoto";
    public override int Priority => 110;
    public override string Description => "Extracts subject from SLSA/in-toto attestation subject field";
    public override List<string> SupportedContentTypes => new() { "application/vnd.in-toto+json", "application/json" };

    public override ResolverResult Resolve(ResolverContext context)
    {
        if (context.Payload is null)
        {
            return new ResolverResult { Subject = null, ResolverName = Name };
        }

        try
        {
            using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(context.Payload);
            System.Text.Json.JsonElement root = doc.RootElement;

            // Handle DSSE envelope
            System.Text.Json.JsonElement data = root;
            if (root.TryGetProperty("payloadType", out System.Text.Json.JsonElement pt) && pt.GetString() == "application/vnd.in-toto+json")
            {
                if (root.TryGetProperty("payload", out System.Text.Json.JsonElement innerPayload))
                {
                    byte[] decoded = Convert.FromBase64String(innerPayload.GetString() ?? "");
                    data = System.Text.Json.JsonDocument.Parse(decoded).RootElement;
                }
            }

            // Check for in-toto statement
            bool isInToto = false;
            if (data.TryGetProperty("_type", out System.Text.Json.JsonElement typeEl))
            {
                string? typeStr = typeEl.GetString();
                isInToto = typeStr == "https://in-toto.io/Statement/v0.1" || typeStr == "https://in-toto.io/Statement/v1";
            }
            if (!isInToto && data.TryGetProperty("predicateType", out System.Text.Json.JsonElement predEl))
            {
                isInToto = predEl.GetString()?.Contains("slsa.dev/provenance") == true;
            }
            if (!isInToto)
            {
                isInToto = data.TryGetProperty("subject", out _) && data.TryGetProperty("predicateType", out _);
            }

            if (!isInToto)
            {
                return new ResolverResult { Subject = null, ResolverName = Name };
            }

            if (data.TryGetProperty("subject", out System.Text.Json.JsonElement subjects) && subjects.GetArrayLength() > 0)
            {
                System.Text.Json.JsonElement first = subjects[0];
                if (first.TryGetProperty("name", out System.Text.Json.JsonElement nameEl))
                {
                    string? name = nameEl.GetString();
                    if (!string.IsNullOrEmpty(name))
                    {
                        return new ResolverResult
                        {
                            Subject = name,
                            ResolverName = Name,
                            Confidence = 0.9,
                            ResolverMetadata = new() { ["source"] = "in-toto statement subject", ["format"] = "intoto" },
                        };
                    }
                }
                if (first.TryGetProperty("digest", out System.Text.Json.JsonElement digest))
                {
                    foreach (System.Text.Json.JsonProperty prop in digest.EnumerateObject())
                    {
                        return new ResolverResult
                        {
                            Subject = $"{prop.Name}:{prop.Value.GetString()}",
                            ResolverName = Name,
                            Confidence = 0.9,
                            ResolverMetadata = new() { ["source"] = "in-toto statement subject digest" },
                        };
                    }
                }
            }
        }
        catch
        {
            // Not valid JSON
        }

        return new ResolverResult { Subject = null, ResolverName = Name };
    }
}

/// <summary>
/// Derives subject from certificate EKU. Priority 200. Stub implementation.
/// </summary>
public class EkuFallbackResolver : SubjectResolver
{
    public override string Name => "eku-fallback";
    public override int Priority => 200;
    public override string Description => "Derives subject from certificate EKU (stub)";

    public override ResolverResult Resolve(ResolverContext context)
    {
        if (context.Metadata.TryGetValue("eku", out string? eku) && !string.IsNullOrEmpty(eku))
        {
            return new ResolverResult
            {
                Subject = $"eku:{eku}",
                ResolverName = Name,
                Confidence = 0.5,
                ResolverMetadata = new() { ["source"] = "certificate EKU" },
                Indexable = false,
            };
        }

        return new ResolverResult { Subject = null, ResolverName = Name };
    }
}

/// <summary>
/// Derives subject from bearer token. Priority 210. Stub implementation.
/// </summary>
public class BearerTokenResolver : SubjectResolver
{
    public override string Name => "bearer-token";
    public override int Priority => 210;
    public override string Description => "Derives subject from Authorization bearer token (stub)";

    public override ResolverResult Resolve(ResolverContext context)
    {
        // Stub - acknowledge token but don't process
        return new ResolverResult { Subject = null, ResolverName = Name };
    }
}
