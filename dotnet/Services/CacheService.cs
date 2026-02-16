using System.Security.Cryptography;
using System.Text;
using Scittish.Api.Models;

namespace Scittish.Api.Services;

/// <summary>
/// File-based receipt cache. Cache key is SHA256(payload_hash:subject).
/// </summary>
public class CacheService
{
    private readonly ILogger<CacheService> _logger;
    private readonly string _cacheDir;

    public CacheService(ILogger<CacheService> logger, IConfiguration configuration)
    {
        _logger = logger;
        _cacheDir = configuration.GetValue<string>("SCITT_CACHE_DIR")
            ?? Environment.GetEnvironmentVariable("SCITT_CACHE_DIR")
            ?? "/var/cache/scittish";
        Directory.CreateDirectory(_cacheDir);
    }

    public string ComputeCacheKey(string payloadHash, string? subject)
    {
        string input = $"{payloadHash}:{subject ?? ""}";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexStringLower(hash);
    }

    public byte[]? GetCachedReceipt(string cacheKey)
    {
        string path = Path.Combine(_cacheDir, $"{cacheKey}.receipt");
        if (File.Exists(path))
        {
            _logger.LogInformation("Cache hit for key {Key}...", cacheKey[..16]);
            return File.ReadAllBytes(path);
        }
        return null;
    }

    public void StoreReceipt(string cacheKey, byte[] receipt)
    {
        Directory.CreateDirectory(_cacheDir);
        string path = Path.Combine(_cacheDir, $"{cacheKey}.receipt");
        File.WriteAllBytes(path, receipt);
        _logger.LogInformation("Stored receipt in cache for key {Key}...", cacheKey[..16]);
    }
}
