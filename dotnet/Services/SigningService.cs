using System.Diagnostics;
using Scittish.Api.Models;

namespace Scittish.Api.Services;

/// <summary>
/// Signs payloads using CoseSignTool indirect-sign with a PFX certificate.
/// </summary>
public class SigningService
{
    private readonly ILogger<SigningService> _logger;
    private readonly CertificateService _certService;
    private readonly string _coseSignToolPath;

    public SigningService(ILogger<SigningService> logger, CertificateService certService, IConfiguration configuration)
    {
        _logger = logger;
        _certService = certService;
        _coseSignToolPath = configuration.GetValue<string>("COSESIGNTOOL_PATH")
            ?? Environment.GetEnvironmentVariable("COSESIGNTOOL_PATH")
            ?? "/app/CoseSignTool";
    }

    /// <summary>
    /// Sign a payload using CoseSignTool indirect-sign, producing a COSE_Sign1 with full x5c chain.
    /// </summary>
    public async Task<byte[]> SignPayloadAsync(byte[] payload, string payloadHash, string contentType, string? subject, CancellationToken cancellationToken)
    {
        CertificateChain chain = _certService.GetChain();

        // Write payload to temp file
        string tempDir = Path.Combine(Path.GetTempPath(), $"scittish-sign-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            string payloadPath = Path.Combine(tempDir, "payload.bin");
            string signaturePath = Path.Combine(tempDir, "signature.cose");

            await File.WriteAllBytesAsync(payloadPath, payload, cancellationToken);

            _logger.LogInformation("Signing payload with hash {Hash}...", payloadHash[..16]);

            ProcessStartInfo psi = new(_coseSignToolPath)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = tempDir,
            };
            psi.ArgumentList.Add("indirect-sign");
            psi.ArgumentList.Add("--payload");
            psi.ArgumentList.Add(payloadPath);
            psi.ArgumentList.Add("--signature");
            psi.ArgumentList.Add(signaturePath);
            psi.ArgumentList.Add("--pfx");
            psi.ArgumentList.Add(chain.PfxPath);
            psi.ArgumentList.Add("--content-type");
            psi.ArgumentList.Add(contentType);

            using Process? proc = Process.Start(psi);
            if (proc is null)
            {
                throw new InvalidOperationException("Failed to start CoseSignTool");
            }

            await proc.WaitForExitAsync(cancellationToken);

            if (proc.ExitCode != 0)
            {
                string stderr = await proc.StandardError.ReadToEndAsync(cancellationToken);
                throw new InvalidOperationException($"CoseSignTool indirect-sign failed (exit {proc.ExitCode}): {stderr}");
            }

            byte[] signedStatement = await File.ReadAllBytesAsync(signaturePath, cancellationToken);
            _logger.LogInformation("Signed statement created ({Bytes} bytes)", signedStatement.Length);
            return signedStatement;
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { /* cleanup best-effort */ }
        }
    }
}
