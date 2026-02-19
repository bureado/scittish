using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseIndirectSignature;
using CoseSign1.Abstractions.Interfaces;
using CoseSign1.Certificates.Local;
using Scittish.Api.Models;

namespace Scittish.Api.Services;

/// <summary>
/// Signs payloads using CoseSignTool libraries for indirect signing.
/// Supports both full-payload and hash-only (endorsement) modes.
/// </summary>
public class SigningService
{
    private readonly ILogger<SigningService> _logger;
    private readonly CertificateService _certService;

    public SigningService(ILogger<SigningService> logger, CertificateService certService, IConfiguration configuration)
    {
        _logger = logger;
        _certService = certService;
    }

    /// <summary>
    /// Sign a full payload using indirect signing, producing a COSE_Sign1 with CoseHashEnvelope.
    /// The payload is hashed internally by the factory.
    /// </summary>
    public async Task<byte[]> SignPayloadAsync(byte[] payload, string payloadHash, string contentType, string? subject, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Signing payload with hash {Hash}...", payloadHash[..16]);

        ICoseSigningKeyProvider keyProvider = CreateKeyProvider();

        using IndirectSignatureFactory factory = new(HashAlgorithmName.SHA256);
        using MemoryStream payloadStream = new(payload);

        CoseSign1Message signature = await factory.CreateIndirectSignatureAsync(
            payload: payloadStream,
            signingKeyProvider: keyProvider,
            contentType: contentType,
            signatureVersion: IndirectSignatureFactory.IndirectSignatureVersion.CoseHashEnvelope,
            cancellationToken: cancellationToken);

        byte[] signedStatement = signature.Encode();
        _logger.LogInformation("Signed statement created ({Bytes} bytes)", signedStatement.Length);
        return signedStatement;
    }

    /// <summary>
    /// Sign a pre-computed hash (endorsement mode), producing a COSE_Sign1 with CoseHashEnvelope.
    /// The hash bytes are used directly without re-hashing.
    /// </summary>
    public async Task<byte[]> SignHashAsync(byte[] hashBytes, string contentType, string? subject, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Signing pre-computed hash (endorsement mode)...");

        ICoseSigningKeyProvider keyProvider = CreateKeyProvider();

        using IndirectSignatureFactory factory = new(HashAlgorithmName.SHA256);
        using MemoryStream hashStream = new(hashBytes);

        CoseSign1Message signature = await factory.CreateIndirectSignatureFromHashAsync(
            rawHash: hashStream,
            signingKeyProvider: keyProvider,
            contentType: contentType,
            signatureVersion: IndirectSignatureFactory.IndirectSignatureVersion.CoseHashEnvelope,
            cancellationToken: cancellationToken);

        byte[] signedStatement = signature.Encode();
        _logger.LogInformation("Signed statement created ({Bytes} bytes, from hash)", signedStatement.Length);
        return signedStatement;
    }

    private ICoseSigningKeyProvider CreateKeyProvider()
    {
        CertificateChain chain = _certService.GetChain();

        X509Certificate2 signingCert = X509CertificateLoader.LoadPkcs12FromFile(chain.PfxPath, null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

        // Load root certs from the chain for x5c header
        List<X509Certificate2> rootCerts = new();
        string rootPem = chain.RootCertPem;
        if (!string.IsNullOrEmpty(rootPem))
        {
            rootCerts.Add(X509Certificate2.CreateFromPem(rootPem));
        }

        return new X509Certificate2CoseSigningKeyProvider(
            signingCertificate: signingCert,
            hashAlgorithm: HashAlgorithmName.SHA256,
            rootCertificates: rootCerts,
            enableScittCompliance: true);
    }
}
