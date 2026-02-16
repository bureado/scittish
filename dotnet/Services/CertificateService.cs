using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Scittish.Api.Models;

namespace Scittish.Api.Services;

/// <summary>
/// Manages certificate chain generation and loading using openssl CLI.
/// Generates a root CA + leaf cert chain and exports as PFX for CoseSignTool.
/// </summary>
public class CertificateService
{
    private readonly ILogger<CertificateService> _logger;
    private readonly string _certsDir;
    private CertificateChain? _chain;

    public CertificateService(ILogger<CertificateService> logger, IConfiguration configuration)
    {
        _logger = logger;
        _certsDir = configuration.GetValue<string>("SCITT_CERTS_DIR")
            ?? Environment.GetEnvironmentVariable("SCITT_CERTS_DIR")
            ?? "/var/lib/scittish/certs";
    }

    public CertificateChain GetChain()
    {
        if (_chain is null)
        {
            _chain = Initialize();
        }
        return _chain;
    }

    private CertificateChain Initialize()
    {
        Directory.CreateDirectory(_certsDir);

        string rootPemPath = Path.Combine(_certsDir, "root.pem");
        string leafPemPath = Path.Combine(_certsDir, "leaf.pem");
        string leafKeyPath = Path.Combine(_certsDir, "leaf_key.pem");
        string pfxPath = Path.Combine(_certsDir, "signing.pfx");

        if (File.Exists(rootPemPath) && File.Exists(leafPemPath) && File.Exists(leafKeyPath))
        {
            // PEM files exist (possibly from the Python version). Generate PFX if missing.
            if (!File.Exists(pfxPath))
            {
                _logger.LogInformation("PEM files found but PFX missing; generating PFX from existing certs...");
                RunOpenSsl("pkcs12", "-export",
                    "-out", pfxPath,
                    "-inkey", leafKeyPath,
                    "-in", leafPemPath,
                    "-certfile", rootPemPath,
                    "-passout", "pass:");
            }

            _logger.LogInformation("Loaded existing certificate chain from {CertsDir}", _certsDir);
            return new CertificateChain
            {
                RootCertPem = File.ReadAllText(rootPemPath),
                LeafCertPem = File.ReadAllText(leafPemPath),
                LeafKeyPem = File.ReadAllText(leafKeyPath),
                PfxPath = pfxPath,
            };
        }

        _logger.LogInformation("Generating new certificate chain...");
        CertificateChain chain = GenerateChain(rootPemPath, leafPemPath, leafKeyPath, pfxPath);
        _logger.LogInformation("Certificate chain generated and saved to {CertsDir}", _certsDir);
        _logger.LogInformation("Certificate chain PEM:\n{ChainPem}", chain.ChainPem);
        return chain;
    }

    private CertificateChain GenerateChain(string rootPemPath, string leafPemPath, string leafKeyPath, string pfxPath)
    {
        // Generate root CA key and self-signed cert
        RunOpenSsl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", Path.Combine(_certsDir, "root_key.pem"));

        RunOpenSsl("req", "-new", "-x509",
            "-key", Path.Combine(_certsDir, "root_key.pem"),
            "-out", rootPemPath,
            "-days", "3650",
            "-subj", "/CN=Scittish Root CA/O=Scittish/C=US",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash");

        // Generate leaf key and CSR
        RunOpenSsl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", leafKeyPath);

        string csrPath = Path.Combine(_certsDir, "leaf.csr");
        RunOpenSsl("req", "-new",
            "-key", leafKeyPath,
            "-out", csrPath,
            "-subj", "/CN=Scittish Signing Key/O=Scittish/C=US");

        // Sign leaf cert with root CA
        string extFile = Path.Combine(_certsDir, "leaf_ext.cnf");
        File.WriteAllText(extFile, string.Join("\n",
            "basicConstraints=critical,CA:FALSE",
            "keyUsage=critical,digitalSignature",
            "extendedKeyUsage=1.3.6.1.5.5.7.3.36",
            "subjectKeyIdentifier=hash",
            "authorityKeyIdentifier=keyid,issuer"));

        RunOpenSsl("x509", "-req",
            "-in", csrPath,
            "-CA", rootPemPath,
            "-CAkey", Path.Combine(_certsDir, "root_key.pem"),
            "-CAcreateserial",
            "-out", leafPemPath,
            "-days", "365",
            "-extfile", extFile);

        // Export PFX with full chain (leaf + root CA)
        RunOpenSsl("pkcs12", "-export",
            "-out", pfxPath,
            "-inkey", leafKeyPath,
            "-in", leafPemPath,
            "-certfile", rootPemPath,
            "-passout", "pass:");

        // Cleanup temp files
        foreach (string tmpFile in new[] { csrPath, extFile, Path.Combine(_certsDir, "root_key.pem"), Path.Combine(_certsDir, "root.srl") })
        {
            if (File.Exists(tmpFile))
            {
                File.Delete(tmpFile);
            }
        }

        return new CertificateChain
        {
            RootCertPem = File.ReadAllText(rootPemPath),
            LeafCertPem = File.ReadAllText(leafPemPath),
            LeafKeyPem = File.ReadAllText(leafKeyPath),
            PfxPath = pfxPath,
        };
    }

    public string GetIssuer()
    {
        CertificateChain chain = GetChain();

        // Compute did:x509 issuer from root cert fingerprint
        ProcessStartInfo psi = new("openssl", $"x509 -in {Path.Combine(_certsDir, "root.pem")} -outform DER")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        using Process? proc = Process.Start(psi);
        if (proc is null)
        {
            throw new InvalidOperationException("Failed to start openssl");
        }

        byte[] derBytes;
        using (MemoryStream ms = new())
        {
            proc.StandardOutput.BaseStream.CopyTo(ms);
            derBytes = ms.ToArray();
        }
        proc.WaitForExit();

        byte[] fingerprint = SHA256.HashData(derBytes);
        string fingerprintB64Url = Convert.ToBase64String(fingerprint)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        return $"did:x509:0:sha256:{fingerprintB64Url}::eku:1.3.6.1.5.5.7.3.36";
    }

    private static void RunOpenSsl(params string[] args)
    {
        ProcessStartInfo psi = new("openssl")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using Process? proc = Process.Start(psi);
        if (proc is null)
        {
            throw new InvalidOperationException("Failed to start openssl");
        }

        proc.WaitForExit(30000);

        if (proc.ExitCode != 0)
        {
            string stderr = proc.StandardError.ReadToEnd();
            throw new InvalidOperationException($"openssl failed (exit {proc.ExitCode}): {stderr}");
        }
    }
}
