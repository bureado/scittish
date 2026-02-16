using System.Security.Cryptography;
using System.Threading.Channels;
using Scittish.Api.Indexers;
using Scittish.Api.Models;
using Scittish.Api.Resolvers;

namespace Scittish.Api.Services;

/// <summary>
/// Background service that processes signing jobs from a channel.
/// </summary>
public class SigningWorker : BackgroundService
{
    private readonly ILogger<SigningWorker> _logger;
    private readonly Channel<string> _jobChannel;
    private readonly JobService _jobService;
    private readonly CacheService _cacheService;
    private readonly SigningService _signingService;
    private readonly ScittSubmissionService _submissionService;
    private readonly ResolverRegistry _resolverRegistry;
    private readonly OciIndexer _ociIndexer;

    public SigningWorker(
        ILogger<SigningWorker> logger,
        Channel<string> jobChannel,
        JobService jobService,
        CacheService cacheService,
        SigningService signingService,
        ScittSubmissionService submissionService,
        ResolverRegistry resolverRegistry,
        OciIndexer ociIndexer)
    {
        _logger = logger;
        _jobChannel = jobChannel;
        _jobService = jobService;
        _cacheService = cacheService;
        _signingService = signingService;
        _submissionService = submissionService;
        _resolverRegistry = resolverRegistry;
        _ociIndexer = ociIndexer;
    }

    /// <summary>
    /// Enqueue a job for background processing.
    /// </summary>
    public async Task EnqueueAsync(string jobId)
    {
        await _jobChannel.Writer.WriteAsync(jobId);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Signing worker started");

        // Process up to 4 jobs concurrently
        Task[] workers = Enumerable.Range(0, 4).Select(_ => ProcessJobsAsync(stoppingToken)).ToArray();
        await Task.WhenAll(workers);
    }

    private async Task ProcessJobsAsync(CancellationToken stoppingToken)
    {
        await foreach (string jobId in _jobChannel.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                await ProcessJobAsync(jobId, stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled error processing job {JobId}", jobId[..16]);
            }
        }
    }

    private async Task ProcessJobAsync(string jobId, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Processing job {JobId}...", jobId[..16]);

        JobInfo? job = _jobService.GetJob(jobId);
        if (job is null)
        {
            _logger.LogError("Job {JobId} not found", jobId[..16]);
            return;
        }

        job.Status = JobStatus.Processing;
        _jobService.SaveJob(job);

        JobPayload? payloadData = _jobService.LoadJobPayload(jobId);
        if (payloadData is null)
        {
            job.Status = JobStatus.Failed;
            job.Error = "Payload not found";
            _jobService.SaveJob(job);
            return;
        }

        string payloadHash = Convert.ToHexStringLower(SHA256.HashData(payloadData.Payload));

        // Resolve subject
        ResolverContext resolverContext = new()
        {
            Payload = payloadData.Payload,
            PayloadHash = payloadHash,
            ContentType = payloadData.ContentType,
            ClientSubject = payloadData.ClientSubject,
            Headers = payloadData.Headers,
            Metadata = new Dictionary<string, string> { ["eku"] = "1.3.6.1.5.5.7.3.36" },
        };

        ResolverResult resolverResult = _resolverRegistry.Resolve(resolverContext);
        _logger.LogInformation("Subject resolved: {Subject} (by {Resolver})", resolverResult.Subject, resolverResult.ResolverName);

        try
        {
            // Sign
            byte[] signedStatement = await _signingService.SignPayloadAsync(
                payloadData.Payload, payloadHash, payloadData.ContentType, resolverResult.Subject, cancellationToken);

            // Submit to SCITT
            byte[] transparentStatement = await _submissionService.SubmitAndWaitAsync(signedStatement, cancellationToken);

            // Cache receipt
            _cacheService.StoreReceipt(jobId, transparentStatement);

            // OCI index
            if (resolverResult.Subject is not null && resolverResult.Indexable && _ociIndexer.Enabled)
            {
                IndexerContext indexerContext = new()
                {
                    Receipt = transparentStatement,
                    Subject = resolverResult.Subject,
                    PayloadHash = payloadHash,
                    ContentType = payloadData.ContentType,
                    ResolverMetadata = resolverResult.ResolverMetadata,
                };
                IndexerResult indexerResult = _ociIndexer.Index(indexerContext);
                if (indexerResult.Success)
                {
                    _logger.LogInformation("Receipt indexed: {Reference}", indexerResult.Reference);
                }
                else
                {
                    _logger.LogWarning("Receipt indexing failed: {Error}", indexerResult.Error);
                }
            }

            job.Status = JobStatus.Completed;
            _jobService.SaveJob(job);
            _jobService.CleanupJobPayload(jobId);
            _logger.LogInformation("Job {JobId} completed successfully", jobId[..16]);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Job {JobId} failed", jobId[..16]);
            job.Status = JobStatus.Failed;
            job.Error = ex.Message;
            _jobService.SaveJob(job);
            _jobService.CleanupJobPayload(jobId);
        }
    }
}
