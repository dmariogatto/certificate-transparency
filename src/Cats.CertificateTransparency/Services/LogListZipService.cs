using Cats.CertificateTransparency.Api;
using Cats.CertificateTransparency.Models;
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Cats.CertificateTransparency.Services
{
    public class LogListZipService : LogListService
    {
        private readonly SemaphoreSlim _logListSemaphore = new SemaphoreSlim(1, 1);

        public LogListZipService(
            ILogListApi logListApi,
            ILogStoreService logStoreService) : base(logListApi, logStoreService)
        {
        }

        public async override Task<LogListRoot> GetLogListRootAsync(CancellationToken cancellationToken)
        {
            var logListRoot = default(LogListRoot);

            var stopwatch = new System.Diagnostics.Stopwatch();
            stopwatch.Start();

            if (!LogStoreService.TryGetValue(LogListRootKey, out logListRoot))
            {
                await _logListSemaphore.WaitAsync().ConfigureAwait(false);

                try
                {
                    if (!LogStoreService.TryGetValue(LogListRootKey, out logListRoot))
                    {
                        var logListZip = await LogListApi.GetLogListZip(cancellationToken).ConfigureAwait(false);
                        cancellationToken.ThrowIfCancellationRequested();

                        using var stream = await logListZip.ReadAsStreamAsync().ConfigureAwait(false);
                        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, false);

                        if (archive.Entries.Count != 2)
                            throw new InvalidOperationException($"Expected 2 files from log list zip, got {archive.Entries.Count}");

                        var logListEntry = archive.Entries.FirstOrDefault(e => e.Name.EndsWith(".json"))
                            ?? throw new InvalidDataException($"Could not find log list json entry");

                        var logListSignatureEntry = archive.Entries.FirstOrDefault(e => e.Name.EndsWith(".sig"))
                            ?? throw new InvalidDataException($"Could not find log list signature entry");

                        using var logListStream = logListEntry.Open();
                        using var logListSignatureStream = logListSignatureEntry.Open();
                        using var ms = new MemoryStream();

                        await logListStream.CopyToAsync(ms, 81920, cancellationToken).ConfigureAwait(false);
                        var logListBytes = ms.ToArray();

                        ms.SetLength(0);
                        await logListSignatureStream.CopyToAsync(ms, 81920, cancellationToken).ConfigureAwait(false);
                        var logListSignatureBytes = ms.ToArray();

                        var isValid = VerifyGoogleSignature(logListBytes, logListSignatureBytes);

                        if (!isValid)
                            throw new InvalidDataException("Log list failed signature verification!");

                        logListRoot = Deserialise<LogListRoot>(logListBytes);

                        if (logListRoot?.Operators != null)
                            LogStoreService.SetValue(LogListRootKey, logListRoot);
                    }
                }
                catch
                {
                    throw;
                }
                finally
                {
                    _logListSemaphore.Release();
                }
            }

            stopwatch.Stop();

            return logListRoot;            
        }
    }
}
