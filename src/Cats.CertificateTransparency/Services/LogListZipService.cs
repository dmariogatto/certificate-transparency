using Cats.CertificateTransparency.Api;
using Cats.CertificateTransparency.Models;
using System.IO;
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
                        var logListBytes = await LogListApi.GetLogListWithSigAsync(cancellationToken).ConfigureAwait(false);
                        var isValid = VerifyGoogleSignature(logListBytes.list, logListBytes.sig);

                        if (!isValid)
                            throw new InvalidDataException("Log list failed signature verification!");

                        logListRoot = Deserialise<LogListRoot>(logListBytes.list);

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
