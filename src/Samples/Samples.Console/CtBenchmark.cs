using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Cats.CertificateTransparency;
using Cats.CertificateTransparency.Services;

namespace Samples.Console
{
    [MemoryDiagnoser] // <-- memory + GC stats
    [SimpleJob(RuntimeMoniker.Net10_0)] // adjust if needed
    public class CtBenchmark
    {
        private readonly ICertificateTransparencyVerifier _verifier = Instance.CertificateTransparencyVerifier;

        private IDictionary<string, IList<X509Certificate2>> _hostAndCertChains;

        // Popular / diverse endpoints (CDN, cloud, geo, etc.)
        private static readonly string[] Urls =
        {
            "https://www.google.com.au",
            "https://www.google.com",
            "https://github.com",
            "https://stackoverflow.com",
            "https://learn.microsoft.com",
            "https://azure.microsoft.com",
            "https://aws.amazon.com",
            "https://www.cloudflare.com",
            "https://www.reddit.com",
            "https://news.ycombinator.com",
            "https://www.wikipedia.org",
            "https://twitter.com",
            "https://www.youtube.com",
            "https://openai.com"
        };

        [GlobalSetup]
        public async Task GlobalSetup()
        {
            _hostAndCertChains = await SetupAsync().ConfigureAwait(false);

            // warm log list (avoid skewing benchmark)
            await Instance.LogListService.LoadLogListAsync(CancellationToken.None)
                .ConfigureAwait(false);
        }

        // Baseline: iterate all hosts
        [Benchmark(Baseline = true)]
        public async Task Verify_All()
        {
            foreach (var kv in _hostAndCertChains)
            {
                await _verifier.IsValidAsync(kv.Key, kv.Value, CancellationToken.None).ConfigureAwait(false);
            }
        }

        // Variant: parallel (realistic high-throughput scenario)
        [Benchmark]
        public async Task Verify_All_Parallel()
        {
            var tasks = _hostAndCertChains
                .Select(kv => _verifier.IsValidAsync(kv.Key, kv.Value, CancellationToken.None).AsTask())
                .ToList();
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }

        // Variant: single host (isolates per-call cost)
        [Benchmark]
        public async Task Verify_Single()
        {
            var first = _hostAndCertChains.First();
            await _verifier.IsValidAsync(first.Key, first.Value, default)
                .ConfigureAwait(false);
        }

        private static async Task<IDictionary<string, IList<X509Certificate2>>> SetupAsync()
        {
            var hostAndCertChains = new ConcurrentDictionary<string, IList<X509Certificate2>>();

            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (request, certificate, certChain, sslPolicyErrors) =>
                {
                    if (certChain?.ChainElements != null)
                    {
                        var certs = certChain.ChainElements
                            .OfType<X509ChainElement>()
                            .Select(e => X509CertificateLoader.LoadCertificate(e.Certificate.RawData))
                            .ToList();

                        var host = request.RequestUri.Host;
                        hostAndCertChains[host] = certs;
                    }

                    return sslPolicyErrors == SslPolicyErrors.None;
                }
            };

            using var client = new HttpClient(handler);

            // fire all requests concurrently
            await Task.WhenAll(Urls.Select(u => client.GetAsync(u)))
                .ConfigureAwait(false);

            return hostAndCertChains;
        }
    }
}