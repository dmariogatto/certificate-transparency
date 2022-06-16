using BenchmarkDotNet.Attributes;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Cats.CertificateTransparency;
using Cats.CertificateTransparency.Services;

namespace Samples.Console
{
    public class CtBenchmark
    {
        private readonly ICertificateTransparencyVerifier _verifier = Instance.CertificateTransparencyVerifier;
        private readonly IDictionary<string, IList<X509Certificate2>> _hostAndCertChains;

        public CtBenchmark()
        {
            var result = SetupAsync().Result;
            _hostAndCertChains = new Dictionary<string, IList<X509Certificate2>>(result);

            _ = Instance.LogListService.LoadLogListAsync(default);
        }

        [Benchmark]
        public async Task VerifyAsync()
        {
            foreach (var kv in _hostAndCertChains)
            {
                await _verifier.IsValidAsync(kv.Key, kv.Value, default);
            }
        }

        private async Task<IDictionary<string, IList<X509Certificate2>>> SetupAsync()
        {
            var hostAndCertChains = new ConcurrentDictionary<string, IList<X509Certificate2>>();

            var client = new HttpClient(new HttpClientHandler()
            {
                ServerCertificateCustomValidationCallback = (request, certificate, certChain, sslPolicyErrors) =>
                {
                    var certs = certChain.ChainElements
                        .OfType<X509ChainElement>()
                        .Select(i => new X509Certificate2(i.Certificate.RawData))
                        .ToList();
                    var host = request.RequestUri.Host;
                    hostAndCertChains[host] = certs;

                    return sslPolicyErrors == SslPolicyErrors.None;
                }
            });

            await Task.WhenAll(
                client.GetAsync("https://www.google.com.au"),
                client.GetAsync("https://github.com/"),
                client.GetAsync("https://www.microsoft.com/")).ConfigureAwait(false);

            return hostAndCertChains;
        }
    }
}
