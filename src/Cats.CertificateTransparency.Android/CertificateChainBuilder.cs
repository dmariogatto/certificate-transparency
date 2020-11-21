using Java.Security;
using Javax.Net.Ssl;
using System;
using System.Collections.Generic;
using System.Linq;
using JavaX509Certificate = Java.Security.Cert.X509Certificate;

namespace Cats.CertificateTransparency.Android
{
    public class CertificateChainBuilder : ICertificateChainBuilder
    {
        public const int MaxChainDepth = 9;

        private static readonly Lazy<ICertificateChainBuilder> DefaultCertCleaner =
            new Lazy<ICertificateChainBuilder>(() =>
            {
                var trustManager = TrustManagerFactory.GetInstance(TrustManagerFactory.DefaultAlgorithm);
                trustManager.Init(null as KeyStore);
                var localTrustManager = trustManager.GetTrustManagers().OfType<IX509TrustManager>().First();
                return new CertificateChainBuilder(localTrustManager);
            });

        public static ICertificateChainBuilder Default => DefaultCertCleaner.Value;

        private readonly Dictionary<string, List<JavaX509Certificate>> _subjectCaCerts;

        public CertificateChainBuilder(IX509TrustManager trustManager)
        {
            _subjectCaCerts = trustManager.GetAcceptedIssuers()
                    .GroupBy(i => i.IssuerX500Principal.Name)
                    .ToDictionary(g => g.Key, g => g.Select(i => i).ToList());
        }

        public IList<JavaX509Certificate> GetCertificateChain(IEnumerable<JavaX509Certificate> chain)
        {
            var result = new List<JavaX509Certificate>();

            if (chain.Any())
            {
                var chainList = chain.ToList();

                result.Add(chain.First());
                chainList.Remove(result.Last());

                var foundTrusted = false;

                for (var i = 0; i < MaxChainDepth; i++)
                {
                    var toVerify = result.Last();
                    var issuer = toVerify.IssuerX500Principal;

                    var trustedCert = default(JavaX509Certificate);
                    if (issuer.Name is string key && _subjectCaCerts.ContainsKey(key))
                    {
                        trustedCert = _subjectCaCerts[key].FirstOrDefault(c => toVerify.IsSignedBy(c));

                        if (result.Count > 1 || toVerify != trustedCert)
                            result.Add(trustedCert);
                        if (trustedCert.IsSignedBy(trustedCert))
                            break; // we've reached the root certificate

                        foundTrusted = true;
                    }

                    if (trustedCert == default)
                    {
                        var sigingCert = chainList.FirstOrDefault(c => toVerify.IsSignedBy(c));
                        if (sigingCert != default)
                        {
                            chainList.Remove(sigingCert);
                            result.Add(sigingCert);
                        }
                        else if (!foundTrusted)
                        {
                            // No certificate is trusted and we've gone through the entire chain so fail
                            throw new SSLPeerUnverifiedException($"Failed to find a trusted cert that signed {toVerify}");
                        }
                    }
                }
            }

            return result;
        }
    }
}