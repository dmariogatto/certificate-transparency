using Cats.CertificateTransparency;
using Java.Security;
using Javax.Net.Ssl;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Tests.Droid;

namespace Tests
{
    internal static class CertificateChainBuilder
    {
        private static readonly Lazy<IX509TrustManager> TrustManager =
            new Lazy<IX509TrustManager>(() =>
            {
                var trustManager = TrustManagerFactory.GetInstance(TrustManagerFactory.DefaultAlgorithm);
                trustManager.Init(null as KeyStore);
                var localTrustManager = trustManager.GetTrustManagers().OfType<IX509TrustManager>().First();
                return localTrustManager;
            });

        internal static IList<X509Certificate2> Build(IEnumerable<X509Certificate2> chain, X509Certificate2 rootCert = null)
        {
            var rootCerts = rootCert == null
                                  ? Data.LoadCerts(Data.ROOT_CA_CERT)
                                        .ToJavaCerts()
                                        .ToArray()
                                  : new[] { rootCert }.ToJavaCerts().ToArray();

            var trustManager = new Moq.Mock<IX509TrustManager>();
            trustManager.Setup(tm => tm.GetAcceptedIssuers())
                        .Returns(TrustManager.Value.GetAcceptedIssuers().Concat(rootCerts).ToArray());

            var chainBuilder = new CertificateChainCleaner(trustManager.Object);
            var completeChain = chain.ToJavaCerts();

            return chainBuilder.Clean(completeChain).ToDotNetCerts();
        }
    }
}