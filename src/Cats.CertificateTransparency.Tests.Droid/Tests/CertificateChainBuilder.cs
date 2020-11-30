using Cats.CertificateTransparency.Tests.Droid;
using Java.Security;
using Javax.Net.Ssl;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Cats.CertificateTransparency.Tests
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
                                  ? TestData.Certificates
                                            .LoadCerts(TestData.Certificates.ROOT_CA_CERT)
                                            .ToJavaCerts()
                                            .ToArray()
                                  : new[] { rootCert }.ToJavaCerts().ToArray();

            var trustManager = new Moq.Mock<IX509TrustManager>();
            trustManager.Setup(tm => tm.GetAcceptedIssuers())
                        .Returns(TrustManager.Value.GetAcceptedIssuers().Concat(rootCerts).ToArray());

            var chainBuilder = new Android.CertificateChainBuilder(trustManager.Object);
            var completeChain = chain.ToJavaCerts();

            return chainBuilder.GetCertificateChain(completeChain).ToDotNetCerts();
        }
    }
}