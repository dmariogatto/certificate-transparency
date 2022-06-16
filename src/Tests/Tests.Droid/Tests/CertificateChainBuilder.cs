using Cats.CertificateTransparency;
using Javax.Net.Ssl;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Tests.Droid;

namespace Tests
{
    internal static class CertificateChainBuilder
    {
        private static readonly IX509TrustManager TrustManager = Instance.GetLocalTrustManager();

        internal static IList<X509Certificate2> Build(IEnumerable<X509Certificate2> chain, X509Certificate2 rootCert = null)
        {
            rootCert ??= Data.LoadCerts(Data.ROOT_CA_CERT).First();
            var rootCerts = new[] { rootCert }.ToJavaCerts().ToArray();

            var trustManager = new Moq.Mock<IX509TrustManager>();
            trustManager.Setup(tm => tm.GetAcceptedIssuers())
                        .Returns(TrustManager.GetAcceptedIssuers().Concat(rootCerts).ToArray());

            var chainBuilder = new CertificateChainCleaner(trustManager.Object);
            var completeChain = chain.ToJavaCerts();

            return chainBuilder.Clean(completeChain).ToDotNetCerts();
        }
    }
}