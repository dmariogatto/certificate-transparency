using Java.Security;
using Javax.Net.Ssl;
using System;
using System.Linq;

namespace Cats.CertificateTransparency
{
    public static partial class Instance
    {
        private static readonly Lazy<ICertificateChainCleaner> DefaultCertChainCleaner =
            new Lazy<ICertificateChainCleaner>(() =>
            {
                var trustManager = TrustManagerFactory.GetInstance(TrustManagerFactory.DefaultAlgorithm);
                trustManager.Init(null as KeyStore);
                var localTrustManager = trustManager.GetTrustManagers().OfType<IX509TrustManager>().First();
                return new CertificateChainCleaner(localTrustManager);
            });

        public static ICertificateChainCleaner CertificateChainCleaner => DefaultCertChainCleaner.Value;
    }
}