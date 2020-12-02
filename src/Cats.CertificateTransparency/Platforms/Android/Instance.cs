using Java.Interop;
using Java.Security;
using Javax.Net.Ssl;
using System;
using System.Linq;

namespace Cats.CertificateTransparency
{
    public static partial class Instance
    {
        private static readonly Lazy<ICertificateChainCleaner> DefaultCertChainCleaner =
            new Lazy<ICertificateChainCleaner>(() => new CertificateChainCleaner(GetLocalTrustManager()));

        public static ICertificateChainCleaner CertificateChainCleaner => DefaultCertChainCleaner.Value;

        internal static IX509TrustManager GetLocalTrustManager()
        {
            var trustManager = TrustManagerFactory.GetInstance(TrustManagerFactory.DefaultAlgorithm);
            trustManager.Init(null as KeyStore);
            var localTrustManager = trustManager.GetTrustManagers().First().JavaCast<IX509TrustManager>();
            return localTrustManager;
        }
    }
}