using Cats.CertificateTransparency.Services;
using Java.Security;
using Javax.Net.Ssl;
using System;
using System.Linq;

namespace Cats.CertificateTransparency.Android
{
    public static class Instance
    {
        private static readonly Lazy<ICertificateChainBuilder> DefaultCertChainBuilder =
            new Lazy<ICertificateChainBuilder>(() =>
            {
                var trustManager = TrustManagerFactory.GetInstance(TrustManagerFactory.DefaultAlgorithm);
                trustManager.Init(null as KeyStore);
                var localTrustManager = trustManager.GetTrustManagers().OfType<IX509TrustManager>().First();
                return new CertificateChainBuilder(localTrustManager);
            });

        public static ICertificateChainBuilder CertificateChainBuilder => DefaultCertChainBuilder.Value;

        public static ICertificateTransparencyVerifier CertificateTransparencyVerifier => CertificateTransparency.Instance.CertificateTransparencyVerifier;
    }
}