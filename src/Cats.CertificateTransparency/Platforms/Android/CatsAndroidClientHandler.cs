using Cats.CertificateTransparency.Models;
using Javax.Net.Ssl;
using System;
using System.Collections.Generic;
using Xamarin.Android.Net;
using DotNetX509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace Cats.CertificateTransparency
{
#if NET6_0_OR_GREATER
    [Obsolete("CatsAndroidClientHandler has been deprecated. Use CatsAndroidMessageHandler instead.")]
#endif
    public class CatsAndroidClientHandler : AndroidClientHandler
    {
        private readonly IHostnameVerifier _hostnameVerifier;

        public CatsAndroidClientHandler()
        {
            _hostnameVerifier = new CatsHostnameVerifier();
        }

        public CatsAndroidClientHandler(
            Func<string, IList<DotNetX509Certificate>, CtVerificationResult, bool> verifyResultFunc)
        {
            _hostnameVerifier = new CatsHostnameVerifier(verifyResultFunc);
        }

        public CatsAndroidClientHandler(IHostnameVerifier hostnameVerifier)
        {
            _hostnameVerifier = hostnameVerifier;
        }

        protected override IHostnameVerifier GetSSLHostnameVerifier(HttpsURLConnection connection)
        {
            return _hostnameVerifier;
        }
    }
}