using Cats.CertificateTransparency.Models;
using Javax.Net.Ssl;
using System;
using System.Collections.Generic;
using Xamarin.Android.Net;
using DotNetX509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace Cats.CertificateTransparency
{
    public class CatsAndroidMessageHandler : AndroidMessageHandler
    {
        private readonly IHostnameVerifier _hostnameVerifier;

        public CatsAndroidMessageHandler()
        {
            _hostnameVerifier = new CatsHostnameVerifier();
        }

        public CatsAndroidMessageHandler(
            Func<string, IList<DotNetX509Certificate>, CtVerificationResult, bool> verifyResultFunc)
        {
            _hostnameVerifier = new CatsHostnameVerifier(verifyResultFunc);
        }

        public CatsAndroidMessageHandler(IHostnameVerifier hostnameVerifier)
        {
            _hostnameVerifier = hostnameVerifier;
        }

        protected override IHostnameVerifier GetSSLHostnameVerifier(HttpsURLConnection connection)
        {
            return _hostnameVerifier;
        }
    }
}