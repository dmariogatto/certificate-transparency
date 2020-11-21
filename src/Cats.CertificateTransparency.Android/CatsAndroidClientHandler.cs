﻿using Cats.CertificateTransparency.Models;
using Javax.Net.Ssl;
using System;
using System.Collections.Generic;
using Xamarin.Android.Net;
using DotNetX509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace Cats.CertificateTransparency.Android
{
    public class CatsAndroidClientHandler : AndroidClientHandler
    {
        private readonly IHostnameVerifier _hostnameVerifier;

        public CatsAndroidClientHandler()
        {
            _hostnameVerifier = new CatsHostNameVerifier();
        }

        public CatsAndroidClientHandler(
            Func<string, DotNetX509Certificate, IList<DotNetX509Certificate>, CtVerificationResult, bool> _verifyResultFunc)
        {
            _hostnameVerifier = new CatsHostNameVerifier(_verifyResultFunc);
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