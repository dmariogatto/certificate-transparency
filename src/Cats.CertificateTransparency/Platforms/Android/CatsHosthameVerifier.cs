using Cats.CertificateTransparency.Extensions;
using Cats.CertificateTransparency.Models;
using Cats.CertificateTransparency.Services;
using Java.Security.Cert;
using Javax.Net.Ssl;
using System;
using System.Collections.Generic;
using System.Linq;
using DotNetX509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace Cats.CertificateTransparency
{
    public class CatsHostnameVerifier : Java.Lang.Object, IHostnameVerifier
    {
        private readonly ICertificateChainCleaner _certCleaner;
        private readonly ICertificateTransparencyVerifier _verifier;

        private readonly Func<string, IList<DotNetX509Certificate>, CtVerificationResult, bool> _verifyResultFunc;

        public CatsHostnameVerifier()
             : this(null, Instance.CertificateChainCleaner, Instance.CertificateTransparencyVerifier)
        {
        }

        public CatsHostnameVerifier(
            Func<string, IList<DotNetX509Certificate>, CtVerificationResult, bool> verifyResultFunc)
             : this(verifyResultFunc, Instance.CertificateChainCleaner, Instance.CertificateTransparencyVerifier)
        {
        }

        public CatsHostnameVerifier(
            Func<string, IList<DotNetX509Certificate>, CtVerificationResult, bool> verifyResultFunc,
            ICertificateChainCleaner certificateCleaner,
            ICertificateTransparencyVerifier certificateTransparencyVerifier)
        {
            _verifyResultFunc = verifyResultFunc;
            _certCleaner = certificateCleaner;
            _verifier = certificateTransparencyVerifier;
        }

        public bool Verify(string hostname, ISSLSession session)
        {
            var certChain = _certCleaner.Clean(session.GetPeerCertificates().OfType<X509Certificate>());

            if (certChain.Any())
            {
                var dotNetCertChain = certChain.Select(c => c.ToDotNetX509Certificate()).ToList();

                var ctValueTask = _verifier.IsValidAsync(hostname, dotNetCertChain, default);
                var ctResult = ctValueTask.IsCompleted
                    ? ctValueTask.Result
                    : ctValueTask.AsTask().Result;

                var customResult = _verifyResultFunc?.Invoke(hostname, dotNetCertChain, ctResult);
                return customResult ?? ctResult.IsValid;
            }

            return false;
        }
    }
}