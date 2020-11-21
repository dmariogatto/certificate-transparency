using Cats.CertificateTransparency.Models;
using Cats.CertificateTransparency.Services;
using Java.Security.Cert;
using Javax.Net.Ssl;
using System;
using System.Collections.Generic;
using System.Linq;
using DotNetX509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace Cats.CertificateTransparency.Android
{
    public class CatsHostNameVerifier : Java.Lang.Object, IHostnameVerifier
    {
        private readonly ICertificateChainBuilder _certificateCleaner;
        private readonly ICertificateTransparencyVerifier _certificateTransparencyVerifier;

        private readonly Func<string, DotNetX509Certificate, IList<DotNetX509Certificate>, CtVerificationResult, bool> _verifyResultFunc;

        public CatsHostNameVerifier() 
             : this(null, CertificateChainBuilder.Default, CertificateTransparencyVerifier.Default)
        {
        }

        public CatsHostNameVerifier(
            Func<string, DotNetX509Certificate, IList<DotNetX509Certificate>, CtVerificationResult, bool> verifyResultFunc)
             : this(verifyResultFunc, CertificateChainBuilder.Default, CertificateTransparencyVerifier.Default)
        {
        }

        public CatsHostNameVerifier(
            Func<string, DotNetX509Certificate, IList<DotNetX509Certificate>, CtVerificationResult, bool> verifyResultFunc,
            ICertificateChainBuilder certificateCleaner,
            ICertificateTransparencyVerifier certificateTransparencyVerifier)
        {
            _verifyResultFunc = verifyResultFunc;
            _certificateCleaner = certificateCleaner;
            _certificateTransparencyVerifier = certificateTransparencyVerifier;
        }
        
        public bool Verify(string hostname, ISSLSession session)
        {
            var certChain = _certificateCleaner.GetCertificateChain(session.GetPeerCertificates().OfType<X509Certificate>());
            
            if (certChain.Any())
            {
                var dotNetCertChain = certChain.Select(c => c.ToDotNetX509Certificate()).ToList();
                var ctResult = _certificateTransparencyVerifier.IsValidAsync(hostname, dotNetCertChain.First(), dotNetCertChain, default).Result;
                var customResult = _verifyResultFunc?.Invoke(hostname, dotNetCertChain.First(), dotNetCertChain, ctResult);
                return customResult ?? ctResult.IsValid;
            }

            return false;
        }
    }
}