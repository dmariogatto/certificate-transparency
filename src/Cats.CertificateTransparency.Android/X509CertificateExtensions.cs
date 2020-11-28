using Javax.Security.Auth.X500;
using System;
using DotNetX509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate2;
using JavaX509Certificate = Java.Security.Cert.X509Certificate;

namespace Cats.CertificateTransparency.Android
{
    internal static class X509CertificateExtensions
    {
        internal static DotNetX509Certificate ToDotNetX509Certificate(this JavaX509Certificate cert)
            => new DotNetX509Certificate(cert.GetEncoded());

        internal static bool IsSignedBy(this JavaX509Certificate cert, JavaX509Certificate signingCert)
        {
            if (cert?.IssuerDN is X500Principal p1 &&
                signingCert?.SubjectDN is X500Principal p2 &&
                p1.Equals(p2))
            {
                try
                {
                    cert.Verify(signingCert.PublicKey);
                    return true;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(ex);
                }
            }

            return false;
        }
    }
}