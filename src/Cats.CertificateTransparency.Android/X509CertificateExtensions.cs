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
            // Object equals does not work, falling back to name
            if (cert.IssuerDN.Name == signingCert.SubjectDN.Name)
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