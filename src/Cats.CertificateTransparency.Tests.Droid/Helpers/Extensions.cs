using Java.Security.Cert;
using System.Collections.Generic;
using System.IO;
using DotNetX509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate2;
using JavaX509Certificate = Java.Security.Cert.X509Certificate;

namespace Cats.CertificateTransparency.Tests.Droid
{
    public static class Extensions
    {
        public static IList<JavaX509Certificate> ToJavaCerts(this IEnumerable<DotNetX509Certificate> certificates)
        {
            var certFactory = CertificateFactory.GetInstance("X.509");
            var javaCerts = new List<JavaX509Certificate>();

            foreach (var dotNetCert in certificates)
            {
                using var ms = new MemoryStream(dotNetCert.RawData);
                var javaCert = (JavaX509Certificate)certFactory.GenerateCertificate(ms);
                javaCerts.Add(javaCert);
            }

            return javaCerts.ToArray();
        }
    }
}