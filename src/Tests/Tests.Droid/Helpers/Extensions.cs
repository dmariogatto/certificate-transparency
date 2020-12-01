using Java.Security.Cert;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using DotNetX509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate2;
using JavaX509Certificate = Java.Security.Cert.X509Certificate;

namespace Tests.Droid
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

            return javaCerts;
        }

        public static IList<DotNetX509Certificate> ToDotNetCerts(this IEnumerable<JavaX509Certificate> certificates)
        {            
            return certificates.Select(c => new DotNetX509Certificate(c.GetEncoded())).ToList();
        }
    }
}