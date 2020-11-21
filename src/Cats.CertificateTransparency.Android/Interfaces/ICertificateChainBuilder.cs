using System.Collections.Generic;
using JavaX509Certificate = Java.Security.Cert.X509Certificate;

namespace Cats.CertificateTransparency.Android
{
    public interface ICertificateChainBuilder
    {
        IList<JavaX509Certificate> GetCertificateChain(IEnumerable<JavaX509Certificate> chain);
    }
}