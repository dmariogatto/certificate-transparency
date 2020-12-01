using System.Collections.Generic;
using JavaX509Certificate = Java.Security.Cert.X509Certificate;

namespace Cats.CertificateTransparency
{
    public interface ICertificateChainCleaner
    {
        IList<JavaX509Certificate> Clean(IEnumerable<JavaX509Certificate> chain);
    }
}