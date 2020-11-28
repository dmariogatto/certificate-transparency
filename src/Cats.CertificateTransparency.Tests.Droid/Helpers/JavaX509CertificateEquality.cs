using System.Collections.Generic;
using JavaX509Certificate = Java.Security.Cert.X509Certificate;

namespace Cats.CertificateTransparency.Tests.Droid
{
    public class JavaX509CertificateEquality : IEqualityComparer<JavaX509Certificate>
    {
        public bool Equals(JavaX509Certificate x, JavaX509Certificate y) => x.Equals(y);
        public int GetHashCode(JavaX509Certificate obj) => obj.GetHashCode();
    }
}