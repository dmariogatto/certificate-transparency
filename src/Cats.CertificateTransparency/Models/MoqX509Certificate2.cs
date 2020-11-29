#if DEBUG
using System;
using System.Security.Cryptography.X509Certificates;

namespace Cats.CertificateTransparency.Models
{
    internal class MoqX509Certificate2 : X509Certificate2
    {
        public MoqX509Certificate2(X509Certificate2 certificate) : base(certificate) { }
        public MoqX509Certificate2() { }

        public virtual DateTime MoqNotBefore => throw new NotImplementedException();
        public virtual DateTime MoqNotAfter => throw new NotImplementedException();
        public virtual X509ExtensionCollection GetMoqExtensions() => throw new NotImplementedException();

        public new DateTime NotBefore => MoqNotBefore;
        public new DateTime NotAfter => MoqNotAfter;

        public new X509ExtensionCollection Extensions => GetMoqExtensions();
    }
}
#endif
