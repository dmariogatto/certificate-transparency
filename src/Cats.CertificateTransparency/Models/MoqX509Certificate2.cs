#if DEBUG
using System;
using System.Security.Cryptography.X509Certificates;

namespace Cats.CertificateTransparency.Models
{
    internal class MoqX509Certificate2 : X509Certificate2
    {
        public MoqX509Certificate2(X509Certificate2 certificate) : base(certificate) { }

        public virtual X509ExtensionCollection GetMoqExtensions() => throw new NotImplementedException();

        public new X509ExtensionCollection Extensions
        {
            get => GetMoqExtensions();
        }
    }
}
#endif
