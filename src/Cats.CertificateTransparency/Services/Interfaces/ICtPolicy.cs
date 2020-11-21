using Cats.CertificateTransparency.Models;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Cats.CertificateTransparency.Services
{
    public interface ICtPolicy
    {
        public CtVerificationResult PolicyVerificationResult(X509Certificate2 leafCertificate, IDictionary<string, SctVerificationResult> sctResults);
    }
}
