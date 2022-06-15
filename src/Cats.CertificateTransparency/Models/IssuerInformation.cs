using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Cats.CertificateTransparency.Models
{
    public class IssuerInformation
    {
        public string Name { get; set; }
        public byte[] KeyHash { get; set; }
        public X509Extension X509AuthorityKeyIdentifier { get; set; }
        public bool IssuedByPreCertificateSigningCert { get; set; }

        public override bool Equals(object obj)
        {
            return obj is IssuerInformation issuer &&
                   string.Equals(Name, issuer.Name, StringComparison.Ordinal) &&
                   KeyHash.SequenceEqual(issuer.KeyHash) &&
                   X509AuthorityKeyIdentifier == issuer.X509AuthorityKeyIdentifier &&
                   IssuedByPreCertificateSigningCert == issuer.IssuedByPreCertificateSigningCert;
        }

        public override int GetHashCode() => (Name, KeyHash, X509AuthorityKeyIdentifier, IssuedByPreCertificateSigningCert).GetHashCode();
    }
}
