using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Cats.CertificateTransparency.Models
{
    public class IssuerInformation
    {
        public string Name { get; init; }
        public ReadOnlyMemory<byte> KeyHash { get; init; }
        public X509Extension X509AuthorityKeyIdentifier { get; init; }
        public bool IssuedByPreCertificateSigningCert { get; init; }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;
            if (ReferenceEquals(this, obj))
                return true;

            return obj is IssuerInformation issuer &&
                   string.Equals(Name, issuer.Name, StringComparison.Ordinal) &&
                   KeyHash.Span.SequenceEqual(issuer.KeyHash.Span) &&
                   X509AuthorityKeyIdentifier == issuer.X509AuthorityKeyIdentifier &&
                   IssuedByPreCertificateSigningCert == issuer.IssuedByPreCertificateSigningCert;
        }

        public override int GetHashCode()
        {
            var hc = new HashCode();
            hc.Add(Name);
            hc.AddBytes(KeyHash.Span);
            hc.Add(X509AuthorityKeyIdentifier);
            hc.Add(IssuedByPreCertificateSigningCert);
            return hc.ToHashCode();
        }
    }
}
