using Org.BouncyCastle.Asn1.X509;
using System;
using System.Linq;

namespace Cats.CertificateTransparency.Models
{
    public class IssuerInformation
    {
        public X509Name Name { get; set; }
        public byte[] KeyHash { get; set; }
        public X509Extension X509AuthorityKeyIdentifier { get; set; }
        public bool IssuedByPreCertificateSigningCert { get; set; }

        public override bool Equals(object obj)
        {
            return obj is IssuerInformation issuer &&
                   Name == issuer.Name &&
                   KeyHash.SequenceEqual(issuer.KeyHash) &&
                   X509AuthorityKeyIdentifier == issuer.X509AuthorityKeyIdentifier &&
                   IssuedByPreCertificateSigningCert == issuer.IssuedByPreCertificateSigningCert;
        }

        public override int GetHashCode() => (Name, KeyHash, X509AuthorityKeyIdentifier, IssuedByPreCertificateSigningCert).GetHashCode();
    }
}
