using Cats.CertificateTransparency.Extensions;
using System;
using System.Linq;

namespace Cats.CertificateTransparency.Models
{
    public class DigitallySigned
    {
        public CtHashAlgorithm Hash { get; set; }
        public CtSignatureAlgorithm Signature { get; set; }
        public byte[] SignatureData { get; set; }

        public string PrettyPrint() => string.Join(Environment.NewLine,
                new object[] { Hash, Signature, SignatureData.ToHexString() }).Trim();

        public override bool Equals(object obj)
        {
            return obj is DigitallySigned signed &&
                   Hash == signed.Hash &&
                   Signature == signed.Signature &&
                   SignatureData.SequenceEqual(signed.SignatureData);
        }

        public override int GetHashCode() => (Hash, Signature, SignatureData).GetHashCode();
    }
}
