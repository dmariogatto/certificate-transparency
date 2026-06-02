using Cats.CertificateTransparency.Extensions;
using System;
using System.Linq;

namespace Cats.CertificateTransparency.Models
{
    public readonly struct DigitallySigned : IEquatable<DigitallySigned>
    {
        public CtHashAlgorithm Hash { get; init; }
        public CtSignatureAlgorithm Signature { get; init; }
        public ReadOnlyMemory<byte> SignatureData { get; init; }

        public string PrettyPrint() => string.Join(Environment.NewLine,
                new object[] { Hash, Signature, SignatureData.Span.ToHexString() });

        public bool Equals(DigitallySigned other)
        {
            return Hash == other.Hash &&
                   Signature == other.Signature &&
                   SignatureData.Span.SequenceEqual(other.SignatureData.Span);
        }

        public override bool Equals(object obj)
            => obj is DigitallySigned other && Equals(other);

        public override int GetHashCode()
        {
            var hc = new HashCode();
            hc.Add(Hash);
            hc.Add(Signature);

            hc.AddBytes(SignatureData.Span);

            return hc.ToHashCode();
        }
    }
}