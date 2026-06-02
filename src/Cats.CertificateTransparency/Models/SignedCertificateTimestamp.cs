using Cats.CertificateTransparency.Extensions;
using System;

namespace Cats.CertificateTransparency.Models
{
    public readonly struct SignedCertificateTimestamp : IEquatable<SignedCertificateTimestamp>
    {
        public SignedCertificateTimestamp()
        {
        }

        public SctVersion SctVersion { get; init; }

        private readonly ReadOnlyMemory<byte> _logId;
        public ReadOnlyMemory<byte> LogId
        {
            get => _logId;
            init
            {
                _logId = value;
                LogIdBase64 = !LogId.IsEmpty ? Convert.ToBase64String(LogId.Span) : string.Empty;
            }
        }

        private readonly long _timestampMs;
        public long TimestampMs
        {
            get => _timestampMs;
            init
            {
                _timestampMs = value;
                TimestampUtc = DateTimeOffset.FromUnixTimeMilliseconds(TimestampMs).UtcDateTime;
            }
        }

        public DigitallySigned Signature { get; init; }
        public ReadOnlyMemory<byte> Extensions { get; init; }

        public string LogIdBase64 { get; private init; }
        public DateTime TimestampUtc { get; private init; }

        public string PrettyPrint() => string.Join(Environment.NewLine,
                new object[] { SctVersion, LogId.Span.ToHexString(), TimestampUtc, Signature.PrettyPrint(), Extensions.Span.ToHexString() });


        public bool Equals(SignedCertificateTimestamp other)
        {
            return SctVersion == other.SctVersion &&
                   TimestampMs == other.TimestampMs &&
                   Signature.Equals(other.Signature) &&
                   LogId.Span.SequenceEqual(other.LogId.Span) &&
                   Extensions.Span.SequenceEqual(other.Extensions.Span);
        }

        public override bool Equals(object obj)
            => obj is SignedCertificateTimestamp other && Equals(other);

        public override int GetHashCode()
        {
            var hc = new HashCode();
            hc.Add(SctVersion);
            hc.Add(TimestampMs);
            hc.Add(Signature);

            hc.AddBytes(LogId.Span);
            hc.AddBytes(Extensions.Span);

            return hc.ToHashCode();
        }
    }
}
