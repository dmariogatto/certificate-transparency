using Cats.CertificateTransparency.Extensions;
using System;
using System.Linq;

namespace Cats.CertificateTransparency.Models
{
    public class SignedCertificateTimestamp
    {
        public SctVersion SctVersion { get; set; }

        private byte[] _logId = null;
        public byte[] LogId
        {
            get => _logId;
            set
            {
                _logId = value;
                _logIdBase64 = null;
            }
        }

        private long _timestampMs;
        public long TimestampMs
        {
            get => _timestampMs;
            set
            {
                _timestampMs = value;
                _timestampUtc = null;
            }
        }

        public DigitallySigned Signature { get; set; }
        public byte[] Extensions { get; set; }

        private string _logIdBase64;
        public string LogIdBase64
        {
            get
            {
                if (string.IsNullOrEmpty(_logIdBase64) && LogId != null)
                    _logIdBase64 = Convert.ToBase64String(LogId);

                return _logIdBase64 ?? string.Empty;
            }
        }

        private DateTime? _timestampUtc;
        public DateTime TimestampUtc
        {
            get
            {
                if (!_timestampUtc.HasValue)
                    _timestampUtc = DateTimeOffset.FromUnixTimeMilliseconds(TimestampMs).UtcDateTime;

                return _timestampUtc.Value;
            }
        }

        public string PrettyPrint() => string.Join(Environment.NewLine,
                new object[] { SctVersion, LogId.ToHexString(), TimestampUtc, Signature.PrettyPrint(), Extensions.ToHexString() }).Trim();

        public override bool Equals(object obj)
        {
            return obj is SignedCertificateTimestamp timestamp &&
                   SctVersion == timestamp.SctVersion &&
                   LogId.SequenceEqual(timestamp.LogId) &&
                   TimestampMs == timestamp.TimestampMs &&
                   Signature.Equals(timestamp.Signature) &&
                   Extensions.SequenceEqual(timestamp.Extensions);
        }

        public override int GetHashCode() => (SctVersion, LogId, TimestampMs, Signature, Extensions).GetHashCode();
    }
}
