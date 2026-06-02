using Cats.CertificateTransparency.Attributes;
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Threading;

namespace Cats.CertificateTransparency.Models
{
    [Preserve(AllMembers = true)]
    public class Usable
    {
        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; }
    }

    [Preserve(AllMembers = true)]
    public class FinalTreeHead
    {
        [JsonPropertyName("sha256_root_hash")]
        public string Sha256RootHash { get; set; }

        [JsonPropertyName("tree_size")]
        public int TreeSize { get; set; }
    }

    [Preserve(AllMembers = true)]
    public class Readonly
    {
        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; }

        [JsonPropertyName("final_tree_head")]
        public FinalTreeHead FinalTreeHead { get; set; }
    }

    [Preserve(AllMembers = true)]
    public class Retired
    {
        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; }
    }

    [Preserve(AllMembers = true)]
    public class Qualified
    {
        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; }
    }

    [Preserve(AllMembers = true)]
    public class State
    {
        [JsonPropertyName("usable")]
        public Usable Usable { get; set; }

        [JsonPropertyName("readonly")]
        public Readonly Readonly { get; set; }

        [JsonPropertyName("retired")]
        public Retired Retired { get; set; }

        [JsonPropertyName("qualified")]
        public Qualified Qualified { get; set; }
    }

    [Preserve(AllMembers = true)]
    public class TemporalInterval
    {
        [JsonPropertyName("start_inclusive")]
        public DateTime StartInclusive { get; set; }

        [JsonPropertyName("end_exclusive")]
        public DateTime EndExclusive { get; set; }
    }

    [Preserve(AllMembers = true)]
    public abstract class BaseLog : ILog, IDisposable
    {
        internal const string PkcsOidRsaEncryption = "1.2.840.113549.1.1.1";
        internal const string X9OidIdECPublicKey = "1.2.840.10045.2.1";

        private bool _disposed;

        private CtSignatureAlgorithm _algorithm = CtSignatureAlgorithm.Unknown;
        private string _oid = string.Empty;

        private ThreadLocal<RSA> _rsa;
        private ThreadLocal<ECDsa> _ecdsa;

        [JsonPropertyName("description")]
        public string Description { get; set; }

        [JsonPropertyName("log_id")]
        public string LogId { get; set; }

        private string _key;

        [JsonPropertyName("key")]
        public string Key
        {
            get => _key;
            set
            {
                _key = value;

                KeyBytes = !string.IsNullOrWhiteSpace(value)
                    ? Convert.FromBase64String(value)
                    : Array.Empty<byte>();

                (_oid, _algorithm) = GetKeyAlgorithm(KeyBytes);

                // Reset thread-local instances when key changes
                ResetVerifiers();
            }
        }

        [JsonPropertyName("mmd")]
        public int Mmd { get; set; }

        private State _state;
        [JsonPropertyName("state")]
        public State State
        {
            get => _state;
            set
            {
                _state = value;
                _validUntilUtc = null;
            }
        }

        [JsonPropertyName("temporal_interval")]
        public TemporalInterval TemporalInterval { get; set; }

        public ReadOnlyMemory<byte> KeyBytes { get; private set; }

        private DateTime? _validUntilUtc;
        public DateTime? ValidUntilUtc
        {
            get
            {
                if (!_validUntilUtc.HasValue && State?.Retired is not null)
                    _validUntilUtc = State.Retired.Timestamp;
                if (!_validUntilUtc.HasValue && State?.Readonly is not null)
                    _validUntilUtc = State.Readonly.Timestamp;

                return _validUntilUtc;
            }
        }

        public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);

            return _algorithm switch
            {
                CtSignatureAlgorithm.Rsa => GetOrCreateRsa().Value.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                CtSignatureAlgorithm.Ecdsa => GetOrCreateECDsa().Value.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence),
                _ => throw new NotImplementedException($"Signature algorithm '{_algorithm}' not supported, with OID '{_oid}'")
            };
        }

        private ThreadLocal<RSA> GetOrCreateRsa()
        {
            var current = _rsa;
            if (current is not null)
                return current;

            var keyBytes = KeyBytes;
            var created = new ThreadLocal<RSA>(() =>
            {
                var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(keyBytes.Span, out _);
                return rsa;
            }, true);

            return Interlocked.CompareExchange(ref _rsa, created, null) ?? created;
        }

        private ThreadLocal<ECDsa> GetOrCreateECDsa()
        {
            var current = _ecdsa;
            if (current is not null)
                return current;

            var keyBytes = KeyBytes;
            var created = new ThreadLocal<ECDsa>(() =>
            {
                var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(keyBytes.Span, out _);
                return ecdsa;
            }, true);

            return Interlocked.CompareExchange(ref _ecdsa, created, null) ?? created;
        }

        private void ResetVerifiers()
        {
            var rsa = Interlocked.Exchange(ref _rsa, null);
            if (rsa is not null)
            {
                foreach (var r in rsa.Values)
                    r.Dispose();
                rsa.Dispose();
            }

            var ecdsa = Interlocked.Exchange(ref _ecdsa, null);
            if (ecdsa is not null)
            {
                foreach (var e in ecdsa.Values)
                    e.Dispose();
                ecdsa.Dispose();
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    ResetVerifiers();
                }

                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private static (string oid, CtSignatureAlgorithm sigAlg) GetKeyAlgorithm(ReadOnlyMemory<byte> keyBytes)
        {
            try
            {
                var reader = new AsnReader(keyBytes, AsnEncodingRules.DER);
                var outer = reader.ReadSequence();
                var algId = outer.ReadSequence();
                var oid = algId.ReadObjectIdentifier();

                return oid switch
                {
                    PkcsOidRsaEncryption => (oid, CtSignatureAlgorithm.Rsa),
                    X9OidIdECPublicKey => (oid, CtSignatureAlgorithm.Ecdsa),
                    _ => (oid, CtSignatureAlgorithm.Unknown)
                };
            }
            catch (AsnContentException)
            {
                return (string.Empty, CtSignatureAlgorithm.Unknown);
            }
        }
    }

    [Preserve(AllMembers = true)]
    public class Log : BaseLog
    {
        [JsonPropertyName("url")]
        public string Url { get; set; }
    }

    [Preserve(AllMembers = true)]
    public class TiledLog : BaseLog
    {
        [JsonPropertyName("submission_url")]
        public string SubmissionUrl { get; set; }

        [JsonPropertyName("monitoring_url")]
        public string MonitoringUrl { get; set; }
    }

    [Preserve(AllMembers = true)]
    public class Operator
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("email")]
        public List<string> Email { get; set; }

        [JsonPropertyName("logs")]
        public List<Log> Logs { get; set; }

        [JsonPropertyName("tiled_logs")]
        public List<TiledLog> TiledLogs { get; set; }
    }

    [Preserve(AllMembers = true)]
    public class LogListRoot
    {
        [JsonPropertyName("operators")]
        public List<Operator> Operators { get; set; }

        public IDictionary<string, ILog> ToDictionary()
            => Operators
                .SelectMany(o => (o.Logs ?? Enumerable.Empty<ILog>()).Concat(o.TiledLogs ?? []))
                .ToDictionary(l => l.LogId, l => l, StringComparer.Ordinal);
    }
}
