using Cats.CertificateTransparency.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

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
    public class Log
    {
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
                _keyBytes = null;
            }
        }

        [JsonPropertyName("url")]
        public string Url { get; set; }

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

        private byte[] _keyBytes;
        public byte[] KeyBytes
        {
            get
            {
                if (_keyBytes is null)
                    _keyBytes = Convert.FromBase64String(Key);

                return _keyBytes;
            }
        }

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
    }

    [Preserve(AllMembers = true)]
    public class LogListRoot
    {
        [JsonPropertyName("operators")]
        public List<Operator> Operators { get; set; }

        public IDictionary<string, Log> ToDictionary()
            => Operators
                .Where(o => o.Logs?.Any() == true)
                .SelectMany(o => o.Logs)
                .ToDictionary(l => l.LogId, l => l);
    }
}
