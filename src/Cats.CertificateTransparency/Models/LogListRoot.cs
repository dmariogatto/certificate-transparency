using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Cats.CertificateTransparency.Models
{
    public class Usable
    {
        [JsonProperty("timestamp")]
        public DateTime Timestamp { get; set; }
    }

    public class FinalTreeHead
    {
        [JsonProperty("sha256_root_hash")]
        public string Sha256RootHash { get; set; }

        [JsonProperty("tree_size")]
        public int TreeSize { get; set; }
    }

    public class Readonly
    {
        [JsonProperty("timestamp")]
        public DateTime Timestamp { get; set; }

        [JsonProperty("final_tree_head")]
        public FinalTreeHead FinalTreeHead { get; set; }
    }

    public class Retired
    {
        [JsonProperty("timestamp")]
        public DateTime Timestamp { get; set; }
    }

    public class Qualified
    {
        [JsonProperty("timestamp")]
        public DateTime Timestamp { get; set; }
    }

    public class State
    {
        [JsonProperty("usable")]
        public Usable Usable { get; set; }

        [JsonProperty("readonly")]
        public Readonly Readonly { get; set; }

        [JsonProperty("retired")]
        public Retired Retired { get; set; }

        [JsonProperty("qualified")]
        public Qualified Qualified { get; set; }
    }

    public class TemporalInterval
    {
        [JsonProperty("start_inclusive")]
        public DateTime StartInclusive { get; set; }

        [JsonProperty("end_exclusive")]
        public DateTime EndExclusive { get; set; }
    }

    public class Log
    {
        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("log_id")]
        public string LogId { get; set; }

        private string _key;
        [JsonProperty("key")]
        public string Key 
        {
            get => _key;
            set
            {
                _key = value;
                _keyBytes = null;
            }
        }

        [JsonProperty("url")]
        public string Url { get; set; }

        [JsonProperty("mmd")]
        public int Mmd { get; set; }

        private State _state;
        [JsonProperty("state")]
        public State State
        {
            get => _state;
            set
            {
                _state = value;
                _validUntilUtc = null;
            }
        }

        [JsonProperty("temporal_interval")]
        public TemporalInterval TemporalInterval { get; set; }

        private byte[] _keyBytes;
        public byte[] KeyBytes
        {
            get
            {
                if (_keyBytes == null)
                    _keyBytes = Convert.FromBase64String(Key);
                
                return _keyBytes;
            }
        }

        private DateTime? _validUntilUtc;
        public DateTime? ValidUntilUtc
        {
            get
            {
                if (!_validUntilUtc.HasValue && State?.Retired != null)
                    _validUntilUtc = State.Retired.Timestamp;
                if (!_validUntilUtc.HasValue && State?.Readonly != null)
                    _validUntilUtc = State.Readonly.Timestamp;

                return _validUntilUtc;
            }
        }
    }

    public class Operator
    {
        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("email")]
        public List<string> Email { get; set; }

        [JsonProperty("logs")]
        public List<Log> Logs { get; set; }
    }

    public class LogListRoot
    {
        [JsonProperty("operators")]
        public List<Operator> Operators { get; set; }

        public IDictionary<string, Log> ToDictionary()
            => Operators
                .Where(o => o.Logs?.Any() == true)
                .SelectMany(o => o.Logs)
                .ToDictionary(l => l.LogId, l => l);
    }
}
