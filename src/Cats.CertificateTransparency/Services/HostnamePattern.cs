using System;
using System.Collections.Generic;
using System.Linq;

namespace Cats.CertificateTransparency.Services
{
    public class HostnamePattern : IHostnameValidator
    {
        private const string Https = "https://";
        private const string MatchAll = "*.*";
        private const string Wildcard = "*.";
        private const string Dot = ".";

        private readonly IList<(string pattern, string host)> _includedPatterns;
        private readonly IList<(string pattern, string host)> _excludedPatterns;

        public HostnamePattern(
            IList<string> includedPatterns,
            IList<string> excludedPatterns)
        {
            _includedPatterns = includedPatterns.Select(p => (p, GetCanonicalHost(p))).ToList() ?? new List<(string, string)>(0);
            _excludedPatterns = excludedPatterns.Select(p => (p, GetCanonicalHost(p))).ToList() ?? new List<(string, string)>(0);
        }

        public string[] Included => _includedPatterns.Select(i => i.Item1).ToArray();
        public string[] Excluded => _excludedPatterns.Select(i => i.Item1).ToArray();

        public bool ValidateHost(string host)
            => (!_includedPatterns.Any() || _includedPatterns.Any(i => Matches(host, i.pattern, i.host))) &&
               _excludedPatterns.All(i => !Matches(host, i.pattern, i.host));

        private static bool Matches(string host, string pattern, string canonicalHost)
        {
            if (pattern == MatchAll || string.Equals(host, canonicalHost, StringComparison.OrdinalIgnoreCase))
                return true;

            if (pattern.StartsWith(Wildcard))
            {
                var firstDot = host.IndexOf(Dot);
                return host.Length - firstDot - 1 == canonicalHost.Length &&
                       host.IndexOf(canonicalHost, firstDot + 1, canonicalHost.Length, StringComparison.OrdinalIgnoreCase) > 0;
            }

            return false;
        }

        private static string GetCanonicalHost(string pattern)
        {
            if (pattern == MatchAll)
                return string.Empty;

            var uriString = pattern.StartsWith(Wildcard)
                ? Https + pattern.Substring(Wildcard.Length)
                : Https + pattern;

            if (!Uri.TryCreate(uriString, UriKind.Absolute, out var uri))
                throw new ArgumentException($"'{pattern}' is not a well-formed Url");

            return uri.Host;
        }
    } 
}
