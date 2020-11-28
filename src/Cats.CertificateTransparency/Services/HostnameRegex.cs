using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Cats.CertificateTransparency.Services
{
    public class HostnameRegex : IHostnameValidator
    {
        private readonly IList<Regex> _includedPatterns;
        private readonly IList<Regex> _excludedPatterns;

        public HostnameRegex(
            IEnumerable<Regex> includedPatterns,
            IEnumerable<Regex> excludedPatterns)
        {
            if (includedPatterns?.Any() != true)
                throw new ArgumentException("No included patterns");

            if (excludedPatterns?.Any() == true && includedPatterns.Any(i => excludedPatterns.Contains(i)))
                throw new ArgumentException("Same pattern found in both included & excluded");

            _includedPatterns = includedPatterns?.ToList() ?? new List<Regex>(0);
            _excludedPatterns = excludedPatterns?.ToList() ?? new List<Regex>(0);
        }

        public bool ValidateHost(string host)
            => (!_includedPatterns.Any() || _includedPatterns.Any(r => r.IsMatch(host))) &&
               _excludedPatterns.All(r => !r.IsMatch(host));
    } 
}
