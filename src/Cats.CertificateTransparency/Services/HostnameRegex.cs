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
            IList<Regex> includedPatterns,
            IList<Regex> excludedPatterns)
        {
            _includedPatterns = includedPatterns ?? new List<Regex>(0);
            _excludedPatterns = excludedPatterns ?? new List<Regex>(0);
        }

        public bool ValidateHost(string host)
            => (!_includedPatterns.Any() || _includedPatterns.Any(r => r.IsMatch(host))) &&
               _excludedPatterns.All(r => !r.IsMatch(host));
    } 
}
