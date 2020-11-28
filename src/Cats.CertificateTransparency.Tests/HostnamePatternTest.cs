using Cats.CertificateTransparency.Services;
using NUnit.Framework;
using System.Collections.Generic;

namespace Cats.CertificateTransparency.Tests
{
    public class HostnamePatternTest
    {
        [Test]
        public void EmptyPatterns()
        {
            var included = new List<string>()
            { 
            };
            var excluded = new List<string>()
            {
            };

            var hostnamePattern = new HostnamePattern(included, excluded);
            Assert.True(hostnamePattern != null);
        }

        [Test]
        public void IncludeWildcard()
        {
            var included = new List<string>()
            {
                "*.*"
            };
            var excluded = new List<string>()
            {
            };

            var hostnamePattern = new HostnamePattern(included, excluded);
            Assert.True(hostnamePattern.ValidateHost("example.com"));
        }

        [Test]
        public void IncludedNoWildcard()
        {
            var included = new List<string>()
            {
                "a.example.com",
                "b.example.com"
            };
            var excluded = new List<string>()
            {
            };

            var hostnamePattern = new HostnamePattern(included, excluded);
            Assert.True(hostnamePattern.ValidateHost("a.example.com"));
            Assert.True(hostnamePattern.ValidateHost("b.example.com"));
            Assert.False(hostnamePattern.ValidateHost("c.example.com"));
        }

        [Test]
        public void IncludedNoWildcardCaseInsensitive()
        {
            var included = new List<string>()
            {
                "a.exAmpLe.com",
                "B.example.com"
            };
            var excluded = new List<string>()
            {
            };

            var hostnamePattern = new HostnamePattern(included, excluded);
            Assert.True(hostnamePattern.ValidateHost("a.exampLe.com"));
            Assert.True(hostnamePattern.ValidateHost("b.eXample.com"));
            Assert.False(hostnamePattern.ValidateHost("c.example.com"));
        }

        [Test]
        public void IncludeWildcardWithExclusion()
        {
            var included = new List<string>()
            {
                "*.example.com",                
            };
            var excluded = new List<string>()
            {
                "b.example.com"
            };

            var hostnamePattern = new HostnamePattern(included, excluded);
            Assert.True(hostnamePattern.ValidateHost("example.com"));
            Assert.True(hostnamePattern.ValidateHost("a.example.com"));
            Assert.False(hostnamePattern.ValidateHost("b.example.com"));
            Assert.True(hostnamePattern.ValidateHost("c.example.com"));
        }
    }
}
