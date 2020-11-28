using Cats.CertificateTransparency.Services;
using NUnit.Framework;
using System;

namespace Cats.CertificateTransparency.Tests
{
    public class HostnamePatternTest
    {
        [Test]
        public void EmptyPatterns()
        {
            Assert.Throws<ArgumentException>(() => new HostnamePattern(Array.Empty<string>(), Array.Empty<string>()));
        }

        [Test]
        public void IncludeWildcard()
        {
            var included = new string[]
            {
                "*.*"
            };
            var excluded = new string[]
            {
            };

            var hostnamePattern = new HostnamePattern(included, excluded);
            Assert.True(hostnamePattern.ValidateHost("example.com"));
        }

        [Test]
        public void IncludedNoWildcard()
        {
            var included = new string[]
            {
                "a.example.com",
                "b.example.com"
            };
            var excluded = new string[]
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
            var included = new string[]
            {
                "a.exAmpLe.com",
                "B.example.com"
            };
            var excluded = new string[]
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
            var included = new string[]
            {
                "*.example.com",                
            };
            var excluded = new string[]
            {
                "b.example.com"
            };

            var hostnamePattern = new HostnamePattern(included, excluded);
            Assert.True(hostnamePattern.ValidateHost("example.com"));
            Assert.True(hostnamePattern.ValidateHost("a.example.com"));
            Assert.False(hostnamePattern.ValidateHost("b.example.com"));
            Assert.True(hostnamePattern.ValidateHost("c.example.com"));
        }

        [Test]
        public void InvalidUrl()
        {
            var included = new string[]
            {
                "*.exam!ple.com",
            };
            var excluded = new string[]
            {
            };

            Assert.Throws<ArgumentException>(() => new HostnamePattern(included, excluded));
        }
    }
}
