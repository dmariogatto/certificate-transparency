using Cats.CertificateTransparency.Extensions;
using Javax.Net.Ssl;
using Javax.Security.Auth.X500;
using System.Collections.Generic;
using System.Linq;
using JavaX509Certificate = Java.Security.Cert.X509Certificate;

namespace Cats.CertificateTransparency
{
    public class CertificateChainCleaner : ICertificateChainCleaner
    {
        private const int MaxChainDepth = 9;

        private readonly Dictionary<X500Principal, List<JavaX509Certificate>> _subjectCaCerts;

        public CertificateChainCleaner(IX509TrustManager trustManager)
        {
            var keyEquality = new X500PrincipalEquality();
            _subjectCaCerts = trustManager.GetAcceptedIssuers()
                    .GroupBy(i => i.IssuerX500Principal, keyEquality)
                    .ToDictionary(g => g.Key, g => g.Select(i => i).ToList(), keyEquality);
        }

        public IList<JavaX509Certificate> Clean(IEnumerable<JavaX509Certificate> chain)
        {
            if (chain?.Any() != true) throw new SSLPeerUnverifiedException($"Empty chain");

            var result = new List<JavaX509Certificate>();

            var chainList = chain.ToList();

            result.Add(chain.First());
            chainList.Remove(result.Last());

            var foundTrusted = false;

            for (var i = 0; i < MaxChainDepth; i++)
            {
                var toVerify = result.Last();
                var issuer = toVerify.IssuerX500Principal;

                var trustedCert = default(JavaX509Certificate);

                if (_subjectCaCerts.ContainsKey(issuer))
                {
                    trustedCert = _subjectCaCerts[issuer].FirstOrDefault(c => toVerify.IsSignedBy(c));

                    if (trustedCert != null)
                    {
                        if (result.Count > 1 || toVerify != trustedCert)
                            result.Add(trustedCert);
                        if (trustedCert.IsSignedBy(trustedCert))
                            return result; // we've reached the root certificate
                    }

                    foundTrusted = true;
                }

                if (trustedCert == default)
                {
                    var sigingCert = chainList.FirstOrDefault(c => toVerify.IsSignedBy(c));
                    if (sigingCert != default)
                    {
                        chainList.Remove(sigingCert);
                        result.Add(sigingCert);
                    }
                    else if (foundTrusted)
                    {
                        return result;
                    }
                    else if (!foundTrusted)
                    {
                        // No certificate is trusted and we've gone through the entire chain so fail
                        throw new SSLPeerUnverifiedException($"Failed to find a trusted cert that signed {toVerify}");
                    }
                }
            }

            throw new SSLPeerUnverifiedException($"Certificate chain too long");
        }

        private class X500PrincipalEquality : IEqualityComparer<X500Principal>
        {
            public bool Equals(X500Principal x, X500Principal y) => x.Equals(y);
            public int GetHashCode(X500Principal obj) => obj.GetHashCode();
        }
    }
}