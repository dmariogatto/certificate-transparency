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

        private readonly Dictionary<X500Principal, List<JavaX509Certificate>> _trustedBySubject;

        public CertificateChainCleaner(IX509TrustManager trustManager)
        {
            var comparer = new X500PrincipalEquality();

            _trustedBySubject = trustManager.GetAcceptedIssuers()
                .GroupBy(c => c.SubjectX500Principal, comparer)
                .ToDictionary(g => g.Key, g => g.ToList(), comparer);
        }

        public IList<JavaX509Certificate> Clean(IEnumerable<JavaX509Certificate> chain)
        {
            if (chain is null)
                throw new SSLPeerUnverifiedException("Certificate chain is null");

            var remaining = chain.ToList();
            if (remaining.Count == 0)
                throw new SSLPeerUnverifiedException("Empty chain");

            var result = new List<JavaX509Certificate>(MaxChainDepth)
            {
                remaining[0]
            };
            remaining.RemoveAt(0);

            for (var depth = 0; depth < MaxChainDepth; depth++)
            {
                var current = result[^1];
                var issuer = current.IssuerX500Principal;

                // 1. Try trusted issuers
                if (_trustedBySubject.TryGetValue(issuer, out var trustedCandidates))
                {
                    var trusted = trustedCandidates.FirstOrDefault(c => current.IsSignedBy(c));
                    if (trusted != null)
                    {
                        if (!current.Equals(trusted))
                            result.Add(trusted);

                        if (IsSelfSigned(trusted))
                            return result;

                        continue;
                    }
                }

                // 2. Try remaining chain
                var next = remaining.FirstOrDefault(c => current.IsSignedBy(c));
                if (next is not null)
                {
                    remaining.Remove(next);
                    result.Add(next);
                    continue;
                }

                throw new SSLPeerUnverifiedException(
                    $"Failed to find issuer for {current.SubjectX500Principal}");
            }

            throw new SSLPeerUnverifiedException("Certificate chain too long");
        }

        private static bool IsSelfSigned(JavaX509Certificate cert) =>
            cert.SubjectX500Principal.Equals(cert.IssuerX500Principal) &&
            cert.IsSignedBy(cert);

        private class X500PrincipalEquality : IEqualityComparer<X500Principal>
        {
            public bool Equals(X500Principal x, X500Principal y)
                => ReferenceEquals(x, y) || (x is not null && x.Equals(y));

            public int GetHashCode(X500Principal obj)
                => obj?.GetHashCode() ?? 0;
        }
    }
}