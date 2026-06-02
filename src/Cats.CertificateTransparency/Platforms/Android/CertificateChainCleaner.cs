using Cats.CertificateTransparency.Extensions;
using Javax.Net.Ssl;
using Javax.Security.Auth.X500;
using System;
using System.Collections.Generic;
using System.Linq;
using JavaX509Certificate = Java.Security.Cert.X509Certificate;

namespace Cats.CertificateTransparency
{
    public class CertificateChainCleaner : ICertificateChainCleaner
    {
        private const int MaxChainDepth = 9;

        private readonly Dictionary<X500Principal, JavaX509Certificate[]> _subjectCaCerts;

        public CertificateChainCleaner(IX509TrustManager trustManager)
        {
            var keyEquality = new X500PrincipalEquality();
            _subjectCaCerts = trustManager.GetAcceptedIssuers()
                .GroupBy(i => i.SubjectX500Principal, keyEquality)
                .ToDictionary(g => g.Key, g => g.Select(i => i).ToArray(), keyEquality);
        }

        public IList<JavaX509Certificate> Clean(IEnumerable<JavaX509Certificate> chain)
        {
            if (chain is null)
                throw new ArgumentNullException(nameof(chain));

            var originalChain = chain as IReadOnlyList<JavaX509Certificate> ?? [.. chain];
            if (originalChain.Count == 0)
                throw new SSLPeerUnverifiedException("Empty chain");

            var resultChain = new List<JavaX509Certificate>(Math.Min(originalChain.Count + 1, MaxChainDepth))
            {
                originalChain[0]
            };

            // Track visited indices from the incoming chain
            var visitedIndices = new bool[originalChain.Count];
            visitedIndices[0] = true;

            var foundTrustedCertificate = false;

            for (var i = 0; i < MaxChainDepth; i++)
            {
                var toVerify = resultChain[^1];
                var issuer = toVerify.IssuerX500Principal;

                // Step 1: Look in the Trust Store
                JavaX509Certificate trustedCert = null;
                if (_subjectCaCerts.TryGetValue(issuer, out var trustedCerts))
                {
                    for (var k = 0; k < trustedCerts.Length && trustedCert is null; k++)
                    {
                        var candidate = trustedCerts[k];
                        if (toVerify.IsSignedBy(candidate))
                            trustedCert = candidate;
                    }
                }

                if (trustedCert is not null)
                {
                    // If the current cert was already verified by a trusted cert,
                    // and it wasn't just verifying itself, add the trust anchor to the chain.
                    if (resultChain.Count > 1 || toVerify != trustedCert)
                    {
                        resultChain.Add(trustedCert);
                    }

                    if (trustedCert.IsSignedBy(trustedCert))
                    {
                        // Self-signed root CA encountered, exit immediately
                        return resultChain;
                    }

                    foundTrustedCertificate = true;
                    // Trust match found, jump to next loop turn
                    continue;
                }

                // Step 2: Not in Trust Store. Look in untrusted chain
                JavaX509Certificate signingCert = null;
                for (var k = 1; k < originalChain.Count && signingCert is null; k++)
                {
                    if (visitedIndices[k]) continue;

                    var candidate = originalChain[k];
                    if (toVerify.IsSignedBy(candidate))
                    {
                        visitedIndices[k] = true;
                        signingCert = candidate;
                    }
                }

                if (signingCert is not null)
                {
                    resultChain.Add(signingCert);
                    // Signer found in chain, jump to next loop turn
                    continue;
                }

                // Step 3: Neither found. Only exit cleanly if we flagged a trusted cert earlier
                if (foundTrustedCertificate)
                {
                    return resultChain;
                }

                throw new SSLPeerUnverifiedException($"Failed to find a trusted cert that signed {toVerify}");
            }

            throw new SSLPeerUnverifiedException("Certificate chain too long");
        }

        private class X500PrincipalEquality : IEqualityComparer<X500Principal>
        {
            public bool Equals(X500Principal x, X500Principal y) => x.Equals(y);
            public int GetHashCode(X500Principal obj) => obj.GetHashCode();
        }
    }
}