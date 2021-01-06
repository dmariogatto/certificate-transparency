using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Tests
{
    internal static class CertificateChainBuilder
    {
        internal static IList<X509Certificate2> Build(IEnumerable<X509Certificate2> chain, X509Certificate rootCert = null)
        {
            if (chain?.Any() != true) return null;

            rootCert ??= Data.LoadCerts(Data.ROOT_CA_CERT).First();

            var leaf = chain.First();
            chain = chain.Skip(1);

            using var chainBuilder = new X509Chain();
            chainBuilder.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chainBuilder.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            foreach (var c in chain)
                chainBuilder.ChainPolicy.ExtraStore.Add(c);

            chainBuilder.ChainPolicy.ExtraStore.Add(rootCert);
            var isValidChain = chainBuilder.Build(leaf);
            var builtChain = chainBuilder.ChainElements.OfType<X509ChainElement>().Select(i => i.Certificate).ToList();

            isValidChain |= chainBuilder.ChainStatus.All(
                s => s.Status == X509ChainStatusFlags.UntrustedRoot ||
                     s.Status == X509ChainStatusFlags.HasNotSupportedCriticalExtension ||
                     s.Status == X509ChainStatusFlags.InvalidExtension ||
                     s.Status == X509ChainStatusFlags.NotTimeValid ||
                     (s.Status == X509ChainStatusFlags.PartialChain && chain.Contains(rootCert)));

            return isValidChain || chain.Contains(rootCert)
                ? builtChain
                : null;
        }
    }
}