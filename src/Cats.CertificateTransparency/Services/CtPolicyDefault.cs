using Cats.CertificateTransparency.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Cats.CertificateTransparency.Services
{
    public class CtPolicyDefault : ICtPolicy
    {
        public CtPolicyDefault()
        {
        }

        public CtVerificationResult PolicyVerificationResult(X509Certificate2 leafCertificate, IDictionary<string, SctVerificationResult> sctResults)
        {
#if DEBUG
            var moqCert = leafCertificate as MoqX509Certificate2;
            var before = moqCert?.NotBefore ?? leafCertificate.NotBefore;
            var after = moqCert?.NotAfter ?? leafCertificate.NotAfter;
#else
            var before = leafCertificate.NotBefore;
            var after = leafCertificate.NotAfter;
#endif

            var (months, partial) = FlooredMonth(before, after);
            var minValidScts = MinimumValidSignedCertificateTimestamps(months, partial);

            var validScts = sctResults.Count(kv => kv.Value.IsValid);
            if (validScts < minValidScts)
                return CtVerificationResult.TooFewSctsTrusted(sctResults.Values, minValidScts);

            return CtVerificationResult.Trusted(sctResults.Values, minValidScts);
        }

        private static int MinimumValidSignedCertificateTimestamps(int months, bool partial)
        {
            if (months > 39 || (months == 39 && partial))
                return 5;
            if (months > 27 || (months == 27 && partial))
                return 4;
            if (months >= 15)
                return 3;

            return 2;
        }

        private static (int months, bool partial) FlooredMonth(DateTime start, DateTime end)
        {
            if (end < start)
                return (0, false);

            var flooredMonth = (end.Year - start.Year) * 12 + (end.Month - start.Month) - (end.Day < start.Day ? 1 : 0);
            var partial = end.Day != start.Day;

            return (flooredMonth, partial);
        }
    }
}
