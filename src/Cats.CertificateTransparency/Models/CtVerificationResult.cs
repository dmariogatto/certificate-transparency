using System;
using System.Collections.Generic;
using System.Linq;

namespace Cats.CertificateTransparency.Models
{
    public class CtVerificationResult
    {
        public static CtVerificationResult DisabledForHost()
            => new CtVerificationResult(CtResult.DisabledForHost);
        public static CtVerificationResult Trusted(IEnumerable<SctVerificationResult> sctResults, int minimumTrustedScts)
            => new CtVerificationResult(CtResult.Trusted, sctResults, minimumTrustedScts);
        public static CtVerificationResult InsecureConnection()
           => new CtVerificationResult(CtResult.InsecureConnection);
        public static CtVerificationResult NoCertificates()
           => new CtVerificationResult(CtResult.NoCertificates);
        public static CtVerificationResult LogServersFailed()
          => new CtVerificationResult(CtResult.LogServersFailed);
        public static CtVerificationResult NoScts()
          => new CtVerificationResult(CtResult.NoScts);
        public static CtVerificationResult TooFewSctsTrusted(IEnumerable<SctVerificationResult> sctResults, int minimumTrustedScts)
          => new CtVerificationResult(CtResult.TooFewSctsTrusted, sctResults, minimumTrustedScts);

        public CtVerificationResult(CtResult result, IEnumerable<SctVerificationResult> sctResults = null, int minSctCount = -1)
        {
            Result = result;
            SctResults = sctResults?.ToArray() ?? Array.Empty<SctVerificationResult>();
            MinSctCount = minSctCount;
        }

        public CtVerificationResult()
        {
            Result = CtResult.Unknown;
            SctResults = Array.Empty<SctVerificationResult>();
            MinSctCount = -1;
        }

        public CtResult Result { get; private set; }

        public IReadOnlyCollection<SctVerificationResult> SctResults { get; private set; }

        public int MinSctCount { get; private set; }

        public int ValidSctCount => SctResults?.Count(r => r.IsValid) ?? -1;

        public bool IsValid =>
            Result == CtResult.Trusted ||
            Result == CtResult.DisabledForHost;

        public string Description => Result switch
        {
            CtResult.DisabledForHost => "Success: SCT disabled for host",
            CtResult.Trusted => "Success: SCT trusted logs",
            CtResult.InsecureConnection => "Success: SCT not enabled for insecure connection",
            CtResult.NoCertificates => "Failure: No certificates",
            CtResult.LogServersFailed => "Failure: Unable to load log servers",
            CtResult.NoScts => "Failure: Certificate does not have any SCTs",
            CtResult.TooFewSctsTrusted => "Failure: Certificate does not have any SCTs",
            CtResult.FailedWithException => "Failure: Too few trusted SCTs",
            _ => Result.ToString()
        };

        public override string ToString() => Description;
    }
}
