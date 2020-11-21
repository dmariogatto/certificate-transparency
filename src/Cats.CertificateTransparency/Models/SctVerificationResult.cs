using System;

namespace Cats.CertificateTransparency.Models
{
    public sealed class SctVerificationResult
    {
        public static SctVerificationResult Valid()
            => new SctVerificationResult(SctResult.Valid, $"Valid SCT", null);
        public static SctVerificationResult FailedVerification()
            => new SctVerificationResult(SctResult.FailedVerification, $"SCT signature failed verification", null);
        public static SctVerificationResult FailedVerification(string description)
            => new SctVerificationResult(SctResult.FailedVerification, description, null);
        public static SctVerificationResult NoTrustedLogServerFound()
           => new SctVerificationResult(SctResult.NoTrustedLogServerFound, $"No trusted log server found for SCT", null);
        public static SctVerificationResult FutureTimestamp(DateTime timestampUtc, DateTime nowUtc)
           => new SctVerificationResult(SctResult.FutureTimestamp, $"SCT timestamp, {timestampUtc:g}, is in the future, current timestamp is {nowUtc:g}", null);
        public static SctVerificationResult LogServerUntrusted(DateTime timestampUtc, DateTime logServerValidUntilUtc)
          => new SctVerificationResult(SctResult.UntrustedLogServer, $"SCT timestamp, {timestampUtc:g}, is greater than the log server validity, {logServerValidUntilUtc:g}", null);
        public static SctVerificationResult FailedWithException(Exception exception)
          => new SctVerificationResult(SctResult.FailedWithException, $"Exception during verification, {exception.Message}", exception);

        public SctVerificationResult(SctResult result, string description, Exception exception)
        {
            Result = result;
            Description = description;
            Exception = exception;
        }

        public SctResult Result { get; private set; }
        public string Description { get; private set; }
        public Exception Exception { get; private set; }

        public bool IsValid => Result == SctResult.Valid;
        public override string ToString() => Description;
    }
}
