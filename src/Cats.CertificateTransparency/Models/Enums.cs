using System;

namespace Cats.CertificateTransparency.Models
{
    public enum CtSignatureAlgorithm
    {
        Unknown = -1,
        Anonymous = 0,
        Rsa = 1,
        Dsa = 2,
        Ecdsa = 3
    }

    public enum CtHashAlgorithm
    {
        None = 0,
        Md5 = 1,
        Sha1 = 2,
        Sha224 = 3,
        Sha256 = 4,
        Sha384 = 5,
        Sha512 = 6
    }

    public enum SctVersion
    {
        V1 = 0,
        Unknow = 256
    }

    public enum SctResult
    {
        Unknown = -1,
        Valid,
        FailedVerification,
        NoTrustedLogServerFound,
        FutureTimestamp,
        UntrustedLogServer,
        FailedWithException
    }

    public enum CtResult
    {
        Unknown = -1,
        // Success
        DisabledForHost,
        Trusted,
        InsecureConnection,
        // Failed
        NoCertificates,
        LogServersFailed,
        NoScts,
        TooFewSctsTrusted,
        FailedWithException
    }
}
