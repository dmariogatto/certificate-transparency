using System;
using System.Runtime.CompilerServices;

#if DEBUG
[assembly: InternalsVisibleTo("Tests")]
[assembly: InternalsVisibleTo("Tests.Droid")]
[assembly: InternalsVisibleTo("Tests.Droid.net6")]
[assembly: InternalsVisibleTo("DynamicProxyGenAssembly2")]
#endif

namespace Cats.CertificateTransparency
{
    public static class Constants
    {
        public const int BitsInByte = 8;
        public const int BytesInLong = 8;

        public const int X509TbsSequenceIndex = 0;
        public const int TbsSpkiSequenceIndex = 6;

        public const int ExtensionsMaxValue = (1 << 16) - 1;
        public const int SignatureMaxValue = (1 << 16) - 1;
        public const int CertificateMaxValue = (1 << 24) - 1;

        public const int KeyIdNumOfBytes = 32;
        public const int TimestampNumOfBytes = 8;
        public const int VersionNumOfBytes = 1;
        public const int LogEntryTypeNumOfBytes = 2;
        
        public const string PreCertificateSigningOid = "1.3.6.1.4.1.11129.2.4.4";
        public const string PoisonOid = "1.3.6.1.4.1.11129.2.4.3";
        public const string SctCertificateOid = "1.3.6.1.4.1.11129.2.4.2";

        public const string X509AuthorityKeyIdentifier = "2.5.29.35";

        public const string GoogleLogListPublicKey = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsu0BHGnQ++W2CTdyZyxv\nHHRALOZPlnu/VMVgo2m+JZ8MNbAOH2cgXb8mvOj8flsX/qPMuKIaauO+PwROMjiq\nfUpcFm80Kl7i97ZQyBDYKm3MkEYYpGN+skAR2OebX9G2DfDqFY8+jUpOOWtBNr3L\nrmVcwx+FcFdMjGDlrZ5JRmoJ/SeGKiORkbbu9eY1Wd0uVhz/xI5bQb0OgII7hEj+\ni/IPbJqOHgB8xQ5zWAJJ0DmG+FM6o7gk403v6W3S8qRYiR84c50KppGwe4YqSMkF\nbLDleGQWLoaDSpEWtESisb4JiLaY4H+Kk0EyAhPSb+49JfUozYl+lf7iFN3qRq/S\nIXXTh6z0S7Qa8EYDhKGCrpI03/+qprwy+my6fpWHi6aUIk4holUCmWvFxZDfixox\nK0RlqbFDl2JXMBquwlQpm8u5wrsic1ksIv9z8x9zh4PJqNpCah0ciemI3YGRQqSe\n/mRRXBiSn9YQBUPcaeqCYan+snGADFwHuXCd9xIAdFBolw9R9HTedHGUfVXPJDiF\n4VusfX6BRR/qaadB+bqEArF/TzuDUr6FvOR4o8lUUxgLuZ/7HO+bHnaPFKYHHSm+\n+z1lVDhhYuSZ8ax3T0C3FZpb7HMjZtpEorSV5ElKJEJwrhrBCMOD8L01EoSPrGlS\n1w22i9uGHMn/uGQKo28u7AsCAwEAAQ==\n-----END PUBLIC KEY-----";
        public const string GoogleLogListUrl = "https://www.gstatic.com/ct/log_list/v3/";

        public const string BeginPublicKey = "-----BEGIN PUBLIC KEY-----";
        public const string EndPublicKey = "-----END PUBLIC KEY-----";

        public const string Sha256WithRsa = "SHA256withRSA";
        public const string Sha256WithEcdsa = "SHA256withECDSA";

        internal static int BytesToStoreValue(int value)
        {
            if (value < 0) throw new ArgumentOutOfRangeException(nameof(value), "Cannot be negative");

            var numBytes = 0;
            var local = value;

            while (local > 0)
            {
                local >>= Constants.BitsInByte;
                numBytes++;
            }

            return numBytes;
        }
    }
}
