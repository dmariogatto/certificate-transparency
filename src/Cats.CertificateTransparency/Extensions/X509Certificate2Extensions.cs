using Cats.CertificateTransparency.Models;
using Org.BouncyCastle.Asn1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DigitallySigned = Cats.CertificateTransparency.Models.DigitallySigned;

namespace Cats.CertificateTransparency.Extensions
{
    internal static class X509Certificate2Extensions
    {
        internal static bool IsPreCertificateSigningCert(this X509Certificate2 certificate)
            => certificate.GetExtension(Constants.PreCertificateSigningOid) is not null;

        internal static bool IsPreCertificate(this X509Certificate2 certificate)
            => certificate.GetExtension(Constants.PoisonOid)?.Critical ?? false;

        internal static bool HasEmbeddedSct(this X509Certificate2 certificate)
            => certificate.GetExtension(Constants.SctCertificateOid) is not null;

        internal static byte[] PublicKeyHash(this X509Certificate2 certificate)
        {
#if NET6_0_OR_GREATER
            var spkiBytes = certificate.PublicKey.ExportSubjectPublicKeyInfo();
#else
            var asn1Obj = certificate.GetTbsCertificateAsn1Object();
            var spkiBytes = asn1Obj is Asn1Sequence asn1Seq && Constants.TbsSpkiSequenceIndex < asn1Seq.Count
                ? asn1Seq[Constants.TbsSpkiSequenceIndex].GetDerEncoded()
                : throw new InvalidOperationException("Cannot get SPKI from TBS certificate");
#endif

            using var sha2 = SHA256.Create();
            var digest = sha2.ComputeHash(spkiBytes);

            return digest;
        }

        internal static IssuerInformation IssuerInformation(this X509Certificate2 certificate)
            => new IssuerInformation()
            {
                KeyHash = certificate.PublicKeyHash(),
                IssuedByPreCertificateSigningCert = false
            };

        internal static IssuerInformation IssuerInformationFromPreCertificate(this X509Certificate2 certificate, X509Certificate2 preCertificate)
            => new IssuerInformation()
            {
                Name = certificate.IssuerName.Name,
                KeyHash = preCertificate.PublicKeyHash(),
                X509AuthorityKeyIdentifier = certificate.GetExtension(Constants.X509AuthorityKeyIdentifier),
                IssuedByPreCertificateSigningCert = true
            };

        internal static Asn1Object GetTbsCertificateAsn1Object(this X509Certificate2 certificate)
        {
            var asn1Tbs = default(Asn1Object);
            using var asn1Stream = new Asn1InputStream(certificate.RawData);

            if (asn1Stream.ReadObject() is Asn1Object asn1Obj &&
                Asn1Sequence.GetInstance(asn1Obj) is Asn1Sequence asn1Seq &&
                Constants.X509TbsSequenceIndex < asn1Seq.Count)
            {
                asn1Tbs = asn1Seq[Constants.X509TbsSequenceIndex].ToAsn1Object();
            }

            return asn1Tbs;
        }

        internal static X509Extension GetExtension(this X509Certificate2 certificate, string oid)
            => certificate.Extensions
                ?.OfType<X509Extension>()
                ?.FirstOrDefault(i => i.Oid.Value.Equals(oid, StringComparison.Ordinal));

        internal static List<SignedCertificateTimestamp> GetSignedCertificateTimestamps(this X509Certificate2 certificate)
        {
            // https://letsencrypt.org/2018/04/04/sct-encoding.html

            var result = new List<SignedCertificateTimestamp>();

#if DEBUG
            var sctExtension = certificate is MoqX509Certificate2 moqCert
                ? moqCert.Extensions
                         .OfType<X509Extension>()
                         .FirstOrDefault(i => i.Oid.Value.Equals(Constants.SctCertificateOid, StringComparison.Ordinal))
                : certificate.GetExtension(Constants.SctCertificateOid);
#else
            var sctExtension = certificate.GetExtension(Constants.SctCertificateOid);
#endif

            var sctRawData = sctExtension?.RawData;
            if (sctRawData?.Length > 1 && sctRawData[0] == 0x04)
            {
                var numOfLengthBytes = 0;
                var encodingLengthByte = sctRawData[1];

                // Leading bit is 1, (i.e. long format)
                if ((encodingLengthByte & 0x80) != 0)
                {
                    numOfLengthBytes = encodingLengthByte & 0x7F;
                }

                var span = sctRawData.AsSpan(numOfLengthBytes + 2);
                var position = 2;

                while (span.Length - position > 2)
                {
                    var highOrderByte = span[position++];
                    var lowOrderByte = span[position++];
                    var vectorLengthUint16 = lowOrderByte + (highOrderByte << 8);

                    var sctSpan = span.Slice(position, vectorLengthUint16);
                    position += vectorLengthUint16;

                    var sctPosition = 0;

                    var version = (SctVersion)sctSpan[sctPosition++];
                    if (version != SctVersion.V1)
                        throw new NotSupportedException(UnknowError(nameof(SctVersion), version));

                    var keyId = sctSpan.Slice(sctPosition, Constants.KeyIdNumOfBytes);
                    sctPosition += Constants.KeyIdNumOfBytes;

                    var timestamp = sctSpan.ReadLong(Constants.TimestampNumOfBytes, ref sctPosition);
                    var extensions = sctSpan.ReadVariableLength(Constants.ExtensionsMaxValue, ref sctPosition);

                    var hashAlgo = (CtHashAlgorithm)sctSpan[sctPosition++];
                    switch (hashAlgo)
                    {
                        case CtHashAlgorithm.None:
                        case CtHashAlgorithm.Md5:
                        case CtHashAlgorithm.Sha1:
                        case CtHashAlgorithm.Sha224:
                        case CtHashAlgorithm.Sha256:
                        case CtHashAlgorithm.Sha384:
                        case CtHashAlgorithm.Sha512:
                            break;
                        default:
                            throw new NotSupportedException(UnknowError(nameof(CtHashAlgorithm), hashAlgo));
                    }

                    var signatureAlgo = (CtSignatureAlgorithm)sctSpan[sctPosition++];
                    switch (signatureAlgo)
                    {
                        case CtSignatureAlgorithm.Anonymous:
                        case CtSignatureAlgorithm.Rsa:
                        case CtSignatureAlgorithm.Dsa:
                        case CtSignatureAlgorithm.Ecdsa:
                            break;
                        default:
                            throw new NotSupportedException(UnknowError(nameof(CtSignatureAlgorithm), signatureAlgo));
                    }

                    var signature = sctSpan.ReadVariableLength(Constants.SignatureMaxValue, ref sctPosition);

                    var digitallySigned = new DigitallySigned()
                    {
                        Hash = hashAlgo,
                        Signature = signatureAlgo,
                        SignatureData = signature.ToArray()
                    };

                    var sct = new SignedCertificateTimestamp()
                    {
                        SctVersion = version,
                        LogId = keyId.ToArray(),
                        TimestampMs = timestamp,
                        Extensions = extensions.ToArray(),
                        Signature = digitallySigned
                    };

                    result.Add(sct);
                }
            }

            return result;
        }

        private static string UnknowError(string propName, object value) => $"Unknown {propName}: {value ?? "null"}";
    }
}
