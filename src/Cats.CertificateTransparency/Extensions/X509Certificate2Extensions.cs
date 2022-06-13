using Cats.CertificateTransparency.Models;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Tls;
using System;
using System.Collections.Generic;
using System.IO;
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
            var x509Cert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(certificate);
            var spki = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(x509Cert.GetPublicKey());
            var spkiBytes = spki.GetDerEncoded();
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
        {
            var asn1Obj = Asn1Object.FromByteArray(certificate.GetTbsCertificateRaw());
            var tbsCert = Org.BouncyCastle.Asn1.X509.TbsCertificateStructure.GetInstance(asn1Obj);

            var issuerExtensions = tbsCert?.Extensions;
            var x509AuthorityKeyIdentifier = issuerExtensions?.GetExtension(new DerObjectIdentifier(Constants.X509AuthorityKeyIdentifier));

            return new IssuerInformation()
            {
                Name = tbsCert.Issuer,
                KeyHash = preCertificate.PublicKeyHash(),
                X509AuthorityKeyIdentifier = x509AuthorityKeyIdentifier,
                IssuedByPreCertificateSigningCert = true
            };
        }

        internal static byte[] GetTbsCertificateRaw(this X509Certificate2 certificate)
        {
            var x509Cert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(certificate);
            return x509Cert.GetTbsCertificate();
        }

        internal static X509Extension GetExtension(this X509Certificate2 certificate, string oid)
            => (certificate.Extensions ?? new X509ExtensionCollection())
                .OfType<X509Extension>()
                .FirstOrDefault(i => i.Oid.Value.Equals(oid));

        internal static List<SignedCertificateTimestamp> GetSignedCertificateTimestamps(this X509Certificate2 certificate)
        {
            // https://letsencrypt.org/2018/04/04/sct-encoding.html

            var result = new List<SignedCertificateTimestamp>();

#if DEBUG
            var sctExtension = certificate is MoqX509Certificate2 moqCert
                ? moqCert.Extensions
                         .OfType<X509Extension>()
                         .FirstOrDefault(i => i.Oid.Value.Equals(Constants.SctCertificateOid))
                : certificate.GetExtension(Constants.SctCertificateOid);
#else
            var sctExtension = certificate.GetExtension(Constants.SctCertificateOid);
#endif
            if (sctExtension?.RawData?.Any() == true)
            {
                var octets = Asn1OctetString.GetInstance(sctExtension.RawData).GetOctets();
                // could be a nested OCTET string, check leading byte
                var derOctetString = octets[0] == 0x04
                    ? Asn1Object.FromByteArray(octets) as DerOctetString
                    : Asn1Object.FromByteArray(sctExtension.RawData) as DerOctetString;

                using var inputStream = derOctetString.GetOctetStream();

                TlsUtilities.ReadUint16(inputStream);

                while (inputStream.Length - inputStream.Position > 2)
                {
                    var sctBytes = TlsUtilities.ReadOpaque16(inputStream);

                    using var sctStream = new MemoryStream(sctBytes);

                    var version = (SctVersion)sctStream.ReadByte();
                    if (version != SctVersion.V1)
                        throw new NotSupportedException(UnknowError(nameof(SctVersion), version));

                    var keyId = new byte[Constants.KeyIdLength];
                    sctStream.Read(keyId, 0, keyId.Length);

                    var timestamp = sctStream.ReadLong(Constants.TimestampLength);

                    var extensions = sctStream.ReadVariableLength(Constants.ExtensionsMaxLength);

                    var hashAlgo = (CtHashAlgorithm)sctStream.ReadByte();
                    if (!Enum.IsDefined(typeof(CtHashAlgorithm), hashAlgo))
                        throw new NotSupportedException(UnknowError(nameof(CtHashAlgorithm), hashAlgo));

                    var signatureAlgo = (CtSignatureAlgorithm)sctStream.ReadByte();
                    if (!Enum.IsDefined(typeof(CtSignatureAlgorithm), signatureAlgo))
                        throw new NotSupportedException(UnknowError(nameof(CtSignatureAlgorithm), signatureAlgo));

                    var signature = sctStream.ReadVariableLength(Constants.SignatureMaxLength);

                    var digitallySigned = new DigitallySigned()
                    {
                        Hash = hashAlgo,
                        Signature = signatureAlgo,
                        SignatureData = signature
                    };

                    var sct = new SignedCertificateTimestamp()
                    {
                        SctVersion = version,
                        LogId = keyId,
                        TimestampMs = timestamp,
                        Extensions = extensions,
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
