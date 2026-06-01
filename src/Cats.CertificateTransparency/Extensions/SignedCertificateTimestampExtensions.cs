using Cats.CertificateTransparency.Models;
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cats.CertificateTransparency.Extensions
{
    internal static class SignedCertificateTimestampExtensions
    {
        internal static readonly Asn1Tag Version = new(TagClass.ContextSpecific, 0, isConstructed: true);
        internal static readonly Asn1Tag IssuerUniqueId = new(TagClass.ContextSpecific, 1);
        internal static readonly Asn1Tag SubjectUniqueId = new(TagClass.ContextSpecific, 2);
        internal static readonly Asn1Tag Extensions = new(TagClass.ContextSpecific, 3, isConstructed: true);

        internal static SctVerificationResult VerifySignature(this SignedCertificateTimestamp sct, ILog logServer, IList<X509Certificate2> chain)
        {
            if (logServer is null)
                return SctVerificationResult.FailedVerification(sct.TimestampUtc, logServer?.LogId, $"Invalid verification arguments, ${nameof(logServer)} is null");
            if (chain is null || chain.Count == 0)
                return SctVerificationResult.FailedVerification(sct.TimestampUtc, logServer?.LogId, $"Invalid verification arguments, ${nameof(chain)} is null or empty");
            if (!string.Equals(logServer.LogId, sct.LogIdBase64, StringComparison.Ordinal))
                return SctVerificationResult.FailedVerification(sct.TimestampUtc, logServer?.LogId, "Invalid verification arguments, Log Server and SCT LogId do not match");

            var nowUtc = DateTime.UtcNow;
            if (sct.TimestampUtc > nowUtc)
                return SctVerificationResult.FutureTimestamp(sct.TimestampUtc, logServer.LogId);

            if (logServer.ValidUntilUtc.HasValue && sct.TimestampUtc > logServer.ValidUntilUtc)
                return SctVerificationResult.LogServerUntrusted(sct.TimestampUtc, logServer.LogId);

            try
            {
                var leafCert = chain[0];
                var notPreCert = !leafCert.IsPreCertificate();
                var noEmbeddedSct = !leafCert.HasEmbeddedSct();
                if (notPreCert && noEmbeddedSct)
                {
                    // When verifying final cert without embedded SCTs, we don't need the issuer but can verify directly
                    var toVerify = sct.SerialiseSignedSctData(leafCert);
                    return sct.VerifySctSignatureOverBytes(logServer, toVerify);
                }

                if (chain.Count < 2)
                    return SctVerificationResult.FailedVerification(sct.TimestampUtc, logServer.LogId, "Chain with PreCertificate or Certificate must contain issuer");

                // PreCertificate or final certificate with embedded SCTs, we want the issuerInformation
                var issuerCert = chain[1];
                var isPreCertificateSigningCert = issuerCert.IsPreCertificateSigningCert();

                var issuerInformation = default(IssuerInformation);

                if (!isPreCertificateSigningCert)
                {
                    issuerInformation = issuerCert.IssuerInformation();
                }
                else if (chain.Count < 3)
                {
                    return SctVerificationResult.FailedVerification(sct.TimestampUtc, logServer.LogId, "Chain with PreCertificate signed by PreCertificate Signing Cert must contain issuer");
                }
                else
                {
                    issuerInformation = issuerCert.IssuerInformationFromPreCertificate(chain[2]);
                }

                return VerifySctOverPreCertificate(sct, logServer, leafCert, issuerInformation);
            }
            catch (Exception ex)
            {
                return SctVerificationResult.FailedWithException(sct.TimestampUtc, logServer.LogId, ex);
            }
        }

        internal static SctVerificationResult VerifySctOverPreCertificate(this SignedCertificateTimestamp sct, ILog logServer, X509Certificate2 certificate, IssuerInformation issuerInfo)
        {
            var preCertificateTbs = CreateTbsForVerification(certificate, issuerInfo);
            var toVerify = sct.SerialiseSignedSctDataForPreCertificate(preCertificateTbs, issuerInfo.KeyHash.Span);
            return sct.VerifySctSignatureOverBytes(logServer, toVerify);
        }

        private static byte[] CreateTbsForVerification(X509Certificate2 preCertificate, IssuerInformation issuerInformation)
        {
            var tbsBytes = preCertificate.GetTbsCertificate();
            var reader = new AsnReader(tbsBytes, AsnEncodingRules.DER);
            var tbsSequence = reader.ReadSequence();

            // --- Version [0] EXPLICIT ---
            var versionReader = tbsSequence.ReadSequence(Version);
            var version = versionReader.ReadInteger();
            if (version < 2)
                throw new InvalidOperationException("PreCertificate version must be 3 or higher!");

            // Preserve original DER where required
            var serialNumberRaw = tbsSequence.ReadEncodedValue();
            var signatureRaw = tbsSequence.ReadEncodedValue();

            // Issuer (optionally overridden)
            var originalIssuerRaw = tbsSequence.ReadEncodedValue();

            ReadOnlySpan<byte> issuerRaw = !string.IsNullOrEmpty(issuerInformation?.Name)
                ? new X500DistinguishedName(issuerInformation.Name).RawData
                : originalIssuerRaw.Span;

            var validityRaw = tbsSequence.ReadEncodedValue();
            var subjectRaw = tbsSequence.ReadEncodedValue();
            var spkiRaw = tbsSequence.ReadEncodedValue();

            // Optional unique IDs
            ReadOnlyMemory<byte>? issuerUniqueIdRaw = null;
            if (tbsSequence.HasData && HasTag(tbsSequence.PeekTag(), IssuerUniqueId))
                issuerUniqueIdRaw = tbsSequence.ReadEncodedValue();

            ReadOnlyMemory<byte>? subjectUniqueIdRaw = null;
            if (tbsSequence.HasData && HasTag(tbsSequence.PeekTag(), SubjectUniqueId))
                subjectUniqueIdRaw = tbsSequence.ReadEncodedValue();

            // --- Extensions ---
            var hasAki = false;
            var hasExtensions = tbsSequence.HasData && HasTag(tbsSequence.PeekTag(), Extensions);

            AsnReader extensionsSequenceReader = null;

            if (hasExtensions)
            {
                var explicitReader = tbsSequence.ReadSequence(Extensions);
                extensionsSequenceReader = explicitReader.ReadSequence();
            }

            // --- Build output ---
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();

            // Version (force v3)
            writer.PushSequence(Version);
            writer.WriteInteger(2);
            writer.PopSequence(Version);

            writer.WriteEncodedValue(serialNumberRaw.Span);
            writer.WriteEncodedValue(signatureRaw.Span);
            writer.WriteEncodedValue(issuerRaw);
            writer.WriteEncodedValue(validityRaw.Span);
            writer.WriteEncodedValue(subjectRaw.Span);
            writer.WriteEncodedValue(spkiRaw.Span);

            if (issuerUniqueIdRaw.HasValue)
                writer.WriteEncodedValue(issuerUniqueIdRaw.Value.Span);

            if (subjectUniqueIdRaw.HasValue)
                writer.WriteEncodedValue(subjectUniqueIdRaw.Value.Span);

            if (hasExtensions)
            {
                // [3] EXPLICIT
                writer.PushSequence(Extensions);
                // SEQUENCE OF Extension
                writer.PushSequence();

                while (extensionsSequenceReader.HasData)
                {
                    var extensionRaw = extensionsSequenceReader.ReadEncodedValue();
                    var extSeq = new AsnReader(extensionRaw, AsnEncodingRules.DER).ReadSequence();

                    var oid = extSeq.ReadObjectIdentifier();

                    var critical = false;
                    if (extSeq.HasData && extSeq.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                        critical = extSeq.ReadBoolean();

                    if (oid == Constants.X509AuthorityKeyIdentifier)
                        hasAki = true;

                    // Skip unwanted
                    if (oid == Constants.PoisonOid || oid == Constants.SctCertificateOid)
                        continue;

                    // Replace AKI inline (no intermediate encode)
                    if (oid == Constants.X509AuthorityKeyIdentifier && issuerInformation?.X509AuthorityKeyIdentifier is not null)
                    {
                        var newAki = issuerInformation.X509AuthorityKeyIdentifier;

                        writer.PushSequence();
                        writer.WriteObjectIdentifier(Constants.X509AuthorityKeyIdentifier);

                        if (newAki.Critical)
                            writer.WriteBoolean(true);

                        writer.WriteEncodedValue(newAki.RawData);
                        writer.PopSequence();
                    }
                    else
                    {
                        writer.WriteEncodedValue(extensionRaw.Span);
                    }
                }

                // SEQUENCE OF
                writer.PopSequence();
                writer.PopSequence(Extensions);
            }

            // Structural validation
            if (hasAki && issuerInformation is { IssuedByPreCertificateSigningCert: true, X509AuthorityKeyIdentifier: null })
            {
                throw new InvalidOperationException("PreCertificate was not signed by a PreCertificate signing cert");
            }

            writer.PopSequence();

            return writer.Encode();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool HasTag(Asn1Tag tag, Asn1Tag expected)
            => tag.TagClass == expected.TagClass && tag.TagValue == expected.TagValue;

        private static SctVerificationResult VerifySctSignatureOverBytes(this SignedCertificateTimestamp sct, ILog logServer, byte[] toVerify)
        {
            var (oid, sigAlg) = GetKeyAlgorithm(logServer.KeyBytes);

            var isValid = sigAlg switch
            {
                CtSignatureAlgorithm.Rsa => VerifyRsa(logServer.KeyBytes.Span, toVerify, sct.Signature.SignatureData.Span),
                CtSignatureAlgorithm.Ecdsa => VerifyEcdsa(logServer.KeyBytes.Span, toVerify, sct.Signature.SignatureData.Span),
                _ => throw new NotImplementedException($"Signature algorithm '{sigAlg}' not supported, with OID '{oid}'")
            };

            return isValid
                ? SctVerificationResult.Valid(sct.TimestampUtc, logServer.LogId)
                : SctVerificationResult.FailedVerification(sct.TimestampUtc, logServer.LogId);

            static bool VerifyRsa(ReadOnlySpan<byte> keyBytes, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
            {
                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(keyBytes, out _);
                return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }

            static bool VerifyEcdsa(ReadOnlySpan<byte> keyBytes, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(keyBytes, out _);
                return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            }
        }

        private static byte[] SerialiseSignedSctData(this SignedCertificateTimestamp sct, X509Certificate2 certificate)
        {
            using var ms = new MemoryStream();

            SerialiseCommonFields(ms, sct);

            ms.WriteLong(0, Constants.LogEntryTypeNumOfBytes); // X509 Entry
            ms.WriteVariableLength(certificate.RawData, Constants.CertificateMaxValue);
            ms.WriteVariableLength(sct.Extensions.Span, Constants.ExtensionsMaxValue);

            return ms.ToArray();
        }

        private static byte[] SerialiseSignedSctDataForPreCertificate(this SignedCertificateTimestamp sct, ReadOnlySpan<byte> preCert, ReadOnlySpan<byte> issuerKeyHash)
        {
            using var ms = new MemoryStream();

            SerialiseCommonFields(ms, sct);

            ms.WriteLong(1, Constants.LogEntryTypeNumOfBytes); // PerCert Entry
            ms.Write(issuerKeyHash);
            ms.WriteVariableLength(preCert, Constants.CertificateMaxValue);
            ms.WriteVariableLength(sct.Extensions.Span, Constants.ExtensionsMaxValue);

            return ms.ToArray();
        }

        private static void SerialiseCommonFields(Stream stream, SignedCertificateTimestamp sct)
        {
            if (sct.SctVersion != SctVersion.V1) throw new InvalidOperationException("Can only serialise SCT v1!");

            stream.WriteLong((long)sct.SctVersion, Constants.VersionNumOfBytes);
            stream.WriteLong(0, 1); // Certificate Timestamp
            stream.WriteLong(sct.TimestampMs, Constants.TimestampNumOfBytes);
        }

        private static (string oid, CtSignatureAlgorithm sigAlg) GetKeyAlgorithm(ReadOnlyMemory<byte> keyBytes)
        {
            try
            {
                var reader = new AsnReader(keyBytes, AsnEncodingRules.DER);
                var outerSequence = reader.ReadSequence();
                var algorithmIdentifier = outerSequence.ReadSequence();
                var oid = algorithmIdentifier.ReadObjectIdentifier();

                return oid switch
                {
                    Constants.PkcsOidRsaEncryption => (oid, CtSignatureAlgorithm.Rsa),
                    Constants.X9OidIdECPublicKey => (oid, CtSignatureAlgorithm.Ecdsa),
                    _ => (oid, CtSignatureAlgorithm.Unknown)
                };
            }
            catch (AsnContentException)
            {
                return (string.Empty, CtSignatureAlgorithm.Unknown);
            }
        }
    }
}
