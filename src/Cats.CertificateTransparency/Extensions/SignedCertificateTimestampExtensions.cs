using Cats.CertificateTransparency.Models;
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cats.CertificateTransparency.Extensions
{
    internal static class SignedCertificateTimestampExtensions
    {
        internal static SctVerificationResult VerifySignature(this SignedCertificateTimestamp sct, ILog logServer, IList<X509Certificate2> chain)
        {
            if (logServer is null || sct is null || chain?.Any() != true || logServer.LogId != sct.LogIdBase64)
                return SctVerificationResult.FailedVerification(sct.TimestampUtc, logServer?.LogId, "Invalid verification arguments");

            var nowUtc = DateTime.UtcNow;
            if (sct.TimestampUtc > nowUtc)
                return SctVerificationResult.FutureTimestamp(sct.TimestampUtc, logServer.LogId);

            if (logServer.ValidUntilUtc.HasValue && sct.TimestampUtc > logServer.ValidUntilUtc)
                return SctVerificationResult.LogServerUntrusted(sct.TimestampUtc, logServer.LogId);

            try
            {
                var leafCert = chain.First();
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
            var toVerify = sct.SerialiseSignedSctDataForPreCertificate(preCertificateTbs, issuerInfo.KeyHash);
            return sct.VerifySctSignatureOverBytes(logServer, toVerify);
        }

        private static byte[] CreateTbsForVerification(X509Certificate2 preCertificate, IssuerInformation issuerInformation)
        {
            // Extract original TBS Certificate bytes from the X509Certificate2
            var tbsBytes = preCertificate.GetTbsCertificate();
            var reader = new AsnReader(tbsBytes, AsnEncodingRules.DER);
            // Outer TBSCertificate SEQUENCE
            var tbsSequence = reader.ReadSequence();

            // Parse and validate Version [0] EXPLICIT
            var versionReader = tbsSequence.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
            var version = versionReader.ReadInteger();
            // Version 3 is encoded as integer 2 (0-based)
            if (version < 2)
            {
                throw new InvalidOperationException("PreCertificate version must be 3 or higher!");
            }

            // Keep immutable elements raw to preserve exact DER-encoding signatures
            var serialNumberRaw = tbsSequence.ReadEncodedValue();
            var signatureRaw = tbsSequence.ReadEncodedValue();

            // Process Issuer Name (Update if a custom issuer name is specified)
            var originalIssuerRaw = tbsSequence.ReadEncodedValue();
            ReadOnlySpan<byte> issuerRaw = !string.IsNullOrEmpty(issuerInformation?.Name)
                ? new X500DistinguishedName(issuerInformation.Name).RawData
                : originalIssuerRaw.Span;

            // Read standard validity, subject, and PKI
            var validityRaw = tbsSequence.ReadEncodedValue();
            var subjectRaw = tbsSequence.ReadEncodedValue();
            var spkiRaw = tbsSequence.ReadEncodedValue();

            // Capture Optional Unique IDs if present
            ReadOnlyMemory<byte>? issuerUniqueIdRaw = null;
            if (tbsSequence.HasData && tbsSequence.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                issuerUniqueIdRaw = tbsSequence.ReadEncodedValue();
            }

            ReadOnlyMemory<byte>? subjectUniqueIdRaw = null;
            if (tbsSequence.HasData && tbsSequence.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                subjectUniqueIdRaw = tbsSequence.ReadEncodedValue();
            }

            // Parse, filter, and modify Extensions [3] EXPLICIT OPTIONAL
            var hasX509AuthorityKeyIdentifier = false;
            byte[] modifiedExtensionsRaw = null;

            if (tbsSequence.HasData && tbsSequence.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true)))
            {
                var explicitTagReader = tbsSequence.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true));
                // Inner SEQUENCE OF Extension
                var extensionsSequenceReader = explicitTagReader.ReadSequence();

                var writerExtensions = new AsnWriter(AsnEncodingRules.DER);
                // Start inner collection sequence
                writerExtensions.PushSequence();

                while (extensionsSequenceReader.HasData)
                {
                    var extensionRaw = extensionsSequenceReader.ReadEncodedValue();

                    // Temporary reader to inspect the OID and Criticality of the current extension
                    var tempReader = new AsnReader(extensionRaw, AsnEncodingRules.DER);
                    var extSequence = tempReader.ReadSequence();
                    var oid = extSequence.ReadObjectIdentifier();

                    var critical = false;
                    if (extSequence.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                    {
                        critical = extSequence.ReadBoolean();
                    }

                    if (oid == Constants.X509AuthorityKeyIdentifier)
                    {
                        hasX509AuthorityKeyIdentifier = true;
                    }

                    // Skip Poison and SCT extensions
                    if (oid == Constants.PoisonOid || oid == Constants.SctCertificateOid)
                    {
                        continue;
                    }

                    // Replace Authority Key Identifier if requested
                    if (oid == Constants.X509AuthorityKeyIdentifier && issuerInformation?.X509AuthorityKeyIdentifier is not null)
                    {
                        var newAki = issuerInformation.X509AuthorityKeyIdentifier;
                        var akiWriter = new AsnWriter(AsnEncodingRules.DER);
                        akiWriter.PushSequence();
                        akiWriter.WriteObjectIdentifier(Constants.X509AuthorityKeyIdentifier);
                        if (newAki.Critical)
                        {
                            akiWriter.WriteBoolean(true);
                        }
                        akiWriter.WriteEncodedValue(newAki.RawData);
                        akiWriter.PopSequence();

                        writerExtensions.WriteEncodedValue(akiWriter.Encode());
                    }
                    else
                    {
                        // Retain original extension bytes exactly as encoded
                        writerExtensions.WriteEncodedValue(extensionRaw.Span);
                    }
                }

                // End inner collection sequence
                writerExtensions.PopSequence();

                // Wrap everything inside the [3] EXPLICIT context tag
                var explicitTagWriter = new AsnWriter(AsnEncodingRules.DER);
                var extensionsTag = new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true);

                explicitTagWriter.PushSequence(extensionsTag);
                explicitTagWriter.WriteEncodedValue(writerExtensions.Encode());
                explicitTagWriter.PopSequence(extensionsTag);

                modifiedExtensionsRaw = explicitTagWriter.Encode();
            }

            // Perform structural pre-cert validation
            if (hasX509AuthorityKeyIdentifier &&
                issuerInformation is { IssuedByPreCertificateSigningCert: true, X509AuthorityKeyIdentifier: null })
            {
                throw new InvalidOperationException("PreCertificate was not signed by a PreCertificate signing cert");
            }

            // Reconstruct the finalised TBSCertificate Sequence
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();

            // Version [0] EXPLICIT
            var versionTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
            writer.PushSequence(versionTag);
            writer.WriteInteger(2);
            writer.PopSequence(versionTag);

            writer.WriteEncodedValue(serialNumberRaw.Span);
            writer.WriteEncodedValue(signatureRaw.Span);
            writer.WriteEncodedValue(issuerRaw);
            writer.WriteEncodedValue(validityRaw.Span);
            writer.WriteEncodedValue(subjectRaw.Span);
            writer.WriteEncodedValue(spkiRaw.Span);

            if (issuerUniqueIdRaw.HasValue)
            {
                writer.WriteEncodedValue(issuerUniqueIdRaw.Value.Span);
            }
            if (subjectUniqueIdRaw.HasValue)
            {
                writer.WriteEncodedValue(subjectUniqueIdRaw.Value.Span);
            }
            if (modifiedExtensionsRaw != null)
            {
                writer.WriteEncodedValue(modifiedExtensionsRaw);
            }

            // End TBSCertificate SEQUENCE
            writer.PopSequence();
            return writer.Encode();
        }

        private static SctVerificationResult VerifySctSignatureOverBytes(this SignedCertificateTimestamp sct, ILog logServer, byte[] toVerify)
        {
            var (oid, sigAlg) = GetKeyAlgorithm(logServer.KeyBytes);

            var isValid = sigAlg switch
            {
                CtSignatureAlgorithm.Rsa => VerifyRsa(logServer.KeyBytes, toVerify, sct.Signature.SignatureData),
                CtSignatureAlgorithm.Ecdsa => VerifyEcdsa(logServer.KeyBytes, toVerify, sct.Signature.SignatureData),
                _ => throw new NotImplementedException($"Signature algorithm '{sigAlg}' not supported, with OID '{oid}'")
            };

            return isValid
                ? SctVerificationResult.Valid(sct.TimestampUtc, logServer.LogId)
                : SctVerificationResult.FailedVerification(sct.TimestampUtc, logServer.LogId);

            static bool VerifyRsa(byte[] keyBytes, byte[] data, byte[] signature)
            {
                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(keyBytes, out _);
                return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }

            static bool VerifyEcdsa(byte[] keyBytes, byte[] data, byte[] signature)
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
            ms.WriteVariableLength(sct.Extensions, Constants.ExtensionsMaxValue);

            return ms.ToArray();
        }

        private static byte[] SerialiseSignedSctDataForPreCertificate(this SignedCertificateTimestamp sct, byte[] preCert, byte[] issuerKeyHash)
        {
            using var ms = new MemoryStream();

            SerialiseCommonFields(ms, sct);

            ms.WriteLong(1, Constants.LogEntryTypeNumOfBytes); // PerCert Entry
            ms.Write(issuerKeyHash);
            ms.WriteVariableLength(preCert, Constants.CertificateMaxValue);
            ms.WriteVariableLength(sct.Extensions, Constants.ExtensionsMaxValue);

            return ms.ToArray();
        }

        private static void SerialiseCommonFields(Stream stream, SignedCertificateTimestamp sct)
        {
            if (sct.SctVersion != SctVersion.V1) throw new InvalidOperationException("Can only serialise SCT v1!");

            stream.WriteLong((long)sct.SctVersion, Constants.VersionNumOfBytes);
            stream.WriteLong(0, 1); // Certificate Timestamp
            stream.WriteLong(sct.TimestampMs, Constants.TimestampNumOfBytes);
        }

        private static (string oid, CtSignatureAlgorithm sigAlg) GetKeyAlgorithm(byte[] keyBytes)
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
