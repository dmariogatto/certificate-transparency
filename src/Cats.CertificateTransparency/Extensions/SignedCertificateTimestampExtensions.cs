using Cats.CertificateTransparency.Models;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;

namespace Cats.CertificateTransparency.Extensions
{
    internal static class SignedCertificateTimestampExtensions
    {
        internal static SctVerificationResult VerifySignature(this SignedCertificateTimestamp sct, Log logServer, IList<X509Certificate2> chain)
        {
            if (logServer == null || sct == null || chain?.Any() != true || logServer.LogId != sct.LogIdBase64)
                return SctVerificationResult.FailedVerification("Invalid verification arguments");

            var nowUtc = DateTime.UtcNow;
            if (sct.TimestampUtc > nowUtc)
                return SctVerificationResult.FutureTimestamp(sct.TimestampUtc, nowUtc);

            if (logServer.ValidUntilUtc.HasValue && sct.TimestampUtc > logServer.ValidUntilUtc)
                return SctVerificationResult.LogServerUntrusted(sct.TimestampUtc, logServer.ValidUntilUtc.Value);

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
                    return SctVerificationResult.FailedVerification("Chain with PreCertificate or Certificate must contain issuer");

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
                    return SctVerificationResult.FailedVerification("Chain with PreCertificate signed by PreCertificate Signing Cert must contain issuer");
                }
                else
                {
                    issuerInformation = issuerCert.IssuerInformationFromPreCertificate(chain[2]);
                }

                return VerifySctOverPreCertificate(sct, logServer, leafCert, issuerInformation);
            }
            catch (Exception ex)
            {
                return SctVerificationResult.FailedWithException(ex);
            }
        }

        internal static SctVerificationResult VerifySctOverPreCertificate(this SignedCertificateTimestamp sct, Log logServer, X509Certificate2 certificate, IssuerInformation issuerInfo)
        {
            var preCertificateTbs = CreateTbsForVerification(certificate, issuerInfo);
            var toVerify = sct.SerialiseSignedSctDataForPreCertificate(preCertificateTbs.GetEncoded(), issuerInfo.KeyHash);
            return sct.VerifySctSignatureOverBytes(logServer, toVerify);
        }

        private static TbsCertificateStructure CreateTbsForVerification(X509Certificate2 preCertificate, IssuerInformation issuerInformation)
        {
            if (preCertificate.Version < 3) throw new InvalidOperationException("PreCertificate version must be 3 or higher!");

            var preCertParsed = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(preCertificate.GetRawCertData());

            var asn1Obj = Asn1Object.FromByteArray(preCertParsed.GetTbsCertificate());
            var tbsCert = TbsCertificateStructure.GetInstance(asn1Obj);
            var hasX509AuthorityKeyIdentifier = tbsCert.Extensions.GetExtension(new DerObjectIdentifier(Constants.X509AuthorityKeyIdentifier)) != null;

            if (hasX509AuthorityKeyIdentifier &&
                issuerInformation.IssuedByPreCertificateSigningCert &&
                issuerInformation.X509AuthorityKeyIdentifier == null)
            {
                throw new InvalidOperationException("PreCertificate was not signed by a PreCertificate signing cert");
            }

            var orderedExtensions = GetExtensionsWithoutPoisonAndSct(tbsCert.Extensions, issuerInformation.X509AuthorityKeyIdentifier);

            var generator = new V3TbsCertificateGenerator();

            generator.SetSerialNumber(tbsCert.SerialNumber);
            generator.SetSignature(tbsCert.Signature);
            generator.SetIssuer(issuerInformation.Name ?? tbsCert.Issuer);
            generator.SetStartDate(tbsCert.StartDate);
            generator.SetEndDate(tbsCert.EndDate);
            generator.SetSubject(tbsCert.Subject);
            generator.SetSubjectPublicKeyInfo(tbsCert.SubjectPublicKeyInfo);
            generator.SetIssuerUniqueID(tbsCert.IssuerUniqueID);
            generator.SetSubjectUniqueID(tbsCert.SubjectUniqueID);

            var extensionsGenerator = new X509ExtensionsGenerator();
            foreach (var e in orderedExtensions)
                extensionsGenerator.AddExtension(e.Key, e.Value.IsCritical, e.Value.GetParsedValue());

            generator.SetExtensions(extensionsGenerator.Generate());

            return generator.GenerateTbsCertificate();
        }

        private static Dictionary<DerObjectIdentifier, X509Extension> GetExtensionsWithoutPoisonAndSct(X509Extensions extensions, X509Extension replacementX509Authority)
        {
            var result = new Dictionary<DerObjectIdentifier, X509Extension>();

            foreach (DerObjectIdentifier oid in extensions.GetExtensionOids())
            {
                if (oid.Id != Constants.PoisonOid && oid.Id != Constants.SctCertificateOid)
                {
                    if (oid.Id == Constants.X509AuthorityKeyIdentifier && replacementX509Authority != null)
                    {
                        result.Add(oid, replacementX509Authority);
                    }
                    else
                    {
                        result.Add(oid, extensions.GetExtension(oid));
                    }
                }
            }

            return result;
        }

        private static SctVerificationResult VerifySctSignatureOverBytes(this SignedCertificateTimestamp sct, Log logServer, byte[] toVerify)
        {
            var (oid, sigAlg) = GetKeyAlgorithm(logServer.KeyBytes);
            var signer = sigAlg switch
            {
                CtSignatureAlgorithm.Ecdsa => SignerUtilities.GetSigner(Constants.Sha256WithEcdsa),
                CtSignatureAlgorithm.Rsa => SignerUtilities.GetSigner(Constants.Sha256WithRsa),
                _ => throw new NotImplementedException($"Signature algothrim '{sigAlg}' not supported, with OID '{oid}'"),
            };

            var pubKey = PublicKeyFactory.CreateKey(logServer.KeyBytes);
            signer.Init(false, pubKey);
            signer.BlockUpdate(toVerify, 0, toVerify.Length);
            var isValid = signer.VerifySignature(sct.Signature.SignatureData);

            return isValid
                ? SctVerificationResult.Valid()
                : SctVerificationResult.FailedVerification();
        }

        private static byte[] SerialiseSignedSctData(this SignedCertificateTimestamp sct, X509Certificate2 certificate)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            SerialiseCommonFields(bw, sct);

            bw.WriteLong(0, Constants.LogEntryTypeLength); // X509 Entry
            bw.WriteVariableLength(certificate.RawData, Constants.CertificateMaxLength);
            bw.WriteVariableLength(sct.Extensions, Constants.ExtensionsMaxLength);

            return ms.ToArray();
        }

        private static byte[] SerialiseSignedSctDataForPreCertificate(this SignedCertificateTimestamp sct, byte[] preCert, byte[] issuerKeyHash)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            SerialiseCommonFields(bw, sct);

            bw.WriteLong(1, Constants.LogEntryTypeLength); // PerCert Entry
            bw.Write(issuerKeyHash);
            bw.WriteVariableLength(preCert, Constants.CertificateMaxLength);
            bw.WriteVariableLength(sct.Extensions, Constants.ExtensionsMaxLength);

            return ms.ToArray();
        }

        private static void SerialiseCommonFields(BinaryWriter bw, SignedCertificateTimestamp sct)
        {
            if (sct.SctVersion != SctVersion.V1) throw new InvalidOperationException("Can only serialise SCT v1!");

            bw.WriteLong((long)sct.SctVersion, Constants.VersionLength);
            bw.WriteLong(0, 1); // Certificate Timestamp
            bw.WriteLong(sct.TimestampMs, Constants.TimestampLength);
        }

        private static (string oid, CtSignatureAlgorithm sigAlg) GetKeyAlgorithm(byte[] keyBytes)
        {
            var seq = Asn1Sequence.GetInstance(keyBytes);

            if (seq.Count > 0 && seq[0] is DerSequence derSeq &&
                derSeq.Count > 0 && derSeq[0] is DerObjectIdentifier oi)
            {
                if (oi.Equals(PkcsObjectIdentifiers.RsaEncryption))
                    return (oi.Id, CtSignatureAlgorithm.Rsa);
                if (oi.Equals(X9ObjectIdentifiers.IdECPublicKey))
                    return (oi.Id, CtSignatureAlgorithm.Ecdsa);

                return (oi.Id, CtSignatureAlgorithm.Unknown);
            }

            return (string.Empty, CtSignatureAlgorithm.Unknown);
        }
    }
}
