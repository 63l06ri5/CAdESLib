using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using BcCms = Org.BouncyCastle.Asn1.Cms;

namespace CAdESLib.Document.Signature.Extensions
{
    /// <summary>
    /// This class holds the CAdES-C signature profile; it supports the inclusion of the mandatory unsigned
    /// id-aa-ets-certificateRefs and id-aa-ets-revocationRefs attributes as specified in ETSI TS 101 733 V1.8.1, clauses
    /// 6.2.1 & 6.2.2.
    /// </summary>

    public class CAdESProfileC : CAdESProfileT
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public ICertificateVerifier CertificateVerifier { get; set; }

        public override SignatureProfile SignatureProfile => SignatureProfile.C;

        /// <summary>
        /// Create a reference to a X509Certificate
        /// </summary>
        private static OtherCertID MakeOtherCertID(X509Certificate cert, DerObjectIdentifier hashAlg)
        {
            byte[] d = DigestUtilities.CalculateDigest(hashAlg, cert.GetEncoded());
            logger.Trace(new DerOctetString(d).ToString());
            OtherHash hash = new OtherHash(new OtherHashAlgAndValue(new AlgorithmIdentifier(hashAlg), d));
            OtherCertID othercertid = new OtherCertID(hash, new IssuerSerial(new GeneralNames(new GeneralName(cert.IssuerDN)), new DerInteger(cert.SerialNumber)));
            return othercertid;
        }

        /// <summary>
        /// Create a reference to a X509Crl
        /// </summary>
        private static CrlValidatedID MakeCrlValidatedID(X509Crl crl, DerObjectIdentifier hashAlg)
        {
            OtherHash hash = new OtherHash(new OtherHashAlgAndValue(new AlgorithmIdentifier(hashAlg), DigestUtilities.CalculateDigest(hashAlg, crl.GetEncoded())));
            CrlIdentifier crlid;
            DerObjectIdentifier crlExt = new DerObjectIdentifier("2.5.29.20");
            var crlNumberExtensionValue = crl.GetExtensionValue(crlExt);
            if (crlNumberExtensionValue != null)
            {
                var octetString = (DerOctetString) crlNumberExtensionValue;
                var octets = octetString.GetOctets();
                var integer = (DerInteger) new Asn1InputStream(octets).ReadObject();
                crlid = new CrlIdentifier(crl.IssuerDN, crl.ThisUpdate, integer.PositiveValue);
            }
            else
            {
                crlid = new CrlIdentifier(crl.IssuerDN, crl.ThisUpdate);
            }
            CrlValidatedID crlvid = new CrlValidatedID(hash, crlid);
            return crlvid;
        }

        /// <summary>
        /// Create a reference on a OcspResp
        /// </summary>
        private static OcspResponsesID MakeOcspResponsesID(BasicOcspResp ocspResp, DerObjectIdentifier hashAlg)
        {
            byte[] digestValue = DigestUtilities.CalculateDigest(hashAlg, ocspResp.GetEncoded());
            OtherHash hash = new OtherHash(new OtherHashAlgAndValue(new AlgorithmIdentifier(hashAlg), digestValue));
            // there is fuckup with DerGeneralizedTime, it loses milliseconds if DateTime is you param
            OcspResponsesID ocsprespid = new OcspResponsesID(OcspIdentifier.GetInstance(new DerSequence(ocspResp.ResponderId.ToAsn1Object(), new DerGeneralizedTime(ocspResp.ProducedAt.ToZuluString()))), hash);
            logger.Trace("Incorporate OcspResponseId[hash=" + Hex.ToHexString(digestValue) + ",producedAt=" + ocspResp.ProducedAt);
            return ocsprespid;
        }

        private (IDictionary, IValidationContext) ExtendUnsignedAttributes(IDictionary unsignedAttrs, X509Certificate signingCertificate, SignatureParameters parameters, DateTime signingTime, ICertificateSource optionalCertificateSource, IValidationContext validationContext)
        {
            var usedCerts = new List<CertificateAndContext>();
            validationContext = CertificateVerifier.ValidateCertificate(
                signingCertificate,
                signingTime,
                new CompositeCertificateSource(new ListCertificateSource(parameters.CertificateChain), optionalCertificateSource), usedCerts, inContext: validationContext);
            BcCms.Attribute timeStampAttr = new BcCms.AttributeTable(unsignedAttrs)[PkcsObjectIdentifiers.IdAASignatureTimeStampToken];
            if (timeStampAttr != null)
            {
                var value = timeStampAttr.AttrValues[0].GetDerEncoded();
                var timeStampToken = new TimeStampToken(new CmsSignedData(value));
                var token = new TimestampToken(timeStampToken, TimestampToken.TimestampType.SIGNATURE_TIMESTAMP);
                validationContext.ValidateTimestamp(token, optionalCertificateSource, null, null, usedCerts);

                var unAttr = timeStampToken.UnsignedAttributes?.ToDictionary() ?? new Dictionary<object, object>();
                SetRefs(
                    parameters.DigestAlgorithmOID,
                    unAttr,
                    token.GetSigner(),
                    validationContext.NeededCertificateTokens.Where(x => x.RootCause is TimestampToken && ((TimestampToken) x.RootCause).GetTimeStampType() == TimestampToken.TimestampType.SIGNATURE_TIMESTAMP).Select(x => x.GetCertificateAndContext()),
                    validationContext);

                if (new[] { SignatureProfile.XL, SignatureProfile.A }.Contains(SignatureProfile))
                {
                    SetValues(
                       unAttr,
                       validationContext.NeededCertificateTokens.Where(x => x.RootCause is TimestampToken && ((TimestampToken) x.RootCause).GetTimeStampType() == TimestampToken.TimestampType.SIGNATURE_TIMESTAMP).Select(x => x.GetCertificateAndContext()),
                       validationContext.NeededCRLTokens.Where(x => x.RootCause is TimestampToken && ((TimestampToken) x.RootCause).GetTimeStampType() == TimestampToken.TimestampType.SIGNATURE_TIMESTAMP),
                       validationContext.NeededOCSPRespTokens.Where(x => x.RootCause is TimestampToken && ((TimestampToken) x.RootCause).GetTimeStampType() == TimestampToken.TimestampType.SIGNATURE_TIMESTAMP));
                }

                var tstSignedData = timeStampToken.ToCmsSignedData();

                var e = tstSignedData.GetSignerInfos().GetSigners().GetEnumerator();
                e.MoveNext();
                var si = e.Current as SignerInformation;
                var newsi = SignerInformation.ReplaceUnsignedAttributes(si, new BcCms.AttributeTable(unAttr));

                CmsSignedData newTstSignedData = CmsSignedData.ReplaceSigners(tstSignedData, new SignerInformationStore(new[] { newsi }));

                unsignedAttrs[PkcsObjectIdentifiers.IdAASignatureTimeStampToken] = new BcCms.Attribute(PkcsObjectIdentifiers.IdAASignatureTimeStampToken, new DerSet(Asn1Object.FromByteArray(newTstSignedData.GetEncoded("DER"))));
            }

            SetRefs(parameters.DigestAlgorithmOID, unsignedAttrs, signingCertificate, validationContext.NeededCertificateTokens.Where(x => x.RootCause is X509Certificate).Select(x => x.GetCertificateAndContext()), validationContext);

            return (unsignedAttrs, validationContext);
        }

        private static void SetRefs(string digestOID, IDictionary unsignedAttrs, X509Certificate signingCertificate, IEnumerable<CertificateAndContext> certs, IValidationContext validationContext)
        {
            var digestId = new DerObjectIdentifier(digestOID);
            var completeCertificateRefs = new List<OtherCertID>();
            var completeRevocationRefs = new List<CrlOcspRef>();
            foreach (CertificateAndContext c in certs)
            {
                if (!c.Certificate.Equals(signingCertificate))
                {
                    completeCertificateRefs.Add(MakeOtherCertID(c.Certificate, digestId));
                }
                List<CrlValidatedID> crlListIdValues = new List<CrlValidatedID>();
                List<OcspResponsesID> ocspListIDValues = new List<OcspResponsesID>();
                foreach (X509Crl relatedcrl in validationContext.GetRelatedCRLs(c))
                {
                    crlListIdValues.Add(MakeCrlValidatedID(relatedcrl, digestId));
                }
                foreach (BasicOcspResp relatedocspresp in validationContext.GetRelatedOCSPResp(c))
                {
                    ocspListIDValues.Add(MakeOcspResponsesID(new BasicOcspResp(RefineOcspResp(relatedocspresp)), digestId));
                }
                completeRevocationRefs.Add(new CrlOcspRef(crlListIdValues.Count == 0 || ocspListIDValues.Count != 0 ? null : new CrlListID(crlListIdValues.ToArray()), ocspListIDValues.Count == 0 ? null : new OcspListID(ocspListIDValues.ToArray()), null));
            }
            unsignedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsCertificateRefs, new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsCertificateRefs, new DerSet(new DerSequence(completeCertificateRefs.ToArray()))));
            unsignedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsRevocationRefs, new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsRevocationRefs, new DerSet(new DerSequence(completeRevocationRefs.ToArray()))));
        }

        protected static void SetValues(IDictionary unsignedAttrs, IEnumerable<CertificateAndContext> certs, IEnumerable<CRLToken> crls, IEnumerable<OCSPRespToken> ocsps)
        {
            List<X509CertificateStructure> certificateValues = new List<X509CertificateStructure>();
            List<CertificateList> crlValues = new List<CertificateList>();
            List<BasicOcspResponse> ocspValues = new List<BasicOcspResponse>();
            foreach (CertificateAndContext c in certs)
            {
                certificateValues.Add(X509CertificateStructure.GetInstance(((Asn1Sequence) Asn1Object.FromByteArray(c.Certificate.GetEncoded()))));
            }
            foreach (var relatedcrl in crls)
            {
                crlValues.Add(CertificateList.GetInstance((Asn1Sequence) Asn1Object.FromByteArray(relatedcrl.GetX509crl().GetEncoded())));
            }
            foreach (var relatedocspresp in ocsps)
            {
                ocspValues.Add(RefineOcspResp(relatedocspresp.GetOcspResp()));
            }
            RevocationValues revocationValues = new RevocationValues(crlValues.Count == 0 ? null : crlValues.ToArray(), ocspValues.Count == 0 ? null : ocspValues.ToArray(), null);
            unsignedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsRevocationValues, new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsRevocationValues, new DerSet(revocationValues)));
            unsignedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsCertValues, new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsCertValues, new DerSet(new DerSequence(certificateValues.ToArray()))));
        }

        /// <summary>
        /// Remove certs field. Certificates are carried in a CertValues
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        private static BasicOcspResponse RefineOcspResp(BasicOcspResp input)
        {
            var original = (BasicOcspResponse.GetInstance((Asn1Sequence) Asn1Object.FromByteArray(input.GetEncoded())));
            return new BasicOcspResponse(original.TbsResponseData, original.SignatureAlgorithm, original.Signature, null);
        }

        protected internal override (SignerInformation, IValidationContext) ExtendCMSSignature(CmsSignedData signedData, SignerInformation si, SignatureParameters parameters, IDocument originalData)
        {
            if (si is null)
            {
                throw new ArgumentNullException(nameof(si));
            }

            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            var (newSi, validationContext) = base.ExtendCMSSignature(signedData, si, parameters, originalData);
            IDictionary unsignedAttrs = newSi.UnsignedAttributes.ToDictionary();
            CAdESSignature signature = new CAdESSignature(signedData, si.SignerID);
            (unsignedAttrs, validationContext) = ExtendUnsignedAttributes(
                unsignedAttrs,
                signature.SigningCertificate,
                parameters,
                signature.SigningTime?.Value ?? DateTime.Now,
                signature.CertificateSource,
                validationContext);
            return (SignerInformation.ReplaceUnsignedAttributes(newSi, new BcCms.AttributeTable(unsignedAttrs)), validationContext);
        }
    }
}
