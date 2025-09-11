using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using BcCms = Org.BouncyCastle.Asn1.Cms;
using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using CAdESLib.Service;
using NLog;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using PkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System;

namespace CAdESLib.Document.Signature.Extensions
{
    public abstract class CAdESSignatureExtension : ISignatureExtension
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        protected const string CannotParseCMSDataMessage = "Cannot parse CMS data";
        private const string EmptyTimestampMessage = "The TimeStampToken returned for the signature time stamp was empty.";

        public virtual SignatureProfile SignatureProfile => throw new NotImplementedException();

        protected ICryptographicProvider CryptographicProvider { get; }

        protected ICurrentTimeGetter CurrentTimeGetter { get; }

        protected CAdESSignatureExtension(ICryptographicProvider cryptographicProvider, ICurrentTimeGetter currentTimeGetter)
        {
            this.CryptographicProvider = cryptographicProvider;
            this.CurrentTimeGetter = currentTimeGetter;
        }

        public virtual (IDocument, ICollection<IValidationContext?>?) ExtendSignatures(
            IDocument document,
            DateTime endDate,
            IDocument? originalData,
            SignatureParameters parameters)
        {
            if (document is null)
            {
                throw new ArgumentNullException(nameof(document));
            }

            try
            {
                CmsSignedData signedData = new CmsSignedData(document.OpenStream());
                SignerInformationStore signerStore = signedData.GetSignerInfos();
                var siArray = new List<SignerInfo>();
                var validationContexts = new List<IValidationContext?>();

                foreach (var si in signerStore.GetSigners().Cast<SignerInformation>())
                {
                    var (signerInformation, validationContext) = ExtendCMSSignature(signedData, endDate, si, parameters, originalData);
                    siArray.Add(signerInformation);
                    validationContexts.Add(validationContext);
                }

                CmsSignedData extended = ReplaceSigners(signedData, siArray);
                return (new InMemoryDocument(extended.GetEncoded()), validationContexts);
            }
            catch (CmsException)
            {
                throw new IOException(CannotParseCMSDataMessage);
            }
        }

        protected internal abstract (SignerInfo, IValidationContext?) ExtendCMSSignature(
                CmsSignedData signedData,
                DateTime endDate,
                SignerInformation si,
                SignatureParameters parameters,
                IDocument? originalData);

        /// <summary>
        /// Computes an attribute containing a time-stamp token of the provided data, from the provided TSA using the
        /// provided.
        /// </summary>
        /// <remarks>
        /// Computes an attribute containing a time-stamp token of the provided data, from the provided TSA using the
        /// provided. The hashing is performed by the method using the specified algorithm and a BouncyCastle provider.
        /// </remarks>
        protected internal virtual BcCms.Attribute GetTimeStampAttribute(DerObjectIdentifier oid, ITspSource tsa, byte[] messageImprint, bool needToWaitTsTime = true)
        {
            if (tsa is null)
            {
                throw new ArgumentNullException(nameof(tsa));
            }

            string? digest;
            string? algorithmOid;
            if (tsa is ITSAClient)
            {
                digest = tsa.GetDigestAlgorithm();
                if (digest is null)
                {
                    throw new ArgumentNullException(nameof(digest));
                }

                algorithmOid = tsa.TsaDigestAlgorithmOID;
                if (algorithmOid is null)
                {
                    throw new ArgumentNullException(nameof(algorithmOid));
                }
            }
            else
            {
                digest = DigestAlgorithm.SHA1.Name;
                algorithmOid = DigestAlgorithm.SHA1.OID;
            }

            byte[] toTimeStamp = this.CryptographicProvider.CalculateDigest(digest, messageImprint);

            var tsresp = tsa.GetTimeStampResponse(algorithmOid, toTimeStamp);
            var tstoken = tsresp?.TimeStampToken;
            if (tstoken == null)
            {
                throw new ArgumentNullException(EmptyTimestampMessage);
            }
            if (needToWaitTsTime)
            {
                var utcNow = this.CurrentTimeGetter.CurrentUtcTime;
                var genTime = tstoken.TimeStampInfo.GenTime.ToUniversalTime();
                var datediff = genTime.Subtract(utcNow);
                if (datediff.TotalMilliseconds > 0)
                {
                    // TODO: timeout should be config parameter
                    if (datediff.TotalMilliseconds < 60000)
                    {
                        Thread.Sleep((int)Math.Ceiling(datediff.TotalMilliseconds));
                    }
                    else
                    {
                        var message = $"Timestamp date is far in the future. GenTime = {genTime}, CheckTime = {utcNow} ";
                        nloglogger.Error(message);
                        throw new Exception(message);
                    }
                }
            }

            BcCms.Attribute signatureTimeStamp = new BcCms.Attribute(oid, new DerSet(Asn1Object.FromByteArray(tstoken.GetEncoded())));
            return signatureTimeStamp;
        }

        public static CmsSignedData ReplaceSigners(CmsSignedData oldSignedData, IList<SignerInfo> signerInfoStore)
        {
            Asn1EncodableVector asn1EncodableVector = new Asn1EncodableVector();
            Asn1EncodableVector asn1EncodableVector2 = new Asn1EncodableVector();
            foreach (var signerInfo in signerInfoStore)
            {
                asn1EncodableVector.Add(FixAlgID(signerInfo.DigestAlgorithm));
                asn1EncodableVector2.Add(signerInfo);
            }

            Asn1Set asn1Set = new DerSet(asn1EncodableVector);
            Asn1Set element = new DerSet(asn1EncodableVector2);
            Asn1Sequence asn1Sequence = (Asn1Sequence)SignedData.GetInstance(oldSignedData.ContentInfo.Content).ToAsn1Object();
            asn1EncodableVector2 = new Asn1EncodableVector(asn1Sequence[0], asn1Set);
            for (int i = 2; i != asn1Sequence.Count - 1; i++)
            {
                asn1EncodableVector2.Add(asn1Sequence[i]);
            }

            asn1EncodableVector2.Add(element);
            var signedData = SignedData.GetInstance(new BerSequence(asn1EncodableVector2));
            var cmsSignedData = new CmsSignedData(new ContentInfo(oldSignedData.ContentInfo.ContentType, signedData));
            return cmsSignedData;
        }

        public static AlgorithmIdentifier FixAlgID(
                  AlgorithmIdentifier algId)
        {
            if (algId.Parameters == null)
                return new AlgorithmIdentifier(algId.Algorithm, DerNull.Instance);

            return algId;
        }

        public static SignerInfo ReplaceUnsignedAttributes(SignerInformation signerInformation, OrderedAttributeTable unsignedAttributesTable)
        {
            SignerInfo signerInfo = signerInformation.ToSignerInfo();
            return ReplaceUnsignedAttributes(signerInfo, unsignedAttributesTable);
        }

        public static SignerInfo ReplaceUnsignedAttributes(SignerInfo signerInfo, OrderedAttributeTable unsignedAttributesTable)
        {
            Asn1Set? unauthenticatedAttributes = null;
            if (unsignedAttributesTable?.GetVector() is Asn1EncodableVector vector && vector.Count > 0)
            {
                unauthenticatedAttributes = new BerSet(unsignedAttributesTable.GetVector());
            }

            return new SignerInfo(signerInfo.SignerID, signerInfo.DigestAlgorithm, signerInfo.AuthenticatedAttributes, signerInfo.DigestEncryptionAlgorithm, signerInfo.EncryptedDigest, unauthenticatedAttributes);
        }
        protected CmsSignedData EnrichTimestampsWithRefsAndValues(
                CmsSignedData tstSignedData,
                DateTime endDate,
                IValidationContext validationContext,
                ICertificateSource optionalCertificateSource,
                ICrlSource optionalCrlSource,
                IOcspSource optionalOcspSource,
                string digestAlgorithmOID,
                bool createNewAttributeIfExist,
                bool replaceAttributes)
        {
            var tsSignerInformation = tstSignedData.GetSignerInfos().GetSigners().OfType<SignerInformation>().FirstOrDefault();
            if (tsSignerInformation is null)
            {
                throw new ArgumentNullException(nameof(tsSignerInformation));
            }
            var timeStampToken = new TimeStampToken(tstSignedData);
            var token = new TimestampToken(timeStampToken);
            validationContext.ValidateTimestamp(token, endDate, optionalCertificateSource, optionalCrlSource, optionalOcspSource);
            var signer = token.GetSigner();
            if (signer is null)
            {
                throw new ArgumentNullException(nameof(signer));
            }

            var revocationInfo = validationContext.RevocationInfoDict[token.GetHashCode()]!;

            var timestampDate = token.GetTimeStamp().TimeStampInfo.GenTime;

            var tsUnsignedAttrsItems = new OrderedAttributeTable(tsSignerInformation.ToSignerInfo().UnauthenticatedAttributes);
            nloglogger.Trace("Refs for timestamp " + timestampDate + ", signer=" + signer.SubjectDN);
            var signerChain = revocationInfo.GetCertsChain(
                    signer,
                    timestampDate,
                    endDate);
            SetRefs(
                this.CryptographicProvider,
                revocationInfo,
                timestampDate,
                endDate,
                digestAlgorithmOID,
                tsUnsignedAttrsItems,
                signer,
                signerChain,
                validationContext,
                createNewAttributeIfExist,
                replaceAttributes);

            if (new[] { SignatureProfile.XL, SignatureProfile.A }.Contains(SignatureProfile))
            {
                SetValues(
                   revocationInfo,
                   timestampDate,
                   endDate,
                   tsUnsignedAttrsItems,
                   signer,
                   signerChain,
                   validationContext,
                   createNewAttributeIfExist,
                   replaceAttributes
                   );
            }

            var newsi = ReplaceUnsignedAttributes(tsSignerInformation, tsUnsignedAttrsItems);

            return ReplaceSigners(tstSignedData, new[] { newsi });
        }
        protected static void SetRefs(
                ICryptographicProvider cryptographicProvider,
                RevocationInfo revocationInfo,
                DateTime startDate,
                DateTime endDate,
                string digestOID,
                OrderedAttributeTable unsignedAttrsItems,
                X509Certificate signingCertificate,
                IEnumerable<CertificateAndContext> certs,
                IValidationContext validationContext,
                // TODO: delete
                bool createNewAttributeIfExist,
                bool replaceAttributes)
        {
            var certRefsExist = unsignedAttrsItems[PkcsObjectIdentifiers.IdAAEtsCertificateRefs] is not null;
            var revsRefsExist = unsignedAttrsItems[PkcsObjectIdentifiers.IdAAEtsRevocationRefs] is not null;
            if (!replaceAttributes && (certRefsExist || revsRefsExist))
            {
                nloglogger.Trace("Refs not be set");
                return;
            }

            var digestId = new DerObjectIdentifier(digestOID);
            var completeCertificateRefs = new List<OtherCertID>();
            var completeRevocationRefs = new List<CrlOcspRef>();

            var arrCerts = new List<CertificateAndContext>();
            if (signingCertificate != null)
            {
                arrCerts.Add(certs.First(x => x.Certificate.Equals(signingCertificate)));
                arrCerts.AddRange(certs.Where(x => !x.Certificate.Equals(signingCertificate)));
            }
            else
            {
                arrCerts = certs.ToList();
            }

            foreach (CertificateAndContext c in arrCerts)
            {
                if (!c.Certificate.Equals(signingCertificate))
                {
                    completeCertificateRefs.Add(MakeOtherCertID(cryptographicProvider, c.Certificate, digestId));
                }
                List<CrlValidatedID> crlListIdValues = new List<CrlValidatedID>();
                List<OcspResponsesID> ocspListIDValues = new List<OcspResponsesID>();
                foreach (X509Crl relatedcrl in revocationInfo.GetRelatedCRLs(c, startDate, endDate))
                {
                    crlListIdValues.Add(MakeCrlValidatedID(cryptographicProvider, relatedcrl, digestId));
                }
                foreach (BasicOcspResp relatedocspresp in revocationInfo.GetRelatedOCSPResp(c, startDate, endDate))
                {
                    ocspListIDValues.Add(MakeOcspResponsesID(cryptographicProvider, new BasicOcspResp(relatedocspresp.RefineOcspResp()), digestId));
                }
                completeRevocationRefs.Add(
                        new CrlOcspRef(crlListIdValues.Count == 0 || ocspListIDValues.Count != 0 ?
                            null : new CrlListID(crlListIdValues.ToArray()),
                        ocspListIDValues.Count == 0 ?
                            null : new OcspListID(ocspListIDValues.ToArray()),
                            null));
            }


            if (completeCertificateRefs.Count != 0 && (replaceAttributes || !certRefsExist))
            {
                if (certRefsExist)
                {
                    unsignedAttrsItems.ReplaceAttribute(
                                unsignedAttrsItems[PkcsObjectIdentifiers.IdAAEtsCertificateRefs]!.First(),
                                new DerSet(new DerSequence(completeCertificateRefs.ToArray())));
                }
                else
                {
                    unsignedAttrsItems.AddAttribute(
                            new Attribute(
                                PkcsObjectIdentifiers.IdAAEtsCertificateRefs,
                                new DerSet(new DerSequence(completeCertificateRefs.ToArray()))));
                }
            }

            if (completeRevocationRefs.Count != 0 && (replaceAttributes || !revsRefsExist))
            {
                if (revsRefsExist)
                {
                    unsignedAttrsItems.ReplaceAttribute(
                                unsignedAttrsItems[PkcsObjectIdentifiers.IdAAEtsRevocationRefs]!.First(),
                                new DerSet(new DerSequence(completeRevocationRefs.ToArray())));
                }
                else
                {
                    unsignedAttrsItems.AddAttribute(
                            new Attribute(
                                PkcsObjectIdentifiers.IdAAEtsRevocationRefs,
                                new DerSet(new DerSequence(completeRevocationRefs.ToArray()))));
                }
            }
        }

        protected static void SetValues(
                RevocationInfo revocationInfo,
                DateTime startDate,
                DateTime endDate,
                OrderedAttributeTable unsignedAttrsItems,
                X509Certificate? signingCertificate,
                IEnumerable<CertificateAndContext> certs,
                IValidationContext validationContext,
                bool createNewAttributeIfExist,
                bool replaceAttributes)
        {
            var certValsExist = unsignedAttrsItems[PkcsObjectIdentifiers.IdAAEtsCertValues] is not null;
            var revsValsExist = unsignedAttrsItems[PkcsObjectIdentifiers.IdAAEtsRevocationValues] is not null;
            if (!replaceAttributes && (certValsExist || revsValsExist))
            {
                nloglogger.Trace("Values not be set");
                return;
            }

            List<X509CertificateStructure> certificateValues = new List<X509CertificateStructure>();
            List<CertificateList> crlValues = new List<CertificateList>();
            List<BasicOcspResponse> ocspValues = new List<BasicOcspResponse>();

            var arrCerts = new List<CertificateAndContext>();
            if (signingCertificate != null)
            {
                arrCerts.Add(certs.First(x => x.Certificate.Equals(signingCertificate)));
                arrCerts.AddRange(certs.Where(x => !x.Certificate.Equals(signingCertificate)));
            }
            else
            {
                arrCerts = certs.ToList();
            }

            foreach (CertificateAndContext c in arrCerts)
            {
                certificateValues.Add(X509CertificateStructure.GetInstance(((Asn1Sequence)Asn1Object.FromByteArray(c.Certificate.GetEncoded()))));


                foreach (var relatedcrl in revocationInfo.GetRelatedCRLs(c, startDate, endDate))
                {
                    crlValues.Add(CertificateList.GetInstance((Asn1Sequence)Asn1Object.FromByteArray(relatedcrl.GetEncoded())));
                }
                foreach (var relatedocspresp in revocationInfo.GetRelatedOCSPResp(c, startDate, endDate))
                {
                    ocspValues.Add(relatedocspresp.RefineOcspResp());
                }
            }

            RevocationValues revocationValues =
                new RevocationValues(
                        crlValues.Count == 0 ? null : crlValues.Distinct().ToArray(),
                        ocspValues.Count == 0 ? null : ocspValues.Distinct().ToArray(),
                        null);
            if (certificateValues.Count != 0 && (replaceAttributes || !certValsExist))
            {

                if (certValsExist)
                {
                    unsignedAttrsItems.ReplaceAttribute(
                                unsignedAttrsItems[PkcsObjectIdentifiers.IdAAEtsCertValues]!.First(),
                                new DerSet(new DerSequence(certificateValues.ToArray())));
                }
                else
                {
                    unsignedAttrsItems.AddAttribute(
                            new Attribute(
                                PkcsObjectIdentifiers.IdAAEtsCertValues,
                                new DerSet(new DerSequence(certificateValues.ToArray()))));
                }
            }
            if (revocationValues is not null && (replaceAttributes || !revsValsExist))
            {
                if (revsValsExist)
                {
                    unsignedAttrsItems.ReplaceAttribute(
                                unsignedAttrsItems[PkcsObjectIdentifiers.IdAAEtsRevocationValues]!.First(),
                                new DerSet(revocationValues));
                }
                else
                {
                    unsignedAttrsItems.AddAttribute(
                            new Attribute(
                                PkcsObjectIdentifiers.IdAAEtsRevocationValues,
                                new DerSet(revocationValues)));
                }
            }
        }

        /// <summary>
        /// Create a reference to a X509Certificate
        /// </summary>
        protected static OtherCertID MakeOtherCertID(ICryptographicProvider cryptographicProvider, X509Certificate cert, DerObjectIdentifier hashAlg)
        {
            byte[] d = cryptographicProvider.CalculateDigest(hashAlg.Id, cert.GetEncoded());
            OtherHash hash = new OtherHash(new OtherHashAlgAndValue(new AlgorithmIdentifier(hashAlg), d));
            OtherCertID othercertid = new OtherCertID(hash, new IssuerSerial(new GeneralNames(new GeneralName(cert.IssuerDN)), new DerInteger(cert.SerialNumber)));
            return othercertid;
        }

        /// <summary>
        /// Create a reference to a X509Crl
        /// </summary>
        protected static CrlValidatedID MakeCrlValidatedID(ICryptographicProvider cryptographicProvider, X509Crl crl, DerObjectIdentifier hashAlg)
        {
            OtherHash hash = new OtherHash(new OtherHashAlgAndValue(new AlgorithmIdentifier(hashAlg), cryptographicProvider.CalculateDigest(hashAlg.Id, crl.GetEncoded())));
            CrlIdentifier crlid;
            DerObjectIdentifier crlExt = new DerObjectIdentifier("2.5.29.20");
            var crlNumberExtensionValue = crl.GetExtensionValue(crlExt);
            if (crlNumberExtensionValue != null)
            {
                var octetString = (DerOctetString)crlNumberExtensionValue;
                var octets = octetString.GetOctets();
                var integer = (DerInteger)new Asn1InputStream(octets).ReadObject();
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
        protected static OcspResponsesID MakeOcspResponsesID(ICryptographicProvider cryptographicProvider, BasicOcspResp ocspResp, DerObjectIdentifier hashAlg)
        {
            byte[] digestValue = cryptographicProvider.CalculateDigest(hashAlg.Id, ocspResp.GetEncoded());
            OtherHash hash = new OtherHash(new OtherHashAlgAndValue(new AlgorithmIdentifier(hashAlg), digestValue));
            // there is fuckup with DerGeneralizedTime, it loses milliseconds if DateTime is you param
            OcspResponsesID ocsprespid = new OcspResponsesID(OcspIdentifier.GetInstance(new DerSequence(ocspResp.ResponderId.ToAsn1Object(), new DerGeneralizedTime(ocspResp.ProducedAt.ToZuluString()))), hash);
            nloglogger.Trace("Incorporate OcspResponseId[hash=" + Hex.ToHexString(digestValue) + ",producedAt=" + ocspResp.ProducedAt);
            return ocsprespid;
        }
    }
}
