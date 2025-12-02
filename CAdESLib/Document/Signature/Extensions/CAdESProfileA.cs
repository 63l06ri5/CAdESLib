using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using CAdESLib.Service;
using NLog;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using Newtonsoft.Json;
using Org.BouncyCastle.Tsp;

namespace CAdESLib.Document.Signature.Extensions
{
    /// <summary>
    /// This class holds the CAdES-A signature profiles; it supports the later, over time _extension_ of a signature with
    /// id-aa-ets-archiveTimestampV2 attributes as defined in ETSI TS 101 733 V1.8.1, clause 6.4.1.
    /// </summary>
    /// <remarks>
    /// This class holds the CAdES-A signature profiles; it supports the later, over time _extension_ of a signature with
    /// id-aa-ets-archiveTimestampV2 attributes as defined in ETSI TS 101 733 V1.8.1, clause 6.4.1.
    /// "If the certificate-values and revocation-values attributes are not present in the CAdES-BES or CAdES-EPES, then they
    /// shall be added to the electronic signature prior to computing the archive time-stamp token." is the reason we extend
    /// from the XL profile.
    /// </remarks>
    public class CAdESProfileA : CAdESSignatureExtension
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        // archive-time-stamp-v3 
        public static readonly DerObjectIdentifier id_aa_ets_archiveTimestamp_v3 = new DerObjectIdentifier("0.4.0.1733.2.4");

        // Not used
        // id-aa-ATSHashIndex OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0) electronicsignature-standard(1733) attributes(2) 5 } 
        // public static readonly DerObjectIdentifier id_aa_ATSHashIndex = new DerObjectIdentifier("0.4.0.1733.2.5");

        // id-aa-ATSHashIndex-v3 OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0) cades(19122) attributes(1) 5 } 
        public static readonly DerObjectIdentifier id_aa_ATSHashIndex_v3 = new DerObjectIdentifier("0.4.0.19122.1.5");

        public override SignatureProfile SignatureProfile => SignatureProfile.A;

        /// <returns>
        /// the TSA used for the signature-time-stamp attribute
        /// </returns>
        public virtual ITspSource SignatureTsa { get; set; }

        private ISignedDocumentValidator Validator;

        private CAdESProfileXL Xlt1Extension;

        public CAdESProfileA(
                ITspSource signatureTsa,
                ISignedDocumentValidator signedDocumentValidator,
                CAdESProfileXL xlt1Extension,
                ICryptographicProvider cryptographicProvider,
                ICurrentTimeGetter currentTimeGetter) : base(cryptographicProvider, currentTimeGetter)
        {
            this.SignatureTsa = signatureTsa;
            this.Validator = signedDocumentValidator;
            this.Xlt1Extension = xlt1Extension;
        }

        protected internal override (SignerInfo, IValidationContext?) ExtendCMSSignature(
                CmsSignedData signedData,
                DateTime endDate,
                SignerInformation si,
                SignatureParameters parameters,
                IDocument? originalData)
        {
            throw new NotImplementedException();
        }

        protected internal (CmsSignedData cmsSignedData1, SignerInfo, IValidationContext) ExtendCMSSignature(
                CmsSignedData cmsSignedData, SignerInformation si, SignatureParameters parameters, IDocument? originalDocument, IValidationContext validationContext)
        {
            // - add not existed certs and revocs to signedData.certificates and signedData.crls
            // - and add digestAlgorithmOID to signedData.DigestAlgorithms if there is not present already
            var signatureCertificateSource = new CAdESCertificateSource(cmsSignedData, si.SignerID, false);
            var signatureCertificates = cmsSignedData.GetCertificates("Collection").GetMatches(null).Cast<X509Certificate>().ToArray();
            // var needForValidationCerts = validationContext.RevocationInfoDict.Values
            //     .SelectMany(x => x.NeededCertificateTokens.Select(y => y.Certificate)).Distinct();
            var toAddCerts = new List<X509Certificate>();
            toAddCerts.AddRange(signatureCertificates);
            // toAddCerts.AddRange(needForValidationCerts.Except(signatureCertificates).ToList());

            // We don't support ocsps as others in crls
            var signatureCrlSource = new CAdESCRLSource(cmsSignedData, si.SignerID);
            var signatureCrls = cmsSignedData.GetCrls("Collection").GetMatches(null).Cast<X509Crl>();
            var toAddCRLs = new List<X509Crl>();
            toAddCRLs.AddRange(signatureCrls);
            // var needForValidationCRLs = validationContext.RevocationInfoDict.Values
            //     .SelectMany(x => x.NeededCRLTokens.Select(y => y.Crl)).Distinct();
            // var toAddCRLs = needForValidationCRLs.Except(signatureCrls);

            var signatureOcspSource = new CAdESOCSPSource(cmsSignedData, si.SignerID);

            cmsSignedData = ReplaceCertificatesAndCrlsAndAddDigestAlgorithm(cmsSignedData, toAddCerts, toAddCRLs, basicOcspResps: null, parameters.DigestAlgorithmOID);
            // - calculate hashes for ats-hash-index

            var signerInfo = si.ToSignerInfo();
            var atsHashIndex = CalculateAtsHashIndex(this.CryptographicProvider, cmsSignedData, parameters.DigestAlgorithmOID, signerInfo.UnauthenticatedAttributes);

            // - calculate hash for cades-a
            // - generate archive timestamp
            var toTimestamp = GetDataForStamping(this.CryptographicProvider, cmsSignedData, si, atsHashIndex, originalDocument, parameters.DigestAlgorithmOID);
            var archiveTimeStamp = GetTimeStampAttribute(id_aa_ets_archiveTimestamp_v3, SignatureTsa, toTimestamp);

            // - add ats-hash-index to archive timestamp
            {
                var timestamp = new CmsSignedData(archiveTimeStamp.AttrValues[0].GetDerEncoded());
                // timestamp = EnrichTimestampsWithRefsAndValues(
                //     timestamp,
                //     this.CurrentTimeGetter.CurrentUtcTime,
                //     validationContext,
                //     signatureCertificateSource,
                //     signatureCrlSource,
                //     signatureOcspSource,
                //     parameters.DigestAlgorithmOID,
                //     parameters.CreateNewAttributeIfExist,
                //     true
                //     );

                var timestampSignerInformation = timestamp.GetSignerInfos().GetSigners().OfType<SignerInformation>().First();
                var tsSignedInfo = timestampSignerInformation.ToSignerInfo();
                var timestampUnsignedAttrTable = new OrderedAttributeTable(timestampSignerInformation.ToSignerInfo().UnauthenticatedAttributes);
                var atsHashIndexAttr = new Attribute(id_aa_ATSHashIndex_v3, new BerSet(Asn1Object.FromByteArray(atsHashIndex.GetEncoded())));
                timestampUnsignedAttrTable.AddAttribute(atsHashIndexAttr);
                var timestampNewsi = ReplaceUnsignedAttributes(timestampSignerInformation, timestampUnsignedAttrTable);
                var newSignerStore = new List<SignerInfo>() { timestampNewsi };
                CmsSignedData extended = ReplaceSigners(timestamp, newSignerStore);
                archiveTimeStamp = new Attribute(id_aa_ets_archiveTimestamp_v3, CreateBerSetFromList(new List<object>() { extended.ContentInfo }));
            }

            var unsignedAttrVector = new OrderedAttributeTable(si.ToSignerInfo().UnauthenticatedAttributes);
            unsignedAttrVector.AddAttribute(archiveTimeStamp);
            var newsi = ReplaceUnsignedAttributes(si, unsignedAttrVector);
            return (cmsSignedData, newsi, validationContext);
        }

        // 1. The SignedData.encapContentInfo.eContentType. 
        // 2. The octets representing the hash of the signed data. The hash is computed on the same content that was used 
        // for computing the hash value that is encapsulated within the message-digest signed attribute of the 
        // CAdES signature being archive-time-stamped. The hash algorithm applied shall be the same as the hash 
        // algorithm used for computing the archive time-stamp’s message imprint. The inclusion of the hash algorithm 
        // in the SignedData.digestAlgorithms set is recommended. 
        // 3. Fields version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, and 
        // signature within the SignedData.signerInfos’s item corresponding to the signature being archive 
        // time-stamped, in their order of appearance. 
        // 4. A single instance of ATSHashIndex type (created as specified in clause 6.4.2).
        public static byte[] GetDataForStamping(ICryptographicProvider cryptographicProvider, CmsSignedData cmsSignedData, SignerInformation si, Asn1Encodable atsHashIndex, IDocument? originalDocument, string digestAlgorithOID)
        {
            using var toTimestamp = new MemoryStream();
            var contentInfo = cmsSignedData.ContentInfo;
            var signedData = SignedData.GetInstance(contentInfo.Content);
            // 1.
            toTimestamp.Write(signedData.EncapContentInfo.ContentType.GetDerEncoded());

            // 2.
            if (signedData.EncapContentInfo.Content == null)
            {
                if (originalDocument != null)
                {
                    var hash = cryptographicProvider.CalculateDigest(digestAlgorithOID, Streams.ReadAll(originalDocument.OpenStream()));
                    toTimestamp.Write(hash);
                }
                else
                {
                    throw new Exception("Signature is detached and no original data provided.");
                }
            }
            else
            {
                var content = signedData.EncapContentInfo;
                DerOctetString octet = (DerOctetString)content.Content;
                var hash = cryptographicProvider.CalculateDigest(digestAlgorithOID, octet.GetOctets());
                toTimestamp.Write(hash);
            }

            // 3.
            var signerInfo = si.ToSignerInfo();
            var asn1SignerInfo = (DerSequence)signerInfo.ToAsn1Object();
            for (var i = 0; i < 6; i++)
            {
                Asn1Encodable item = asn1SignerInfo[i];
                toTimestamp.Write(item!.GetDerEncoded());
            }

            // 4.
            toTimestamp.Write(atsHashIndex.GetDerEncoded());

            return toTimestamp.ToArray();

        }

        //  ATSHashIndex ::= SEQUENCE { 
        //         hashIndAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256}, 
        //         certificatesHashIndex    SEQUENCE OF OCTET STRING, 
        //         crlsHashIndex            SEQUENCE OF OCTET STRING, 
        //         unsignedAttrsHashIndex   SEQUENCE OF OCTET STRING 
        //     }
        public static DerSequence CalculateAtsHashIndex(
                ICryptographicProvider cryptographicProvider,
                CmsSignedData cmsSignedData,
                string digestAlgorithOID,
                Asn1Set unauthenticatedAttributes)
        {
            var digestAlgorithm = new AlgorithmIdentifier(new DerObjectIdentifier(digestAlgorithOID), DerNull.Instance);
            var signedData = SignedData.GetInstance(cmsSignedData.ContentInfo.Content);

            return CalculateAtsHashIndexInternal(cryptographicProvider, digestAlgorithm, signedData.Certificates, signedData.CRLs, unauthenticatedAttributes);
        }

        private static DerSequence CalculateAtsHashIndexInternal(
                ICryptographicProvider cryptographicProvider,
                AlgorithmIdentifier digestAlgorithm,
                Asn1Set? certificates,
                Asn1Set? crls,
                Asn1Set? unauthenticatedAttributes)
        {
            var digestAlgorithmOID = digestAlgorithm.Algorithm.Id;
            var certsHashes = new List<byte[]>();
            var crlsHashes = new List<byte[]>();
            var unsignedAttributesHashes = new List<byte[]>();
            if (certificates != null)
            {
                foreach (Asn1Encodable? item in certificates)
                {
                    var messageImprint = item!.GetDerEncoded();
                    certsHashes.Add(cryptographicProvider.CalculateDigest(digestAlgorithmOID, messageImprint));
                }
            }
            if (crls != null)
            {
                foreach (Asn1Encodable? item in crls)
                {
                    var messageImprint = item!.GetDerEncoded();
                    crlsHashes.Add(cryptographicProvider.CalculateDigest(digestAlgorithmOID, messageImprint));
                }
            }
            if (unauthenticatedAttributes != null)
            {
                foreach (var attrObj in unauthenticatedAttributes)
                {

                    var item = Attribute.GetInstance(attrObj);
                    using var toHash = new MemoryStream();
                    var attrType = item.AttrType;
                    foreach (Asn1Encodable? attrValue in item.AttrValues)
                    {
                        toHash.Write(attrType.GetDerEncoded());
                        toHash.Write(attrValue!.GetDerEncoded());
                    }

                    unsignedAttributesHashes.Add(cryptographicProvider.CalculateDigest(digestAlgorithmOID, toHash.ToArray()));
                }
            }

            return new DerSequence(
                       digestAlgorithm,
                       new DerSequence(CreateEncodableVector(certsHashes.Select(x => new DerOctetString(x)).ToArray())),
                       new DerSequence(CreateEncodableVector(crlsHashes.Select(x => new DerOctetString(x)).ToArray())),
                       new DerSequence(CreateEncodableVector(unsignedAttributesHashes.Select(x => new DerOctetString(x)).ToArray()))
            );
        }

        // SignedData ::= SEQUENCE {
        //         version CMSVersion,
        //         digestAlgorithms DigestAlgorithmIdentifiers,
        //         encapContentInfo EncapsulatedContentInfo,
        //         certificates [0] IMPLICIT CertificateSet OPTIONAL,
        //         crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        //         signerInfos SignerInfos }

        // RevocationInfoChoice ::= CHOICE {
        //      crl        CertificateList,
        //      other  [1] IMPLICIT OtherRevocationInfoFormat }

        // OtherRevocationInfoFormat ::= SEQUENCE {
        //      otherRevInfoFormat  OBJECT IDENTIFIER,
        //      otherRevInfo        ANY DEFINED BY otherRevInfoFormat }

        public static OcspResponse ConvertBasicOcspResp(BasicOcspResp resp)
        {
            Asn1OctetString octs;

            try
            {
                octs = new DerOctetString(resp.GetEncoded());
            }
            catch (Exception e)
            {
                throw new OcspException("can't encode object.", e);
            }

            ResponseBytes rb = new ResponseBytes(OcspObjectIdentifiers.PkixOcspBasic, octs);

            return new OcspResponse(new OcspResponseStatus(OcspResponseStatus.Successful), rb);
        }

        public static IEnumerable<object>? GetOtherRevocationInfoFromOcsps(IEnumerable<BasicOcspResp>? basicResps)
        {
            var result = basicResps?
                .Select(ConvertBasicOcspResp)
                .Select(
                    resp => new DerTaggedObject(false, 1, new OtherRevocationInfoFormat(CmsObjectIdentifiers.id_ri_ocsp_response, resp)));
            return result;
        }

        public static IList<object> GetCertificateStructureFromCertificates(IList<X509Certificate> certs)
        {
            try
            {
                var result = new List<object>();

                foreach (X509Certificate c in certs)
                {
                    result.Add(X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(c.GetEncoded())));
                }

                return result;
            }
            catch (CertificateEncodingException e)
            {
                throw new CmsException("error encoding certs", e);
            }
            catch (Exception e)
            {
                throw new CmsException("error processing certs", e);
            }
        }

        public static List<object> GetCertificateListFromCrls(IEnumerable<X509Crl> crls)
        {
            try
            {
                var result = new List<object>();

                foreach (X509Crl c in crls)
                {
                    result.Add(CertificateList.GetInstance(Asn1Object.FromByteArray(c.GetEncoded())));
                }

                return result;
            }
            catch (CrlException e)
            {
                throw new CmsException("error encoding crls", e);
            }
            catch (Exception e)
            {
                throw new CmsException("error processing crls", e);
            }
        }

        public static Asn1Set CreateBerSetFromList(IList<object> berObjects)
        {
            Asn1EncodableVector v = CreateEncodableVector(berObjects);
            return new BerSet(v);
        }

        public static Asn1Set CreateDerSetFromList(IList<object> berObjects)
        {
            Asn1EncodableVector v = CreateEncodableVector(berObjects);
            return new DerSet(v);
        }

        public static Asn1EncodableVector CreateEncodableVector(IList<object> objects)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            foreach (Asn1Encodable ae in objects)
            {
                v.Add(ae);
            }

            return v;
        }

        public static CmsSignedData ReplaceCertificatesAndCrlsAndAddDigestAlgorithm(
            CmsSignedData cmsSignedData,
            List<X509Certificate>? x509Certs,
            IEnumerable<X509Crl>? x509Crls,
            IEnumerable<BasicOcspResp>? basicOcspResps,
            string digestOID)
        {
            Asn1Set? certs = null;
            if (x509Certs != null)
            {
                Asn1Set asn1Set = CreateBerSetFromList(GetCertificateStructureFromCertificates(x509Certs));
                if (asn1Set.Count != 0)
                {
                    certs = asn1Set;
                }
            }

            Asn1Set? crlsSet = null;
            List<object> crls = new List<object>();
            if (x509Crls != null)
            {
                crls.AddRange(GetCertificateListFromCrls(x509Crls));
            }
            if (basicOcspResps != null)
            {
                var ocsps = GetOtherRevocationInfoFromOcsps(basicOcspResps);
                if (ocsps != null)
                {
                    crls.AddRange(ocsps);
                }
            }
            Asn1Set asn1Set2 = CreateBerSetFromList(crls);
            if (asn1Set2.Count != 0)
            {
                crlsSet = asn1Set2;
            }

            var contentInfo = cmsSignedData.ContentInfo;
            var old = SignedData.GetInstance(contentInfo.Content);

            var digestAlgorithms = new List<Asn1Encodable>();
            bool toAdd = true;
            foreach (Asn1Encodable? item in old.DigestAlgorithms)
            {
                var alg = AlgorithmIdentifier.GetInstance(item!);

                if (alg.Algorithm.Id.Equals(digestOID, StringComparison.OrdinalIgnoreCase))
                {
                    toAdd = false;
                }
                digestAlgorithms.Add(alg);
            }

            if (toAdd)
            {
                digestAlgorithms.Add(new DerObjectIdentifier(digestOID));
            }

            var signedData = new SignedData(
                CreateBerSetFromList(digestAlgorithms.ToArray()),
                old.EncapContentInfo,
                certs,
                crlsSet,
                old.SignerInfos);

            var cms = new CmsSignedData(new ContentInfo(contentInfo.ContentType, signedData));

            return cms;
        }


        public override (IDocument, ICollection<IValidationContext?>?) ExtendSignatures(
            IDocument signedDocument,
            DateTime endDate,
            IDocument? originalDocument,
            SignatureParameters parameters)
        {
            if (signedDocument is null)
            {
                throw new ArgumentNullException(nameof(signedDocument));
            }

            if (originalDocument is null)
            {
                throw new ArgumentNullException(nameof(originalDocument));
            }

            // TODO: make it for every signer in signature. ExtendSignatures methods should accept SignerInformation as one of its parameters
            var (signedData, si) = FillDataStructures(signedDocument);
            var wannabeProfile = Helpers.Extensions.GetWannaBeProfile(si);
            nloglogger.Info("wannabeProfile: " + wannabeProfile);
            FileSignatureState state;
            ValidationReport? report = null;
            ICollection<IValidationContext?>? contexts = null;
            IValidationContext? context = null;
            var siArray = new List<SignerInfo>();
            var validationContexts = new List<IValidationContext?>();
            var targetSignatureProfile = wannabeProfile == SignatureProfile.XLType2 ? SignatureProfile.XLType2 : SignatureProfile.XLType1;
            if (wannabeProfile == SignatureProfile.BES)
            {
                state = FileSignatureState.Checked;
            }
            else
            {
                // TODO: check that is failed if signedDocument is not signature
                (report, contexts) = Validator.ValidateDocumentWithContext(signedDocument, checkIntegrity: false, externalContent: originalDocument);
                context = contexts.ElementAt(0)!;

                nloglogger.Trace("Validation Before start");
                nloglogger.Trace(JsonConvert.SerializeObject(ValidationHelper.GetValidationInfos(SignatureType.CAdES, targetSignatureProfile, report, this.CurrentTimeGetter)));
                nloglogger.Trace("Validation Before end");

                state = Helpers.Extensions.GetSignatureState(report.SignatureInformationList[0]!, wannabeProfile);
            }
            if (state == FileSignatureState.Checked)
            {
                // if good then let's make archive stamp using context
                switch (wannabeProfile)
                {
                    case SignatureProfile.XLType1:
                    case SignatureProfile.XLType2:
                    case SignatureProfile.XType1:
                    case SignatureProfile.XType2:
                    case SignatureProfile.XL:
                    case SignatureProfile.C:
                    case SignatureProfile.T:
                    case SignatureProfile.BES:
                        {
                            (signedDocument, contexts) = Xlt1Extension.ExtendSignatures(
                                    signedDocument,
                                    endDate,
                                    originalDocument,
                                    new SignatureParameters(parameters)
                                    {
                                        SignatureProfile = targetSignatureProfile,
                                        EnrichXTimestamp = true
                                    });
                            nloglogger.Trace($"Extending to {targetSignatureProfile} start");
                            (report, contexts) = Validator.ValidateDocumentWithContext(
                                    signedDocument,
                                    checkIntegrity: false,
                                    externalContent: originalDocument,
                                    contexts);
                            nloglogger.Trace($"Extending to {targetSignatureProfile} end");
                            nloglogger.Trace("Validation After start");
                            nloglogger.Trace(JsonConvert.SerializeObject(ValidationHelper.GetValidationInfos(SignatureType.CAdES, targetSignatureProfile, report, this.CurrentTimeGetter)));
                            nloglogger.Trace("Validation After end");
                            if (
                                    Helpers.Extensions.GetSignatureState(
                                        report.SignatureInformationList[0]!,
                                        targetSignatureProfile)
                                    != FileSignatureState.Checked)
                            {
                                return (signedDocument, new[] { context });
                            }
                            (signedData, si) = FillDataStructures(signedDocument);
                            context = contexts.ElementAt(0)!;

                            break;
                        }
                    case SignatureProfile.A:
                        {
                            var unsignedAttrs = new OrderedAttributeTable(si.ToSignerInfo().UnauthenticatedAttributes);
                            var archiveAttributes = unsignedAttrs[id_aa_ets_archiveTimestamp_v3]!;
                            var archiveTimestamps = archiveAttributes
                                .Select(x => new TimeStampToken(new CmsSignedData(x.AttrValues[0].GetDerEncoded())))
                                .ToList();
                            var latestTimestamp = archiveTimestamps
                                .OrderByDescending(x => x.TimeStampInfo.GenTime)
                                .First();
                            var signatureCertificateSource = new CAdESCertificateSource(signedData, si.SignerID, false);
                            var signatureCrlSource = new CAdESCRLSource(signedData, si.SignerID);
                            var signatureOcspSource = new CAdESOCSPSource(signedData, si.SignerID);

                            var cmsLatestTimestamp = EnrichTimestampsWithRefsAndValues(
                                latestTimestamp.ToCmsSignedData(),
                                this.CurrentTimeGetter.CurrentUtcTime,
                                context!,
                                signatureCertificateSource,
                                signatureCrlSource,
                                signatureOcspSource,
                                parameters.DigestAlgorithmOID,
                                parameters.CreateNewAttributeIfExist,
                                true
                                );


                            unsignedAttrs.ReplaceAttribute(archiveAttributes.ElementAt(archiveTimestamps.IndexOf(latestTimestamp)),
                                     new DerSet(Asn1Object.FromByteArray(cmsLatestTimestamp.GetEncoded("DER"))));
                            var newsi = ReplaceUnsignedAttributes(si, unsignedAttrs);
                            var siArr = new List<SignerInfo> { newsi };
                            signedData = ReplaceSigners(signedData, siArr);
                            (signedData, si) = FillDataStructures(new InMemoryDocument(signedData.GetEncoded()));

                            break;
                        }
                    default:
                        throw new ArgumentException("Unexpected signature profile");
                }
                SignerInfo signerInfo;
                IValidationContext validationContext;
                (signedData, signerInfo, validationContext) = ExtendCMSSignature(signedData, si, parameters, originalDocument, context!);
                siArray.Add(signerInfo);
                validationContexts.Add(validationContext);
            }
            else
            {
                nloglogger.Trace(JsonConvert.SerializeObject(ValidationHelper.GetValidationInfos(SignatureType.CAdES, wannabeProfile, report, this.CurrentTimeGetter)));
                return (signedDocument, new[] { context });
            }

            CmsSignedData extended = ReplaceSigners(signedData, siArray);
            return (new InMemoryDocument(extended.GetEncoded()), validationContexts);
        }

        private (CmsSignedData, SignerInformation) FillDataStructures(IDocument signedDocument)
        {
            CmsSignedData signedData = new CmsSignedData(signedDocument.OpenStream());
            var si = signedData.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();

            return (signedData, si);
        }

        public static bool VerifyAtsHash(ICryptographicProvider cryptographicProvider, IAdvancedSignature signature, TimestampToken ats)
        {
            var attrTable = ats.GetTimeStamp().UnsignedAttributes.ToDictionary();
            if (!attrTable.Contains(id_aa_ATSHashIndex_v3))
            {
                return false;
            }

            var hashIndex = attrTable[id_aa_ATSHashIndex_v3] as Attribute;
            var hashIndexValue = (DerSequence)hashIndex?.AttrValues[0]!;

            var digestAlgorithm = AlgorithmIdentifier.GetInstance(hashIndexValue[0]);
            if (digestAlgorithm is null)
            {
                return false;
            }

            var certsHashSequence = hashIndexValue[1] as DerSequence;
            var crlHashSequence = hashIndexValue[2] as DerSequence;
            var unsignedAttributesDerSequence = hashIndexValue[3] as DerSequence;

            var signedData = SignedData.GetInstance(signature.CmsSignedData.ContentInfo.Content);

            Asn1Set? certsToHash = null;
            if (certsHashSequence is not null && signedData.Certificates is not null)
            {
                certsToHash = CreateBerSetFromList(
                        signedData.Certificates.ToArray().Take(certsHashSequence.Count).Cast<object>().ToList());
            }

            Asn1Set? crlsToHash = null;
            if (crlHashSequence is not null && signedData.CRLs is not null)
            {
                crlsToHash = CreateBerSetFromList(
                        signedData.CRLs.ToArray().Take(crlHashSequence.Count).Cast<object>().ToList());
            }

            Asn1Set? unsignedToHash = null;
            if (unsignedAttributesDerSequence is not null && signedData.SignerInfos is not null)
            {
                var signedInfo = signature.SignerInformation.ToSignerInfo();
                if (signedInfo.UnauthenticatedAttributes is not null)
                {
                    unsignedToHash = CreateBerSetFromList(
                           signedInfo.UnauthenticatedAttributes.ToArray().Take(unsignedAttributesDerSequence.Count).Cast<object>().ToList());
                }
            }
            var calculatedSequence = CalculateAtsHashIndexInternal(cryptographicProvider, digestAlgorithm, certsToHash, crlsToHash, unsignedToHash);

            return hashIndexValue.Equals(calculatedSequence);
        }

        public static byte[] GetTimestampData(ICryptographicProvider cryptographicProvider, IAdvancedSignature signature, IDocument originalDocument, TimestampToken ats)
        {
            var attrTable = ats.GetTimeStamp().UnsignedAttributes.ToDictionary();
            if (!attrTable.Contains(id_aa_ATSHashIndex_v3))
            {
                throw new ArgumentException("Archive timestamp does not have an ats hash index");
            }

            var hashIndex = attrTable[id_aa_ATSHashIndex_v3] as Attribute;
            var hashIndexValue = (DerSequence)hashIndex?.AttrValues[0]!;

            var digestAlgorithm = AlgorithmIdentifier.GetInstance(hashIndexValue[0]);
            if (digestAlgorithm is null)
            {
                throw new ArgumentException("The ats hash index does not have a digest algorithm");
            }

            var certsHashSequence = hashIndexValue[1] as DerSequence;
            var crlHashSequence = hashIndexValue[2] as DerSequence;
            var unsignedAttributesDerSequence = hashIndexValue[3] as DerSequence;

            var signedData = SignedData.GetInstance(signature.CmsSignedData.ContentInfo.Content);
            return GetDataForStamping(
                    cryptographicProvider,
                    signature.CmsSignedData,
                    signature.SignerInformation,
                    hashIndexValue,
                    originalDocument,
                    digestAlgorithm.Algorithm.Id);
        }
    }
}
