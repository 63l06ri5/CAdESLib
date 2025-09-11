using CAdESLib.Document.Signature;
using CAdESLib.Document.Validation;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using System.Linq;
using NLog;

namespace CAdESLib.Helpers
{
    public static class AsnHelpers
    {

        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// Remove certs field. Certificates are carried in a CertValues
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static BasicOcspResponse RefineOcspResp(this BasicOcspResp input)
        {
            var original = (BasicOcspResponse.GetInstance((Asn1Sequence)Asn1Object.FromByteArray(input.GetEncoded())));
            return new BasicOcspResponse(original.TbsResponseData, original.SignatureAlgorithm, original.Signature, null);
        }

        public static bool EqualsWithDerNull(this CertificateID certificateID, CertificateID otherCertificateID)
        {
            var asnCertificateID = certificateID?.ToAsn1Object();
            var asnOtherCertificateID = otherCertificateID?.ToAsn1Object();

            if (asnCertificateID == null || otherCertificateID == null)
            {
                if (asnCertificateID == asnOtherCertificateID)
                {
                    return true;
                }

                return false;
            }

            if (!(asnCertificateID.HashAlgorithm?.Equals(asnOtherCertificateID?.HashAlgorithm) ?? false))
            {
                if (asnCertificateID.HashAlgorithm != asnOtherCertificateID?.HashAlgorithm)
                {
                    if (asnCertificateID.HashAlgorithm == null)
                    {
                        return false;
                    }

                    if (!(asnCertificateID.HashAlgorithm.Algorithm?.Equals(asnOtherCertificateID?.HashAlgorithm.Algorithm) ?? false))
                    {
                        return false;
                    }

                    if (!(asnCertificateID.HashAlgorithm.Parameters?.Equals(asnOtherCertificateID.HashAlgorithm.Parameters) ?? false))
                    {
                        if (!((asnCertificateID.HashAlgorithm.Parameters == null || asnCertificateID.HashAlgorithm.Parameters.Equals(DerNull.Instance)) && (asnOtherCertificateID.HashAlgorithm.Parameters == null || asnOtherCertificateID.HashAlgorithm.Parameters.Equals(DerNull.Instance))))
                        {
                            return false;
                        }
                    }
                }
            }

            if (!(asnCertificateID.IssuerKeyHash?.Equals(asnOtherCertificateID?.IssuerKeyHash) ?? false))
            {
                return false;
            }

            if (!(asnCertificateID.IssuerNameHash?.Equals(asnOtherCertificateID.IssuerNameHash) ?? false))
            {
                return false;
            }

            if (!(asnCertificateID.SerialNumber?.Equals(asnOtherCertificateID.SerialNumber) ?? false))
            {
                return false;
            }

            return true;
        }

        public static IList<X509Certificate> GetEtsCertValues(this Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttributes)
        {
            var list = new List<X509Certificate>();
            if (unsignedAttributes != null && unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertValues] != null)
            {
                DerSequence seq = (DerSequence)unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertValues].AttrValues[0];
                for (int i = 0; i < seq.Count; i++)
                {
                    X509CertificateStructure cs = X509CertificateStructure.GetInstance(seq[i]);
                    X509Certificate c = new X509Certificate(cs);
                    if (!list.Contains(c))
                    {
                        list.Add(c);
                    }
                }
            }

            return list;
        }

        public static IList<CertificateRef> GetEtsCertificateRefs(this Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttributes)
        {
            var list = new List<CertificateRef>();
            if (unsignedAttributes != null)
            {
                var unsignedAttributesHash = unsignedAttributes.ToDictionary();
                if (unsignedAttributesHash.Contains(PkcsObjectIdentifiers.IdAAEtsCertificateRefs))
                {
                    var completeCertRefsAttr = unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertificateRefs];
                    if (completeCertRefsAttr != null && completeCertRefsAttr.AttrValues.Count > 0)
                    {
                        DerSequence completeCertificateRefs = (DerSequence)completeCertRefsAttr.AttrValues[0];
                        for (int i1 = 0; i1 < completeCertificateRefs.Count; i1++)
                        {
                            var otherCertId = OtherCertID.GetInstance(completeCertificateRefs[i1]);
                            var certId = new CertificateRef
                            {
                                DigestAlgorithm = otherCertId.OtherCertHash.HashAlgorithm.Algorithm.Id
                            };

                            certId.DigestValue = otherCertId.OtherCertHash.GetHashValue();
                            if (otherCertId.IssuerSerial != null)
                            {
                                if (otherCertId.IssuerSerial.Issuer != null)
                                {
                                    certId.IssuerName = otherCertId.IssuerSerial.Issuer.ToString();
                                }
                                if (otherCertId.IssuerSerial.Serial != null)
                                {
                                    certId.IssuerSerial = otherCertId.IssuerSerial.Serial.ToString();
                                }
                            }
                            list.Add(certId);
                        }
                    }
                }
            }

            return list;
        }

        public static IList<CRLRef> GetEtsCrlRefs(this Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttributes)
        {
            var list = new List<CRLRef>();
            if (unsignedAttributes != null)
                foreach (var otherCertId in unsignedAttributes.GetEtsRevocationRefs())
                {
                    if (otherCertId.CrlIDs != null)
                    {
                        foreach (CrlValidatedID id in otherCertId.CrlIDs.GetCrls())
                        {
                            list.Add(new CRLRef(id));
                        }
                    }
                }

            return list;
        }

        public static IList<OCSPRef> GetEtsOcspRefs(this Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttributes)
        {
            var list = new List<OCSPRef>();
            foreach (var otherCertId in unsignedAttributes.GetEtsRevocationRefs())
            {
                if (otherCertId.OcspIDs != null)
                {
                    foreach (OcspResponsesID id in otherCertId.OcspIDs.GetOcspResponses())
                    {
                        list.Add(new OCSPRef(id, true));
                    }
                }
            }

            return list;
        }

        public static IList<CrlOcspRef> GetEtsRevocationRefs(this Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttributes)
        {
            var list = new List<CrlOcspRef>();
            if (unsignedAttributes != null)
            {
                var unsignedAttributesHash = unsignedAttributes.ToDictionary();
                if (unsignedAttributesHash.Contains(PkcsObjectIdentifiers.IdAAEtsRevocationRefs))
                {
                    var completeRevocationRefsAttr = unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationRefs];
                    if (completeRevocationRefsAttr != null && completeRevocationRefsAttr.AttrValues.Count > 0)
                    {
                        DerSequence completeRevocationRefs = (DerSequence)completeRevocationRefsAttr.AttrValues[0];
                        for (int i1 = 0; i1 < completeRevocationRefs.Count; i1++)
                        {
                            CrlOcspRef otherCertId = CrlOcspRef.GetInstance(completeRevocationRefs[i1]);
                            list.Add(otherCertId);
                        }
                    }
                }
            }

            return list;
        }


        public static IList<BasicOcspResp> GetOcspReps(this Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttributes)
        {
            IList<BasicOcspResp> list = new List<BasicOcspResp>();
            if (unsignedAttributes != null)
            {
                var revocationValues = unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationValues];
                if (revocationValues != null && revocationValues.AttrValues.Count > 0)
                {
                    RevocationValues revValues = RevocationValues.GetInstance(revocationValues.AttrValues[0]);
                    try
                    {
                        foreach (var ocspObj in revValues.GetOcspVals())
                        {
                            BasicOcspResp bOcspObj = new BasicOcspResp(ocspObj);
                            list.Add(bOcspObj);
                        }
                    }
                    catch
                    {
                    }
                }
            }
            return list;
        }

        public static IList<X509Crl> GetCrls(this Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttributes)
        {
            IList<X509Crl> list = new List<X509Crl>();
            if (unsignedAttributes != null)
            {
                var revocationValues = unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationValues];
                if (revocationValues != null && revocationValues.AttrValues.Count > 0)
                {
                    RevocationValues revValues = RevocationValues.GetInstance(revocationValues.AttrValues[0]);
                    try
                    {
                        foreach (var crlObj in revValues.GetCrlVals())
                        {
                            X509Crl bOcspObj = new X509Crl(crlObj);
                            list.Add(bOcspObj);
                        }
                    }
                    catch
                    {
                    }
                }
            }
            return list;
        }

        public static IList<TimestampToken>? GetTimestampList(
                this SignerInformation signerInformation,
                DerObjectIdentifier attrType)
        {
            if (signerInformation.UnsignedAttributes != null)
            {
                IList<TimestampToken> tstokens = new List<TimestampToken>();
                foreach (Attribute timeStampAttr in signerInformation.UnsignedAttributes.GetAll(attrType))
                {
                    foreach (Asn1Encodable value in timeStampAttr.AttrValues.ToArray())
                    {
                        try
                        {
                            TimeStampToken token = new TimeStampToken(new CmsSignedData(value.GetDerEncoded()));
                            tstokens.Add(new TimestampToken(token));
                        }
                        catch (Exception e)
                        {
                            throw new Exception("Parsing error", e);
                        }
                    }
                }
                return tstokens;
            }
            else
            {
                return null;
            }
        }

        public static IList<TimestampToken>? GetSignatureTimestamps(
                this SignerInformation signerInformation) =>
                    signerInformation.GetTimestampList(PkcsObjectIdentifiers.IdAASignatureTimeStampToken);

        public static IList<TimestampToken>? GetTimestampsX1(
                this SignerInformation signerInformation) =>
                    signerInformation.GetTimestampList(PkcsObjectIdentifiers.IdAAEtsEscTimeStamp);

        public static IList<TimestampToken>? GetTimestampsX2(
                this SignerInformation signerInformation) =>
                    signerInformation.GetTimestampList(PkcsObjectIdentifiers.IdAAEtsCertCrlTimestamp);

        public static IList<TimestampToken>? GetArchiveTimestamps(
                this SignerInformation signerInformation) =>
                    signerInformation.GetTimestampList(Document.Signature.Extensions.CAdESProfileA.id_aa_ets_archiveTimestamp_v3);

        public static IList<TimestampToken> GetAllTimestampTokens(this SignerInformation signerInformation)
        {
            var tsts = new List<TimestampToken>();
            var signatureTimestamps = signerInformation.GetSignatureTimestamps();
            if (signatureTimestamps != null)
            {
                tsts.AddRange(signatureTimestamps);
            }

            var timestampsX1 = signerInformation.GetTimestampsX1();
            if (timestampsX1 != null)
            {
                tsts.AddRange(timestampsX1);
            }

            var timestampsX2 = signerInformation.GetTimestampsX2();
            if (timestampsX2 != null)
            {
                tsts.AddRange(timestampsX2);
            }

            var archiveTimestamps = signerInformation.GetArchiveTimestamps();
            if (archiveTimestamps != null)
            {
                tsts.AddRange(archiveTimestamps);
            }

            return tsts;
        }

        public static string ToZuluString(this DateTime dateTime)
        {
            Func<string, string> getFormatStr = (string milli) => $@"yyyyMMddHHmmss{milli}\Z";
            var milliFrm = string.Empty;
            if (dateTime.Millisecond != 0)
            {
                int fCount = dateTime.Millisecond.ToString().TrimEnd('0').Length;
                milliFrm = @"." + new string('f', fCount);
            }

            return dateTime.ToString(getFormatStr(milliFrm));
        }

        public static string ToFineString(this X509Certificate? cert)
        {
            if (cert is null)
            {
                return string.Empty;
            }

            return $"Serial Number: {cert.SerialNumber}\nIssuerDN: {cert.IssuerDN}\nStart date: {cert.NotBefore}\nEnd date: {cert.NotAfter}\nSubjectDN: {cert.SubjectDN}";
        }

        // For bes an end date is current time aka time of validation
        public static bool IsValid(
                this X509Crl value,
                DateTime startDate,
                DateTime endDate) =>
                    value.NextUpdate is not null &&
                        (value.NextUpdate.Value.CompareTo(endDate) >= 0
                        && value.ThisUpdate.CompareTo(endDate) <= 0
                        && value.ThisUpdate.CompareTo(value.NextUpdate.Value) <= 0) ||
                    value.NextUpdate is null && value.ThisUpdate.CompareTo(endDate) <= 0 && value.ThisUpdate.CompareTo(startDate) >= 0;

        public static bool IsValid(
                this BasicOcspResp ocsp,
                DateTime startDate,
                DateTime endDate)
        {
            var value = ocsp.Responses.First();

            return
                     value.NextUpdate is not null &&
                         (value.NextUpdate.Value.CompareTo(endDate) >= 0
                             && value.ThisUpdate.CompareTo(endDate) <= 0
                             && value.ThisUpdate.CompareTo(value.NextUpdate.Value) <= 0) ||
                     value.NextUpdate is null &&
                         // TODO: this ocsp timeout window should be configurable
                         (value.ThisUpdate.AddSeconds(10).CompareTo(startDate) >= 0 &&
                          value.ThisUpdate.CompareTo(endDate.AddSeconds(10)) <= 0 &&
                          value.ThisUpdate.CompareTo(endDate.AddMinutes(-1)) >= 0
                          );
        }

        public static IList<X509Certificate> GetCertificates(this CmsSignedData cmsSignedData, SignerID signerId, bool timestampIncluded)
        {
            var list = new List<X509Certificate>();

            foreach (var ch in cmsSignedData.GetCertificates("Collection").GetMatches(null).Cast<X509Certificate>())
            {
                X509Certificate c = ch;
                if (!list.Contains(c))
                {
                    list.Add(c);
                }
            }
            // Add certificates in CAdES-XL certificate-values inside SignerInfo attribute if present
            SignerInformation si = BCStaticHelpers.GetSigner(cmsSignedData, signerId);
            list.AddRange(si?.UnsignedAttributes?.GetEtsCertValues() ?? new List<X509Certificate>());

            if (timestampIncluded)
            {
                foreach (var tst in si!.GetAllTimestampTokens())
                {
                    list.AddRange(tst.GetTimeStamp().UnsignedAttributes?.GetEtsCertValues() ?? new List<X509Certificate>());
                }
            }

            return list;
        }

        public static object? GetRevocationValue(this CmsSignedData cms, ICryptographicProvider cryptographicProvider, X509Certificate cert)
        {
            nloglogger.Trace($"GetRevocationValue. cert={cert.SubjectDN}");
            var signerInfo = cms.GetSignerInfos().GetSigners().OfType<SignerInformation>().FirstOrDefault();
            if (signerInfo is null)
            {
                nloglogger.Trace("There is no signerInfo");
                return null;
            }

            int? refIndex = null;
            if (signerInfo.SignerID.Match(cert))
            {
                nloglogger.Trace("It's a signing cert");
                refIndex = -1;
            }
            else
            {
                var certificateRefs = signerInfo.UnsignedAttributes.GetEtsCertificateRefs();
                var certificateRef = certificateRefs.FirstOrDefault(x => cert.EqualsCertificateRef(cryptographicProvider, x));
                if (certificateRef is null)
                {
                    nloglogger.Trace("There is no certificateRef");
                    return null;
                }

                refIndex = certificateRefs.IndexOf(certificateRef);
            }
            var revRefs = signerInfo.UnsignedAttributes.GetEtsRevocationRefs();
            if (!revRefs.Any())
            {
                nloglogger.Trace("There is no revocationRefs");
                return null;
            }
            var revRef = revRefs.ElementAt(refIndex.Value + 1);
            if (revRef.CrlIDs != null)
            {
                nloglogger.Trace("There is CrlIds");
                var refValues = signerInfo.UnsignedAttributes.GetCrls();
                var val = revRef.CrlIDs.GetCrls().FirstOrDefault();
                if (val is null)
                {
                    nloglogger.Trace("There is no crlsids");
                    return null;
                }

                var ref1 = new CRLRef(val);
                return refValues.FirstOrDefault(x => ref1.Match(cryptographicProvider, x));
            }

            if (revRef.OcspIDs != null)
            {
                nloglogger.Trace("There is OcspIDs");
                var refValues = signerInfo.UnsignedAttributes.GetOcspReps();
                var val = revRef.OcspIDs.GetOcspResponses().FirstOrDefault();
                if (val is null)
                {
                    nloglogger.Trace("There is no ocspids");
                    return null;
                }

                var ref1 = new OCSPRef(val, true);
                return refValues.FirstOrDefault(x => ref1.Match(cryptographicProvider, x));
            }

            return null;
        }

        public static bool EqualsCertificateRef(this X509Certificate cert, ICryptographicProvider cryptographicProvider, CertificateRef certRef)
        {
            byte[] hash = cryptographicProvider.CalculateDigest(certRef.DigestAlgorithm!, cert.GetEncoded());
            return (certRef.DigestValue is not null && hash.SequenceEqual(certRef.DigestValue));
        }

    }
}
