﻿using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using BcCms = Org.BouncyCastle.Asn1.Cms;
using BcX509 = Org.BouncyCastle.Asn1.X509;

namespace CAdESLib.Document.Signature
{
    /// <summary>
    /// CAdES Signature class helper
    /// </summary>
    public class CAdESSignature : IAdvancedSignature
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private readonly CmsSignedData _cmsSignedData;

        private readonly SignerInformation signerInformation;

        public CAdESSignature(byte[] data) : this(new CmsSignedData(data))
        {
        }

        public CAdESSignature(CmsSignedData cms)
        {
            signerInformation = cms.GetSignerInfos().GetSigners().OfType<SignerInformation>().FirstOrDefault();
            if (signerInformation is null)
            {
                throw new ArgumentNullException(nameof(signerInformation));
            }
            _cmsSignedData = cms;
        }

        public CAdESSignature(CmsSignedData cms, SignerInformation signerInformation)
        {
            _cmsSignedData = cms;
            this.signerInformation = signerInformation;
        }

        public CAdESSignature(CmsSignedData cms, SignerID id)
        {
            _cmsSignedData = cms;
            this.signerInformation = BCStaticHelpers.GetSigner(cms, id);
        }


        public virtual ICertificateSource CertificateSource => new CAdESCertificateSource(_cmsSignedData, signerInformation.SignerID, false);

        public virtual ICertificateSource ExtendedCertificateSource => new CAdESCertificateSource(_cmsSignedData, signerInformation.SignerID, true);

        public virtual ICrlSource CRLSource => new CAdESCRLSource(_cmsSignedData, signerInformation.SignerID);

        public virtual IOcspSource OCSPSource => new CAdESOCSPSource(_cmsSignedData, signerInformation.SignerID);

        public virtual X509Certificate? SigningCertificate
        {
            get
            {
                logger.Trace($"SignerInformation {signerInformation.SignerID.Subject},serial={signerInformation.SignerID.SerialNumber.ToString(16)}");
                ICollection<X509Certificate> certs = Certificates;
                foreach (X509Certificate cert in certs)
                {
                    logger.Trace($"Test match for certificate {cert.SubjectDN.ToString()},serial={cert.SerialNumber.ToString(16)}");
                    if (signerInformation.SignerID.Match(cert))
                    {
                        return cert;
                    }
                }
                return null;
            }
        }

        public virtual IList<X509Certificate> Certificates
        {
            get
            {
                var list = ((CAdESCertificateSource)CertificateSource).GetCertificates()?.ToList() ?? Array.Empty<X509Certificate>().ToList();

                foreach (var tst in AllTimestampTokens)
                {
                    list.AddRange(tst.GetTimeStamp().UnsignedAttributes?.GetEtsCertValues() ?? new List<X509Certificate>());
                }

                return list;
            }
        }

        public virtual PolicyValue? PolicyId
        {
            get
            {
                if (signerInformation.SignedAttributes == null)
                {
                    return null;
                }
                BcCms.Attribute sigPolicytAttr = signerInformation.SignedAttributes[PkcsObjectIdentifiers.IdAAEtsSigPolicyID];
                if (sigPolicytAttr == null)
                {
                    return null;
                }
                if (sigPolicytAttr.AttrValues[0] is DerNull)
                {
                    return new PolicyValue();
                }
                SignaturePolicyId sigPolicy = SignaturePolicyId.GetInstance(sigPolicytAttr.AttrValues[0]);
                if (sigPolicy == null)
                {
                    return new PolicyValue();
                }
                return new PolicyValue(sigPolicy.SigPolicyIdentifier.Id);
            }
        }

        public virtual DateTimeObject? SigningTime
        {
            get
            {
                if (signerInformation.SignedAttributes != null && signerInformation.SignedAttributes
            [PkcsObjectIdentifiers.Pkcs9AtSigningTime] != null)
                {
                    Asn1Set set = signerInformation.SignedAttributes[PkcsObjectIdentifiers.Pkcs9AtSigningTime]
                        .AttrValues;
                    try
                    {
                        object o = set[0];
                        switch (o)
                        {
                            case DerUtcTime _:
                                return new DateTimeObject(((DerUtcTime)o).ToDateTime());
                            case BcX509.Time _:
                                return new DateTimeObject(((BcX509.Time)o).ToDateTime());
                        }
                        logger.Error("Error when reading signing time. Unrecognized " + o.GetType());
                    }
                    catch (Exception ex)
                    {
                        logger.Error("Error when reading signing time " + ex.Message);
                        return null;
                    }
                }
                return null;
            }
        }

        public virtual string? Location => null;

        public virtual string[]? ClaimedSignerRoles
        {
            get
            {
                if (signerInformation.SignedAttributes == null)
                {
                    return null;
                }
                BcCms.Attribute signerAttrAttr = signerInformation.SignedAttributes[PkcsObjectIdentifiers.IdAAEtsSignerAttr];
                if (signerAttrAttr == null)
                {
                    return null;
                }
                SignerAttribute signerAttr = SignerAttribute.GetInstance(signerAttrAttr.AttrValues[0]);
                if (signerAttr == null)
                {
                    return null;
                }
                string[] ret = new string[signerAttr.ClaimedAttributes.Count];
                for (int i = 0; i < signerAttr.ClaimedAttributes.Count; i++)
                {
                    ret[i] = signerAttr.ClaimedAttributes[i] is DerOctetString @string
                        ? Encoding.UTF8.GetString(@string.GetOctets())!
                        : signerAttr.ClaimedAttributes[i].ToString()!;
                }
                return ret;
            }
        }

        public virtual IList<TimestampToken>? SignatureTimestamps => signerInformation.GetSignatureTimestamps();

        public virtual IList<TimestampToken>? TimestampsX1 => signerInformation.GetTimestampsX1();

        public virtual IList<TimestampToken>? TimestampsX2 => signerInformation.GetTimestampsX2();

        public virtual IList<TimestampToken>? ArchiveTimestamps => signerInformation.GetArchiveTimestamps();

        public virtual string SignatureAlgorithm => signerInformation.EncryptionAlgOid;

        public virtual bool CheckIntegrity(IDocument? detachedDocument)
        {
            try
            {
                bool ret = false;
                SignerInformation? si = null;
                if (detachedDocument != null)
                {
                    // Recreate a SignerInformation with the content using a CMSSignedDataParser                   

                    CmsSignedDataParser sp = new CmsSignedDataParser(new CmsTypedStream(detachedDocument.OpenStream()), _cmsSignedData.GetEncoded());
                    sp.GetSignedContent().Drain();
                    si = BCStaticHelpers.GetSigner(sp, signerInformation.SignerID);
                }
                else
                {
                    si = signerInformation;
                }
                ret = si.Verify(SigningCertificate);
                return ret;
            }
            catch (CertificateExpiredException)
            {
                return false;
            }
            catch (CmsException)
            {
                return false;
            }
            catch (IOException)
            {
                return false;
            }
        }

        public virtual string ContentType => signerInformation.ContentType.ToString();

        public virtual IList<IAdvancedSignature> CounterSignatures
        {
            get
            {
                IList<IAdvancedSignature> counterSigs = new List<IAdvancedSignature>();
                foreach (var o in signerInformation.GetCounterSignatures().GetSigners().Cast<SignerInformation>())
                {
                    CAdESSignature info = new CAdESSignature(_cmsSignedData, o.SignerID);
                    counterSigs.Add(info);
                }
                return counterSigs;
            }
        }

        public virtual IList<CertificateRef> CertificateRefs
        {
            get
            {
                var list = new List<CertificateRef>();
                list.AddRange(signerInformation.UnsignedAttributes.GetEtsCertificateRefs());

                foreach (var tst in AllTimestampTokens)
                {
                    list.AddRange(tst.GetTimeStamp().UnsignedAttributes?.GetEtsCertificateRefs() ?? new List<CertificateRef>());
                }

                return list;
            }
        }

        public virtual IList<CRLRef> CRLRefs
        {
            get
            {
                var list = new List<CRLRef>();
                list.AddRange(signerInformation.UnsignedAttributes.GetEtsCrlRefs());

                foreach (var tst in AllTimestampTokens)
                {
                    list.AddRange(tst.GetTimeStamp().UnsignedAttributes?.GetEtsCrlRefs() ?? new List<CRLRef>());
                }
                return list;
            }
        }
        public virtual IList<OCSPRef> OCSPRefs
        {
            get
            {
                var list = new List<OCSPRef>();
                list.AddRange(signerInformation.UnsignedAttributes.GetEtsOcspRefs());

                foreach (var tst in AllTimestampTokens)
                {
                    list.AddRange(tst.GetTimeStamp().UnsignedAttributes?.GetEtsOcspRefs() ?? new List<OCSPRef>());
                }
                return list;
            }
        }

        public virtual IList<X509Crl> CRLs => ((CAdESCRLSource)CRLSource).GetCRLsFromSignature();

        public virtual IList<BasicOcspResp> OCSPs => ((CAdESOCSPSource)OCSPSource).GetOCSPResponsesFromSignature();

        public virtual byte[] SignatureTimestampData => signerInformation.GetSignature();

        public virtual byte[] TimestampX1Data
        {
            get
            {
                var toTimestamp = new MemoryStream();
                toTimestamp.Write(signerInformation.GetSignature());
                Org.BouncyCastle.Asn1.Cms.Attribute attr;
                if (signerInformation.UnsignedAttributes != null && (attr = signerInformation.UnsignedAttributes[PkcsObjectIdentifiers.IdAASignatureTimeStampToken]) != null)
                {
                    toTimestamp.Write(attr.AttrType.GetDerEncoded());
                    toTimestamp.Write(attr.AttrValues.GetDerEncoded());
                }
                toTimestamp.Write(TimestampX2Data);
                return toTimestamp.ToArray();

            }
        }

        public virtual byte[] TimestampX2Data
        {
            get
            {
                var toTimestamp = new MemoryStream();
                if (signerInformation.UnsignedAttributes != null)
                {
                    var unsignedAttibutes = signerInformation.UnsignedAttributes.ToDictionary();

                    if (unsignedAttibutes.Contains(PkcsObjectIdentifiers.IdAAEtsCertificateRefs))
                    {
                        var attrCertRefs = signerInformation.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertificateRefs];
                        if (attrCertRefs != null)
                        {
                            toTimestamp.Write(attrCertRefs.AttrType.GetDerEncoded());
                            toTimestamp.Write(attrCertRefs.AttrValues.GetDerEncoded());
                        }
                    }

                    if (unsignedAttibutes.Contains(PkcsObjectIdentifiers.IdAAEtsRevocationRefs))
                    {
                        var attrRevocCertRefs = signerInformation.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationRefs];
                        if (attrRevocCertRefs != null)
                        {
                            toTimestamp.Write(attrRevocCertRefs.AttrType.GetDerEncoded());
                            toTimestamp.Write(attrRevocCertRefs.AttrValues.GetDerEncoded());
                        }
                    }
                }
                return toTimestamp.ToArray();
            }
        }

        public IList<TimestampToken> AllTimestampTokens => signerInformation.GetAllTimestampTokens();

        public virtual byte[] GetArchiveTimestampData(int index, IDocument? originalDocument)
        {
            using var toTimestamp = new MemoryStream();
            BcCms.ContentInfo contentInfo = _cmsSignedData.ContentInfo;
            BcCms.SignedData signedData = BcCms.SignedData.GetInstance(contentInfo.Content);
            // 5.4.1
            if (signedData.EncapContentInfo == null || signedData.EncapContentInfo.Content == null)
            {
                if (originalDocument != null)
                {
                    toTimestamp.Write(Streams.ReadAll(originalDocument.OpenStream()));
                }
                else
                {
                    throw new Exception("Signature is detached and no original data provided.");
                }
            }
            else
            {
                BcCms.ContentInfo content = signedData.EncapContentInfo;
                DerOctetString octet = (DerOctetString)content.Content;
                BcCms.ContentInfo info2 = new BcCms.ContentInfo(new DerObjectIdentifier("1.2.840.113549.1.7.1"), new BerOctetString(octet.GetOctets()));
                toTimestamp.Write(info2.GetEncoded());
            }
            if (signedData.Certificates != null)
            {
                DerOutputStream output = new DerOutputStream(toTimestamp);
                output.WriteObject(signedData.Certificates);
                output.Close();
            }
            if (signedData.CRLs != null)
            {
                toTimestamp.Write(signedData.CRLs.GetEncoded());
            }
            if (signerInformation.UnsignedAttributes != null)
            {
                Asn1EncodableVector original = signerInformation.UnsignedAttributes.ToAsn1EncodableVector();
                IList<BcCms.Attribute> timeStampToRemove = GetTimeStampToRemove(index);
                Asn1EncodableVector filtered = new Asn1EncodableVector();
                for (int i = 0; i < original.Count; i++)
                {
                    Asn1Encodable enc = original[i];
                    if (!timeStampToRemove.Contains(enc))
                    {
                        filtered.Add(original[i]);
                    }
                }
                SignerInformation filteredInfo = SignerInformation.ReplaceUnsignedAttributes(signerInformation, new BcCms.AttributeTable(filtered));
                toTimestamp.Write(filteredInfo.ToSignerInfo().GetEncoded());
            }
            return toTimestamp.ToArray();
        }

        private class AttributeTimeStampComparator : IComparer<BcCms.Attribute>
        {
            public virtual int Compare(BcCms.Attribute? o1, BcCms.Attribute? o2)
            {
                try
                {
                    if (o1 is null && o2 is null)
                    {
                        return 0;
                    }
                    if (o1 is null)
                    {
                        return 1;
                    }
                    else if (o2 is null)
                    {
                        return -1;
                    }

                    TimeStampToken t1 = new TimeStampToken(new CmsSignedData(o1.AttrValues
                        [0].ToAsn1Object().GetDerEncoded()));
                    TimeStampToken t2 = new TimeStampToken(new CmsSignedData(o2.AttrValues
                        [0].ToAsn1Object().GetDerEncoded()));
                    return -t1.TimeStampInfo.GenTime.CompareTo(t2.TimeStampInfo.GenTime);
                }
                catch (Exception e)
                {
                    throw new Exception("Cannot read original ArchiveTimeStamp", e);
                }
            }
        }

        private IList<BcCms.Attribute> GetTimeStampToRemove(int archiveTimeStampToKeep)
        {
            List<BcCms.Attribute> ts = new List<BcCms.Attribute>();
            if (signerInformation.UnsignedAttributes != null)
            {
                Asn1EncodableVector v = signerInformation.UnsignedAttributes.GetAll(PkcsObjectIdentifiers.IdAAEtsArchiveTimestamp);
                for (int i = 0; i < v.Count; i++)
                {
                    Asn1Encodable enc = v[i];
                    ts.Add((BcCms.Attribute)enc);
                }
                ts.Sort(new AttributeTimeStampComparator());
                for (int i_1 = 0; i_1 < archiveTimeStampToKeep; i_1++)
                {
                    ts.RemoveAt(0);
                }
            }
            return ts;
        }
    }
}
