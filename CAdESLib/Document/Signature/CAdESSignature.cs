using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Date;
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
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        private readonly CmsSignedData _cmsSignedData;

        public SignerInformation SignerInformation { get; }

        public CAdESSignature(byte[] data) : this(new CmsSignedData(data))
        {
        }

        public CAdESSignature(CmsSignedData cms)
        {
            SignerInformation = cms.GetSignerInfos().GetSigners().OfType<SignerInformation>().First();
            _cmsSignedData = cms;
        }

        public CAdESSignature(CmsSignedData cms, SignerInformation signerInformation)
        {
            _cmsSignedData = cms;
            this.SignerInformation = signerInformation;
        }

        public CAdESSignature(CmsSignedData cms, SignerID id)
        {
            _cmsSignedData = cms;
            this.SignerInformation = BCStaticHelpers.GetSigner(cms, id);
        }


        public virtual ICertificateSource CertificateSource => new CAdESCertificateSource(_cmsSignedData, SignerInformation.SignerID, false);

        public virtual ICertificateSource ExtendedCertificateSource => new CAdESCertificateSource(_cmsSignedData, SignerInformation.SignerID, true);

        public virtual ICrlSource CRLSource => new CAdESCRLSource(_cmsSignedData, SignerInformation.SignerID);

        public virtual IOcspSource OCSPSource => new CAdESOCSPSource(_cmsSignedData, SignerInformation.SignerID);

        public virtual X509Certificate? SigningCertificate => Certificates.FirstOrDefault(cert => SignerInformation.SignerID.Match(cert));

        public virtual IList<X509Certificate> AllCertificates => ((CAdESCertificateSource)CertificateSource).GetCertificates(true)?.ToList() ?? Array.Empty<X509Certificate>().ToList();
        
        public virtual IList<X509Certificate> Certificates => ((CAdESCertificateSource)CertificateSource).GetCertificates(false)?.ToList() ?? Array.Empty<X509Certificate>().ToList();

        public virtual PolicyValue? PolicyId
        {
            get
            {
                if (SignerInformation.SignedAttributes == null)
                {
                    return null;
                }
                BcCms.Attribute sigPolicytAttr = SignerInformation.SignedAttributes[PkcsObjectIdentifiers.IdAAEtsSigPolicyID];
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
                if (SignerInformation.SignedAttributes != null && SignerInformation.SignedAttributes
            [PkcsObjectIdentifiers.Pkcs9AtSigningTime] != null)
                {
                    Asn1Set set = SignerInformation.SignedAttributes[PkcsObjectIdentifiers.Pkcs9AtSigningTime]
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
                        nloglogger.Error("Error when reading signing time. Unrecognized " + o.GetType());
                    }
                    catch (Exception ex)
                    {
                        nloglogger.Error("Error when reading signing time " + ex.Message);
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
                if (SignerInformation.SignedAttributes == null)
                {
                    return null;
                }
                BcCms.Attribute signerAttrAttr = SignerInformation.SignedAttributes[PkcsObjectIdentifiers.IdAAEtsSignerAttr];
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

        public virtual IList<TimestampToken>? SignatureTimestamps => SignerInformation.GetSignatureTimestamps();

        public virtual IList<TimestampToken>? TimestampsX1 => SignerInformation.GetTimestampsX1();

        public virtual IList<TimestampToken>? TimestampsX2 => SignerInformation.GetTimestampsX2();

        public virtual IList<TimestampToken>? ArchiveTimestamps => SignerInformation.GetArchiveTimestamps();

        public virtual string SignatureAlgorithm => SignerInformation.EncryptionAlgOid;

        public virtual bool CheckIntegrity(ICryptographicProvider cryptographicProvider, IDocument? detachedDocument)
        {
            return cryptographicProvider.CheckIntegrity(_cmsSignedData, detachedDocument);
        }

        public virtual string ContentType => SignerInformation.ContentType.ToString();

        public virtual IList<IAdvancedSignature> CounterSignatures
        {
            get
            {
                IList<IAdvancedSignature> counterSigs = new List<IAdvancedSignature>();
                foreach (var o in SignerInformation.GetCounterSignatures().GetSigners().Cast<SignerInformation>())
                {
                    CAdESSignature info = new CAdESSignature(_cmsSignedData, o.SignerID);
                    counterSigs.Add(info);
                }
                return counterSigs;
            }
        }
        
        public virtual IList<CertificateRef> AllCertificateRefs
        {
            get
            {
                var list = (CertificateRefs as List<CertificateRef>)!;

                foreach (var tst in AllTimestampTokens)
                {
                    list.AddRange(tst.GetTimeStamp().UnsignedAttributes?.GetEtsCertificateRefs() ?? new List<CertificateRef>());
                }

                return list;
            }
        }

        public virtual IList<CertificateRef> CertificateRefs => new List<CertificateRef>(SignerInformation.UnsignedAttributes.GetEtsCertificateRefs());
        
        public virtual IList<CRLRef> AllCRLRefs
        {
            get
            {
                var list = (CRLRefs as List<CRLRef>)!;

                foreach (var tst in AllTimestampTokens)
                {
                    list.AddRange(tst.GetTimeStamp().UnsignedAttributes?.GetEtsCrlRefs() ?? new List<CRLRef>());
                }
                return list;
            }
        }

        public virtual IList<CRLRef> CRLRefs => new List<CRLRef>(SignerInformation.UnsignedAttributes.GetEtsCrlRefs());

        public virtual IList<OCSPRef> AllOCSPRefs
        {
            get
            {
                var list =(OCSPRefs as List<OCSPRef>)!; 

                foreach (var tst in AllTimestampTokens)
                {
                    list.AddRange(tst.GetTimeStamp().UnsignedAttributes?.GetEtsOcspRefs() ?? new List<OCSPRef>());
                }
                return list;
            }
        }
        
        public virtual IList<OCSPRef> OCSPRefs => new List<OCSPRef>(SignerInformation.UnsignedAttributes.GetEtsOcspRefs());

        public virtual IList<X509Crl> AllCRLs => ((CAdESCRLSource)CRLSource).GetCRLsFromSignature(true);
        
        public virtual IList<X509Crl> CRLs => ((CAdESCRLSource)CRLSource).GetCRLsFromSignature(false);

        public virtual IList<BasicOcspResp> AllOCSPs => ((CAdESOCSPSource)OCSPSource).GetOCSPResponsesFromSignature(true);
        
        public virtual IList<BasicOcspResp> OCSPs => ((CAdESOCSPSource)OCSPSource).GetOCSPResponsesFromSignature(false);

        public virtual byte[] SignatureTimestampData => SignerInformation.GetSignature();

        public virtual byte[] TimestampX1Data
        {
            get
            {
                var toTimestamp = new MemoryStream();
                toTimestamp.Write(SignerInformation.GetSignature());
                Org.BouncyCastle.Asn1.Cms.Attribute attr;
                // TODO: if there more than one ts? Index prop of unsignedAttributes return only one. Consider OrderedAttributeTable, which work with SignerInfo.UnauthenticatedAttributes
                if (SignerInformation.UnsignedAttributes != null && (attr = SignerInformation.UnsignedAttributes[PkcsObjectIdentifiers.IdAASignatureTimeStampToken]) != null)
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
                
                if (SignerInformation.UnsignedAttributes != null)
                {
                    var unsignedAttibutes = SignerInformation.UnsignedAttributes.ToDictionary();

                    if (unsignedAttibutes.Contains(PkcsObjectIdentifiers.IdAAEtsCertificateRefs))
                    {
                        var attrCertRefs = SignerInformation.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertificateRefs];
                        if (attrCertRefs != null)
                        {
                            toTimestamp.Write(attrCertRefs.AttrType.GetDerEncoded());
                            toTimestamp.Write(attrCertRefs.AttrValues.GetDerEncoded());
                        }
                    }

                    if (unsignedAttibutes.Contains(PkcsObjectIdentifiers.IdAAEtsRevocationRefs))
                    {
                        var attrRevocCertRefs = SignerInformation.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationRefs];
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

        public IList<TimestampToken> AllTimestampTokens => SignerInformation.GetAllTimestampTokens();

        public CmsSignedData CmsSignedData
        {
            get
            {
                return this._cmsSignedData;
            }
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
    }
}
