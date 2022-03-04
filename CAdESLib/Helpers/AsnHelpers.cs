using CAdESLib.Document.Signature;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Text;
namespace CAdESLib.Helpers
{
    public static class AsnHelpers
    {
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

            if (!(asnCertificateID.HashAlgorithm?.Equals(asnOtherCertificateID.HashAlgorithm) ?? false))
            {
                if (asnCertificateID.HashAlgorithm != asnOtherCertificateID.HashAlgorithm)
                {
                    if (asnCertificateID.HashAlgorithm == null)
                    {
                        return false;
                    }

                    if (!(asnCertificateID.HashAlgorithm.Algorithm?.Equals(asnOtherCertificateID.HashAlgorithm.Algorithm) ?? false))
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

            if (!(asnCertificateID.IssuerKeyHash?.Equals(asnOtherCertificateID.IssuerKeyHash) ?? false))
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

                        otherCertId.OtherCertHash.GetHashValue();

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

            return list;
        }

        public static IList<CRLRef> GetEtsCrlRefs(this Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttributes)
        {
            var list = new List<CRLRef>();
            if (unsignedAttributes != null)
            {
                var completeRevocationRefsAttr = unsignedAttributes
                    [PkcsObjectIdentifiers.IdAAEtsRevocationRefs];
                if (completeRevocationRefsAttr != null && completeRevocationRefsAttr.AttrValues
                    .Count > 0)
                {
                    DerSequence completeCertificateRefs = (DerSequence)completeRevocationRefsAttr.AttrValues[0];
                    for (int i1 = 0; i1 < completeCertificateRefs.Count; i1++)
                    {
                        CrlOcspRef otherCertId = CrlOcspRef.GetInstance(completeCertificateRefs[i1]);
                        if (otherCertId.CrlIDs != null)
                        {
                            foreach (CrlValidatedID id in otherCertId.CrlIDs.GetCrls())
                            {
                                list.Add(new CRLRef(id));
                            }
                        }
                    }
                }
            }

            return list;
        }

        public static IList<OCSPRef> GetEtsOcspRefs(this Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttributes)
        {
            var list = new List<OCSPRef>();
            if (unsignedAttributes != null)
            {
                var completeRevocationRefsAttr = unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationRefs];
                if (completeRevocationRefsAttr != null && completeRevocationRefsAttr.AttrValues
                    .Count > 0)
                {
                    DerSequence completeRevocationRefs = (DerSequence)completeRevocationRefsAttr.AttrValues[0];
                    for (int i1 = 0; i1 < completeRevocationRefs.Count; i1++)
                    {
                        CrlOcspRef otherCertId = CrlOcspRef.GetInstance(completeRevocationRefs[i1]);
                        if (otherCertId.OcspIDs != null)
                        {
                            foreach (OcspResponsesID id in otherCertId.OcspIDs.GetOcspResponses())
                            {
                                list.Add(new OCSPRef(id, true));
                            }
                        }
                    }
                }
            }

            return list;
        }
    }
}
