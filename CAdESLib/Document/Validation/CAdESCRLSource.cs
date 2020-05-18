using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using CAdESLib.Helpers;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// CRLSource that retrieve information from a CAdES signature
    /// </summary>
    public class CAdESCRLSource : SignatureCRLSource
    {
        private readonly CmsSignedData cmsSignedData;

        private readonly SignerID signerId;

        public CAdESCRLSource(byte[] encodedCMS) : this(new CmsSignedData(encodedCMS))
        {
        }

        public CAdESCRLSource(CmsSignedData cms)
        {
            var signers = cms.GetSignerInfos().GetSigners().GetEnumerator();
            signers.MoveNext();

            cmsSignedData = cms;
            signerId = ((SignerInformation)signers.Current).SignerID;
        }

        public CAdESCRLSource(CmsSignedData cms, SignerID id)
        {
            cmsSignedData = cms;
            signerId = id;
        }

        public override IList<X509Crl> GetCRLsFromSignature()
        {
            IList<X509Crl> list = new List<X509Crl>();

            // Add certificates contained in SignedData
            foreach (X509Crl crl in cmsSignedData.GetCrls
                ("Collection").GetMatches(null))
            {
                list.Add(crl);
            }
            // Add certificates in CAdES-XL certificate-values inside SignerInfo attribute if present
            SignerInformation si = BCStaticHelpers.GetSigner(cmsSignedData, signerId);
            if (si != null && si.UnsignedAttributes != null && si.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationValues] != null)
            {
                RevocationValues revValues = RevocationValues.GetInstance(si.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationValues].AttrValues[0]);
                foreach (CertificateList crlObj in revValues.GetCrlVals())
                {
                    X509Crl crl = new X509Crl(crlObj);
                    list.Add(crl);
                }
            }

            return list;
        }
    }
}
