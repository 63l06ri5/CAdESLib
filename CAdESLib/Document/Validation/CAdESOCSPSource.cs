using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using CAdESLib.Helpers;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// OCSPSource that retrieve information from a CAdESSignature.
    /// </summary>
    public class CAdESOCSPSource : SignatureOCSPSource
    {
        private readonly CmsSignedData cmsSignedData;

        private readonly SignerID signerId;

        public CAdESOCSPSource(byte[] encodedCMS) : this(new CmsSignedData(encodedCMS))
        {
        }

        public CAdESOCSPSource(CmsSignedData cms)
        {
            var signers = cms.GetSignerInfos().GetSigners().GetEnumerator();
            signers.MoveNext();

            cmsSignedData = cms;
            signerId = ((SignerInformation)signers.Current).SignerID;
        }

        public CAdESOCSPSource(CmsSignedData cms, SignerID id)
        {
            cmsSignedData = cms;
            signerId = id;
        }

        public override IList<BasicOcspResp> GetOCSPResponsesFromSignature()
        {
            IList<BasicOcspResp> list = new List<BasicOcspResp>();
            // Add certificates in CAdES-XL certificate-values inside SignerInfo attribute if present
            SignerInformation si = BCStaticHelpers.GetSigner(cmsSignedData, signerId);
            if (si != null && si.UnsignedAttributes != null && si.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationValues] != null)
            {
                RevocationValues revValues = RevocationValues.GetInstance(si.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationValues].AttrValues[0]);
                foreach (BasicOcspResponse ocspObj in revValues.GetOcspVals())
                {
                    BasicOcspResp bOcspObj = new BasicOcspResp(ocspObj);
                    list.Add(bOcspObj);
                }
            }
            return list;
        }
    }
}
