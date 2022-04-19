using CAdESLib.Helpers;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using System.Collections.Generic;
using System.Linq;

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
            signerId = ((SignerInformation) signers.Current).SignerID;
        }

        public CAdESOCSPSource(CmsSignedData cms, SignerID id)
        {
            cmsSignedData = cms;
            signerId = id;
        }

        public override IList<BasicOcspResp> GetOCSPResponsesFromSignature()
        {
            // Add certificates in CAdES-XL certificate-values inside SignerInfo attribute if present
            SignerInformation si = BCStaticHelpers.GetSigner(cmsSignedData, signerId);
            var list = si?.UnsignedAttributes.GetOcspReps()?.ToList() ?? new List<BasicOcspResp>();

            if (si != null)
            {
                foreach (var tst in si.GetAllTimestampTokens())
                {
                    list.AddRange(tst.GetTimeStamp().UnsignedAttributes?.GetOcspReps() ?? new List<BasicOcspResp>());
                }
            }

            return list;
        }
    }
}
