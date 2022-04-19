using CAdESLib.Helpers;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System.Linq;

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
            signerId = ((SignerInformation) signers.Current).SignerID;
        }

        public CAdESCRLSource(CmsSignedData cms, SignerID id)
        {
            cmsSignedData = cms;
            signerId = id;
        }

        public override IList<X509Crl> GetCRLsFromSignature()
        {
            var list = new List<X509Crl>();

            // Add certificates in CAdES-XL certificate-values inside SignerInfo attribute if present
            SignerInformation si = BCStaticHelpers.GetSigner(cmsSignedData, signerId);

            if (si != null)
            {
                var unsignedAttributes = si?.UnsignedAttributes;
                foreach (X509Crl crl in cmsSignedData.GetCrls("Collection").GetMatches(null))
                {
                    list.Add(crl);
                }

                list.AddRange(si?.UnsignedAttributes.GetCrls()?.ToList() ?? new List<X509Crl>());

                foreach (var tst in si.GetAllTimestampTokens())
                {
                    var t = tst.GetTimeStamp();
                    foreach (X509Crl crl in t.GetCrls("Collection").GetMatches(null))
                    {
                        list.Add(crl);
                    }

                    list.AddRange(t.UnsignedAttributes?.GetCrls() ?? new List<X509Crl>());
                }
            }

            return list;
        }
    }
}
