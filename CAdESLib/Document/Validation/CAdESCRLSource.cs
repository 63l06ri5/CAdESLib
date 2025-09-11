using CAdESLib.Helpers;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using System;
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
            var signerInformation = cms.GetSignerInfos().GetSigners().OfType<SignerInformation>().FirstOrDefault();
            if (signerInformation is null)
            {
                throw new ArgumentNullException(nameof(signerInformation));
            }

            cmsSignedData = cms;
            signerId = signerInformation.SignerID;
        }

        public CAdESCRLSource(CmsSignedData cms, SignerID id)
        {
            cmsSignedData = cms;
            signerId = id;
        }

        public override IList<X509Crl> GetCRLsFromSignature(bool timestampIncluded)
        {
            var list = new List<X509Crl>();

            // Add certificates in CAdES-XL certificate-values inside SignerInfo attribute if present
            SignerInformation si = BCStaticHelpers.GetSigner(cmsSignedData, signerId);

            if (si != null)
            {
                foreach (var crl in cmsSignedData.GetCrls("Collection")
                                        .GetMatches(null)
                                        .Cast<object>()
                                        .Where(x => x is X509Crl)
                                        .Cast<X509Crl>())
                {
                    list.Add(crl);
                }

                list.AddRange(si?.UnsignedAttributes.GetCrls()?.ToList() ?? new List<X509Crl>());

                if (timestampIncluded)
                {
                    foreach (var tst in si!.GetAllTimestampTokens())
                    {
                        var t = tst.GetTimeStamp();
                        foreach (var crl in t.GetCrls("Collection").GetMatches(null).Cast<X509Crl>())
                        {
                            list.Add(crl);
                        }

                        list.AddRange(t.UnsignedAttributes?.GetCrls() ?? new List<X509Crl>());
                    }
                }
            }

            return list.Distinct().ToList();
        }
    }
}
