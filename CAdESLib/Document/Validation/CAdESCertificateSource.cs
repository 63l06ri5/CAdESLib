using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// CertificateSource that retrieve items from a CAdES Signature
    /// </summary>
    public class CAdESCertificateSource : SignatureCertificateSource
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private readonly CmsSignedData cmsSignedData;

        private readonly SignerID signerId;

        private readonly bool onlyExtended = true;

        public CAdESCertificateSource(CmsSignedData cms)
        {
            if (cms is null)
            {
                throw new ArgumentNullException(nameof(cms));
            }

            var signerInformation = cms.GetSignerInfos().GetSigners().OfType<SignerInformation>().FirstOrDefault();
            if (signerInformation is null)
            {
                throw new ArgumentNullException(nameof(signerInformation));
            }

            cmsSignedData = cms;
            signerId = signerInformation.SignerID;
            onlyExtended = false;
        }

        public CAdESCertificateSource(CmsSignedData cms, SignerID id, bool onlyExtended)
        {
            cmsSignedData = cms;
            signerId = id;
            this.onlyExtended = onlyExtended;
        }

        public override IList<X509Certificate> GetCertificates()
        {
            var list = new List<X509Certificate>();

            if (!onlyExtended)
            {
                logger.Trace(cmsSignedData.GetCertificates("Collection").GetMatches(null).Count + " certificate in collection");
                foreach (var ch in cmsSignedData.GetCertificates("Collection").GetMatches(null).Cast<X509Certificate>())
                {
                    X509Certificate c = ch;
                    logger.Trace($"Certificate {c.SubjectDN},{c.SerialNumber.ToString(16)}");
                    if (!list.Contains(c))
                    {
                        list.Add(c);
                    }
                }
            }
            // Add certificates in CAdES-XL certificate-values inside SignerInfo attribute if present
            SignerInformation si = BCStaticHelpers.GetSigner(cmsSignedData, signerId);
            list.AddRange(si?.UnsignedAttributes?.GetEtsCertValues() ?? new List<X509Certificate>());

            return list;
        }
    }
}
