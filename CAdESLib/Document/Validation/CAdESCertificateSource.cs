using CAdESLib.Helpers;
using NLog;
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
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

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

        public override IList<X509Certificate> GetCertificates(bool timestampIncluded)
        {
            return cmsSignedData.GetCertificates(signerId, timestampIncluded);
        }
    }
}
