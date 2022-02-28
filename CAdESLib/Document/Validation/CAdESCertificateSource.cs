using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;

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

            var signers = cms.GetSignerInfos().GetSigners().GetEnumerator();
            signers.MoveNext();

            cmsSignedData = cms;
            signerId = ((SignerInformation)signers.Current).SignerID;
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
            IList<X509Certificate> list = new List<X509Certificate>();

            if (!onlyExtended)
            {
                logger.Info(cmsSignedData.GetCertificates("Collection").GetMatches(null).Count + " certificate in collection");
                foreach (X509Certificate ch in cmsSignedData.GetCertificates("Collection").GetMatches(null))
                {
                    X509Certificate c = ch;
                    logger.Info("Certificate for subject " + c.SubjectDN);
                    if (!list.Contains(c))
                    {
                        list.Add(c);
                    }
                }
            }
            // Add certificates in CAdES-XL certificate-values inside SignerInfo attribute if present
            SignerInformation si = BCStaticHelpers.GetSigner(cmsSignedData, signerId);
            if (si != null && si.UnsignedAttributes != null && si.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertValues] != null)
            {
                DerSequence seq = (DerSequence)si.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertValues].AttrValues[0];
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
    }
}
