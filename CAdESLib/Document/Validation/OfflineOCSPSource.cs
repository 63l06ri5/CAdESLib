﻿using System;
using System.Collections.Generic;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using NLog;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Abstract class that helps to implements OCSPSource with a already loaded list of BasicOCSPResp
    /// </summary>
    public abstract class OfflineOCSPSource : IOcspSource
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public BasicOcspResp GetOcspResponse(X509Certificate certificate, X509Certificate
             issuerCertificate)
        {
            logger.Info("find OCSP response");
            try
            {
                foreach (BasicOcspResp basicOCSPResp in GetOCSPResponsesFromSignature())
                {
                    CertificateID certId = new CertificateID(CertificateID.HashSha1, issuerCertificate, certificate.SerialNumber);
                    foreach (SingleResp singleResp in basicOCSPResp.Responses)
                    {
                        if (singleResp.GetCertID().Equals(certId))
                        {
                            logger.Info("OCSP response found");
                            return basicOCSPResp;
                        }
                    }
                }
                OcspNotFound(certificate, issuerCertificate);
                return null;
            }
            catch (OcspException e)
            {
                logger.Error("OcspException: " + e.Message);
                return null;
            }
        }

        /// <summary>
        /// Callback used when the OCSP is not found.
        /// </summary>
        public virtual void OcspNotFound(X509Certificate certificate, X509Certificate issuerCertificate)
        {
        }

        /// <summary>
        /// Retrieve the list of BasicOCSPResp contained in the Signature.
        /// </summary>
        public abstract IList<BasicOcspResp> GetOCSPResponsesFromSignature();
    }
}
