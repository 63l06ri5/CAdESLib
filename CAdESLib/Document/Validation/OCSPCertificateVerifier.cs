﻿using System;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using NLog;
using System.IO;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Check the status of the certificate using an OCSPSource
    /// </summary>
    public class OCSPCertificateVerifier : ICertificateStatusVerifier
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        private readonly IOcspSource ocspSource;

        /// <summary>
        /// Create a CertificateVerifier that will use the OCSP Source for checking revocation data.
        /// </summary>
        /// <remarks>
        /// Create a CertificateVerifier that will use the OCSP Source for checking revocation data. The default constructor
        /// for OCSPCertificateVerifier.
        /// </remarks>
        public OCSPCertificateVerifier(IOcspSource ocspSource)
        {
            this.ocspSource = ocspSource;
        }

        public virtual CertificateStatus Check(X509Certificate childCertificate, X509Certificate certificate, DateTime validationDate)
        {
            CertificateStatus status = new CertificateStatus
            {
                Certificate = childCertificate,
                ValidationDate = validationDate,
                IssuerCertificate = certificate
            };
            if (ocspSource == null)
            {
                logger.Warn("OCSPSource null");
                return null;
            }
            try
            {
                BasicOcspResp ocspResp = ocspSource.GetOcspResponse(childCertificate, certificate);
                if (null == ocspResp)
                {
                    logger.Info("OCSP response not found");
                    return null;
                }
                BasicOcspResp basicOCSPResp = ocspResp;
                CertificateID certificateId = new CertificateID(CertificateID.HashSha1, certificate, childCertificate.SerialNumber);
                SingleResp[] singleResps = basicOCSPResp.Responses;
                foreach (SingleResp singleResp in singleResps)
                {
                    CertificateID responseCertificateId = singleResp.GetCertID();
                    if (!certificateId.Equals(responseCertificateId))
                    {
                        continue;
                    }
                    DateTime thisUpdate = singleResp.ThisUpdate;
                    logger.Info("OCSP thisUpdate: " + thisUpdate);
                    logger.Info("OCSP nextUpdate: " + singleResp.NextUpdate);
                    status.StatusSourceType = ValidatorSourceType.OCSP;
                    status.StatusSource = ocspResp;
                    status.RevocationObjectIssuingTime = ocspResp.ProducedAt;
                    if (null == singleResp.GetCertStatus())
                    {
                        logger.Info("OCSP OK for: " + childCertificate.SubjectDN);
                        status.Validity = CertificateValidity.VALID;
                    }
                    else
                    {
                        logger.Info("OCSP certificate status: " + singleResp.GetCertStatus().GetType().FullName);
                        if (singleResp.GetCertStatus() is RevokedStatus)
                        {
                            logger.Info("OCSP status revoked");
                            if (validationDate.CompareTo(((RevokedStatus)singleResp.GetCertStatus()).RevocationTime) < 0)
                            {
                                logger.Info("OCSP revocation time after the validation date, the certificate was valid at "
                                     + validationDate);
                                status.Validity = CertificateValidity.VALID;
                            }
                            else
                            {
                                status.RevocationDate = ((RevokedStatus)singleResp.GetCertStatus()).RevocationTime;
                                status.Validity = CertificateValidity.REVOKED;
                            }
                        }
                        else
                        {
                            if (singleResp.GetCertStatus() is UnknownStatus)
                            {
                                logger.Info("OCSP status unknown");
                                status.Validity = CertificateValidity.UNKNOWN;
                            }
                        }
                    }
                    return status;
                }
                logger.Info("no matching OCSP response entry");
                return null;
            }
            catch (IOException ex)
            {
                logger.Error("OCSP exception: " + ex.Message);
                return null;
            }
            catch (OcspException ex)
            {
                logger.Error("OCSP exception: " + ex.Message);
                throw;
            }
        }
    }
}
