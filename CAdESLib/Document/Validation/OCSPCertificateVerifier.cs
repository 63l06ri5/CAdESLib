using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;
using System.IO;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Check the status of the certificate using an OCSPSource
    /// </summary>
    public class OCSPCertificateVerifier : ICertificateStatusVerifier
    {
        private static readonly DerObjectIdentifier OCSPNoCheck = new DerObjectIdentifier("1.3.6.1.5.5.7.48.1.5");
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
            var ocspNoCheck = childCertificate.GetExtensionValue(OCSPNoCheck);
            if (ocspNoCheck != null)
            {
                logger.Info("OCSPNoCheck null");
                return null;
            }

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
                SingleResp[] singleResps = basicOCSPResp.Responses;
                foreach (SingleResp singleResp in singleResps)
                {
                    CertificateID responseCertificateId = singleResp.GetCertID();
                    CertificateID certificateId = new CertificateID(responseCertificateId.HashAlgOid, certificate, childCertificate.SerialNumber);

                    if (!certificateId.EqualsWithDerNull(responseCertificateId))
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
                        if (singleResp.GetCertStatus() is RevokedStatus status1)
                        {
                            logger.Info("OCSP status revoked");
                            if (validationDate.CompareTo(status1.RevocationTime) < 0)
                            {
                                logger.Info("OCSP revocation time after the validation date, the certificate was valid at "
                                     + validationDate);
                                status.Validity = CertificateValidity.VALID;
                            }
                            else
                            {
                                status.RevocationDate = status1.RevocationTime;
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
