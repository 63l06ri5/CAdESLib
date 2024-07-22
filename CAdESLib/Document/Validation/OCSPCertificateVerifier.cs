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

        public virtual CertificateStatus? Check(X509Certificate certificate, X509Certificate? issuerCertificate, DateTime validationDate)
        {
            if (issuerCertificate is null)
            {
                throw new ArgumentNullException(nameof(issuerCertificate));
            }

            var status = new CertificateStatus
            {
                Certificate = certificate,
                ValidationDate = validationDate,
                IssuerCertificate = issuerCertificate
            };

            var ocspNoCheck = certificate.GetExtensionValue(X509Consts.OCSPNoCheck);
            if (ocspNoCheck != null && certificate.GetExtendedKeyUsage().Contains(Org.BouncyCastle.Asn1.X509.KeyPurposeID.IdKPOcspSigning.Id))
            {
                logger.Trace("OCSPNoCheck");
                status.StatusSourceType = ValidatorSourceType.OCSP_NO_CHECK;
                status.Validity = CertificateValidity.VALID;
                return status;
            }


            if (ocspSource == null)
            {
                logger.Warn("OCSPSource null");
                return null;
            }
            try
            {
                var ocspResp = ocspSource.GetOcspResponse(certificate, issuerCertificate);
                if (null == ocspResp)
                {
                    logger.Trace("OCSP response not found");
                    return null;
                }
                BasicOcspResp basicOCSPResp = ocspResp;
                SingleResp[] singleResps = basicOCSPResp.Responses;
                foreach (SingleResp singleResp in singleResps)
                {
                    CertificateID responseCertificateId = singleResp.GetCertID();
                    CertificateID certificateId = new CertificateID(responseCertificateId.HashAlgOid, issuerCertificate, certificate.SerialNumber);

                    if (!certificateId.EqualsWithDerNull(responseCertificateId))
                    {
                        continue;
                    }
                    DateTime thisUpdate = singleResp.ThisUpdate;
                    logger.Trace("OCSP thisUpdate: " + thisUpdate);
                    logger.Trace("OCSP nextUpdate: " + singleResp.NextUpdate);
                    status.StatusSourceType = ValidatorSourceType.OCSP;
                    status.StatusSource = ocspResp;
                    status.RevocationObjectIssuingTime = ocspResp.ProducedAt;
                    if (null == singleResp.GetCertStatus())
                    {
                        logger.Trace("OCSP OK for: " + certificate.SubjectDN);
                        status.Validity = CertificateValidity.VALID;
                    }
                    else
                    {
                        logger.Trace("OCSP certificate status: " + singleResp.GetCertStatus().GetType().FullName);
                        if (singleResp.GetCertStatus() is RevokedStatus status1)
                        {
                            logger.Trace("OCSP status revoked");
                            if (validationDate.CompareTo(status1.RevocationTime) < 0)
                            {
                                logger.Trace("OCSP revocation time after the validation date, the certificate was valid at "
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
                                logger.Trace("OCSP status unknown");
                                status.Validity = CertificateValidity.UNKNOWN;
                            }
                        }
                    }
                    return status;
                }
                logger.Trace("no matching OCSP response entry");
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
