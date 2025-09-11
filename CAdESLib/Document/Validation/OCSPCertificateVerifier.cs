using CAdESLib.Helpers;
using NLog;
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
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();
        private readonly IOcspSource? ocspSource;

        /// <summary>
        /// Create a CertificateVerifier that will use the OCSP Source for checking revocation data.
        /// </summary>
        /// <remarks>
        /// Create a CertificateVerifier that will use the OCSP Source for checking revocation data. The default constructor
        /// for OCSPCertificateVerifier.
        /// </remarks>
        public OCSPCertificateVerifier(IOcspSource? ocspSource)
        {
            this.ocspSource = ocspSource;
        }

        public virtual CertificateStatus? Check(
                X509Certificate certificate,
                X509Certificate? issuerCertificate,
                DateTime startDate,
                DateTime endDate)
        {
            if (issuerCertificate is null)
            {
                throw new ArgumentNullException(nameof(issuerCertificate));
            }

            var status = new CertificateStatus
            {
                Certificate = certificate,
                StartDate = startDate,
                EndDate = endDate,
                IssuerCertificate = issuerCertificate
            };

            var ocspNoCheck = certificate.GetExtensionValue(X509Consts.OCSPNoCheck);
            if (ocspNoCheck != null && certificate.GetExtendedKeyUsage().Contains(Org.BouncyCastle.Asn1.X509.KeyPurposeID.IdKPOcspSigning.Id))
            {

                nloglogger.Trace("OCSPNoCheck");
                status.StatusSourceType = ValidatorSourceType.OCSP_NO_CHECK;
                status.Validity = CertificateValidity.VALID;
                return status;
            }


            if (ocspSource == null)
            {
                nloglogger.Warn("OCSPSource null");
                return null;
            }
            try
            {
                foreach (var ocspResp in ocspSource.GetOcspResponse(certificate, issuerCertificate, startDate, endDate))
                {
                    var st = VerifyValue(
                        status,
                        ocspResp,
                        certificate,
                        issuerCertificate,
                        startDate,
                        endDate);

                    if (st is null || st.Validity == CertificateValidity.UNKNOWN)
                    {
                        continue;
                    }
                    return st;
                }

                if (status.Validity == CertificateValidity.UNKNOWN)
                {
                    return status;
                }

                nloglogger.Trace("no matching OCSP response entry");

                return null;
            }
            catch (IOException ex)
            {
                nloglogger.Error("OCSP exception: " + ex.Message);
                return null;
            }
            catch (OcspException ex)
            {
                nloglogger.Error("OCSP exception: " + ex.Message);
                throw;
            }
        }

        public CertificateStatus? VerifyValue(
                CertificateStatus status,
                BasicOcspResp? ocspResp,
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate)
        {
            if (null == ocspResp)
            {
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
                nloglogger.Trace("OCSP thisUpdate: " + thisUpdate);
                nloglogger.Trace("OCSP nextUpdate: " + singleResp.NextUpdate);
                status.StatusSourceType = ValidatorSourceType.OCSP;
                status.StatusSource = new StatusSource(ocspResp);
                status.RevocationObjectIssuingTime = ocspResp.ProducedAt;

                if (ocspResp.ProducedAt.CompareTo(singleResp.ThisUpdate) < 0)
                {
                    nloglogger.Error($"ProducedAt < ThisUpdate, producedAt={ocspResp.ProducedAt}, thisUpdate={singleResp.ThisUpdate}");
                    status.Validity = CertificateValidity.UNKNOWN;
                }
                else if (!ocspResp.IsValid(startDate, endDate))
                {
                    nloglogger.Error($"not valid: validationPeriod={startDate}-{endDate}, producedAt={ocspResp.ProducedAt}, thisUpdate={singleResp.ThisUpdate}, nextUpdate={singleResp.NextUpdate}");
                    status.Validity = CertificateValidity.UNKNOWN;
                }
                else if (null == singleResp.GetCertStatus())
                {
                    nloglogger.Trace("OCSP OK for: " + certificate.SubjectDN);
                    status.StartDate = startDate;
                    status.EndDate = endDate;
                    status.Validity = CertificateValidity.VALID;
                }
                else
                {
                    nloglogger.Trace("OCSP certificate status: " + singleResp.GetCertStatus().GetType().FullName);
                    if (singleResp.GetCertStatus() is RevokedStatus status1)
                    {
                        nloglogger.Trace("OCSP status revoked");
                        if (startDate.CompareTo(status1.RevocationTime) < 0)
                        {
                            nloglogger.Trace("OCSP revocation time after the validation date, the certificate was valid at startDate="
                                 + startDate);
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
                            nloglogger.Trace("OCSP status unknown");
                            status.Validity = CertificateValidity.UNKNOWN;
                        }
                    }
                }
                if (status.Validity is not null && status.Validity != CertificateValidity.UNKNOWN)
                {
                    return status;
                }
            }

            return status;
        }

        public CertificateStatus? VerifyValue(
                CertificateStatus status,
                X509Crl? crl,
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate)
        {
            throw new NotImplementedException();
        }
    }
}
