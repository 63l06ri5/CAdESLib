using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;
using System.Linq;
using Org.BouncyCastle.Ocsp;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Verifier based on CRL
    /// </summary>
    public class CRLCertificateVerifier : ICertificateStatusVerifier
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        private readonly ICrlSource? crlSource;

        /// <summary>
        /// Main constructor.
        /// </summary>
        /// <param>
        /// the CRL repository used by this CRL trust linker.
        /// </param>
        public CRLCertificateVerifier(ICrlSource? crlSource)
        {
            this.crlSource = crlSource;
        }

        public virtual CertificateStatus? Check(X509Certificate childCertificate, X509Certificate? certificate, DateTime startDate, DateTime endDate)
        {
            try
            {
                if (certificate is null)
                {
                    nloglogger.Warn("Issuer certificate is null");
                    return null;
                }

                CertificateStatus report = new CertificateStatus
                {
                    Certificate = childCertificate,
                    StartDate = startDate,
                    EndDate = endDate,
                    IssuerCertificate = certificate
                };
                if (crlSource == null)
                {
                    nloglogger.Warn("CRLSource null");
                    return null;
                }
                var x509crl = GetX509Crl(childCertificate, certificate, startDate, endDate);

                return VerifyValue(report, x509crl, childCertificate, certificate, startDate, endDate);

            }
            catch (IOException e)
            {
                nloglogger.Error($"IOException when accessing CRL for {childCertificate.SubjectDN},serial={childCertificate.SerialNumber.ToString(16)}  {e.Message}");
                return null;
            }
        }

        private X509Crl? GetX509Crl(X509Certificate childCertificate, X509Certificate certificate, DateTime startDate, DateTime endDate)
        {
            if (crlSource != null)
            {
                var crls = crlSource.FindCrls(childCertificate, certificate, startDate, endDate);

                foreach (var crl in crls)
                {
                    if (crl == null)
                    {
                        continue;
                    }
                    if (IsCRLValid(crl, certificate, startDate, endDate))
                    {
                        return crl;
                    }
                }
                return crls.FirstOrDefault();
            }

            return null;
        }

        private bool IsCRLValid(X509Crl x509crl, X509Certificate issuerCertificate, DateTime startDate, DateTime endDate)
        {
            if (!IsCRLOK(x509crl, issuerCertificate, startDate, endDate))
            {
                return false;
            }
            else
            {
                nloglogger.Trace("CRL number: " + GetCrlNumber(x509crl));
                return true;
            }
        }

        private bool IsCRLOK(X509Crl x509crl, X509Certificate issuerCertificate, DateTime startDate, DateTime endDate)
        {
            if (issuerCertificate == null)
            {
                throw new ArgumentNullException("Must provide a issuer certificate to validate the signature");
            }
            if (!x509crl.IssuerDN.Equals(issuerCertificate.SubjectDN))
            {
                nloglogger.Warn($"The CRL must be signed by the issuer ({issuerCertificate.SubjectDN},serial={issuerCertificate.SerialNumber.ToString(16)}) but instead is signed by {x509crl.IssuerDN}");
                return false;
            }
            try
            {
                x509crl.Verify(issuerCertificate.GetPublicKey());
            }
            catch (Exception e)
            {
                nloglogger.Warn("The signature verification for CRL cannot be performed : " + e.Message);
                return false;
            }
            DateTime thisUpdate = x509crl.ThisUpdate;
            nloglogger.Trace($"startDate={startDate}, endDate={endDate}");
            nloglogger.Trace("CRL this update: " + thisUpdate);
            nloglogger.Trace("CRL next update: " + x509crl.NextUpdate);
            if (!x509crl.IsValid(startDate, endDate))
            {
                nloglogger.Trace("CRL not valid");
                return false;
            }

            // assert cRLSign KeyUsage bit
            if (null == issuerCertificate.GetKeyUsage())
            {
                nloglogger.Warn("No KeyUsage extension for CRL issuing certificate");
                return false;
            }
            if (false == issuerCertificate.GetKeyUsage()[6])
            {
                nloglogger.Warn("cRLSign bit not set for CRL issuing certificate");
                return false;
            }
            return true;
        }

        private BigInteger? GetCrlNumber(X509Crl crl)
        {
            Asn1OctetString crlNumberExtensionValue = crl.GetExtensionValue(X509Extensions.CrlNumber);
            if (null == crlNumberExtensionValue)
            {
                return null;
            }
            DerOctetString octetString = (DerOctetString)crlNumberExtensionValue;
            byte[] octets = octetString.GetOctets();
            DerInteger integer = (DerInteger)new Asn1InputStream(octets).ReadObject();
            BigInteger crlNumber = integer.PositiveValue;
            return crlNumber;
        }
        public CertificateStatus? VerifyValue(
                CertificateStatus status,
                BasicOcspResp? ocspResp,
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate)
        {
            throw new NotImplementedException();
        }

        public CertificateStatus? VerifyValue(
                CertificateStatus report,
                X509Crl? x509crl,
                X509Certificate childCertificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate)
        {
            if (x509crl is null)
            {
                nloglogger.Info($"No CRL found for certificate {childCertificate.SubjectDN},serial={childCertificate.SerialNumber.ToString(16)}");
                return null;
            }

            report.StatusSource = new StatusSource(x509crl);
            report.Validity = CertificateValidity.UNKNOWN;
            report.StatusSourceType = ValidatorSourceType.CRL;
            if (!x509crl.IsValid(startDate, endDate))
            {
                nloglogger.Error($"not valid: validationPeriod={startDate}-{endDate}, thisUpdate={x509crl.ThisUpdate}, nextUpdate={x509crl.NextUpdate}");
                report.Validity = CertificateValidity.UNKNOWN;
            }
            else
            {
                X509CrlEntry crlEntry = x509crl.GetRevokedCertificate(childCertificate.SerialNumber);
                if (null == crlEntry)
                {
                    nloglogger.Trace($"CRL OK for:  {childCertificate.SubjectDN},serial={childCertificate.SerialNumber.ToString(16)}");
                    report.Validity = CertificateValidity.VALID;
                }
                else
                {
                    if (crlEntry.RevocationDate.CompareTo(startDate) > 0)
                    {
                        nloglogger.Trace($"CRL OK for: {childCertificate.SubjectDN},serial={childCertificate.SerialNumber.ToString(16)} at startDate={startDate}");
                        report.Validity = CertificateValidity.VALID;
                        report.RevocationObjectIssuingTime = x509crl.ThisUpdate;
                    }
                    else
                    {
                        nloglogger.Trace($"CRL reports certificate: {childCertificate.SubjectDN},serial={childCertificate.SerialNumber.ToString(16)} as revoked since {crlEntry.RevocationDate}");
                        report.Validity = CertificateValidity.REVOKED;
                        report.RevocationObjectIssuingTime = x509crl.ThisUpdate;
                        report.RevocationDate = crlEntry.RevocationDate;
                    }
                }
            }
            return report;
        }
    }
}
