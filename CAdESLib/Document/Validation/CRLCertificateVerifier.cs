using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using NLog;
using System.IO;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Verifier based on CRL
    /// </summary>
    public class CRLCertificateVerifier : ICertificateStatusVerifier
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private readonly ICrlSource crlSource;

        /// <summary>
        /// Main constructor.
        /// </summary>
        /// <param>
        /// the CRL repository used by this CRL trust linker.
        /// </param>
        public CRLCertificateVerifier(ICrlSource crlSource)
        {
            this.crlSource = crlSource;
        }

        public virtual CertificateStatus Check(X509Certificate childCertificate, X509Certificate certificate, DateTime validationDate)
        {
            try
            {
                CertificateStatus report = new CertificateStatus
                {
                    Certificate = childCertificate,
                    ValidationDate = validationDate,
                    IssuerCertificate = certificate
                };
                if (crlSource == null)
                {
                    logger.Warn("CRLSource null");
                    return null;
                }
                X509Crl x509crl = crlSource.FindCrl(childCertificate, certificate);
                if (x509crl == null)
                {
                    logger.Info("No CRL found for certificate " + childCertificate.SubjectDN);
                    return null;
                }
                if (!IsCRLValid(x509crl, certificate, validationDate))
                {
                    logger.Warn("The CRL is not valid !");
                    return null;
                }
                report.StatusSource = x509crl;
                report.Validity = CertificateValidity.UNKNOWN;
                report.Certificate = childCertificate;
                report.StatusSourceType = ValidatorSourceType.CRL;
                report.ValidationDate = validationDate;
                X509CrlEntry crlEntry = x509crl.GetRevokedCertificate(childCertificate.SerialNumber);
                if (null == crlEntry)
                {
                    logger.Info("CRL OK for: " + childCertificate.SubjectDN);
                    report.Validity = CertificateValidity.VALID;
                }
                else
                {
                    if (crlEntry.RevocationDate.CompareTo(validationDate) > 0) //jbonilla - After
                    {
                        logger.Info("CRL OK for: " + childCertificate.SubjectDN + " at " + validationDate);
                        report.Validity = CertificateValidity.VALID;
                        report.RevocationObjectIssuingTime = x509crl.ThisUpdate;
                    }
                    else
                    {
                        logger.Info("CRL reports certificate: " + childCertificate.SubjectDN
                             + " as revoked since " + crlEntry.RevocationDate);
                        report.Validity = CertificateValidity.REVOKED;
                        report.RevocationObjectIssuingTime = x509crl.ThisUpdate;
                        report.RevocationDate = crlEntry.RevocationDate;
                    }
                }
                return report;
            }
            catch (IOException e)
            {
                logger.Error("IOException when accessing CRL for " + childCertificate.SubjectDN.ToString() + " " + e.Message);
                return null;
            }
        }

        private bool IsCRLValid(X509Crl x509crl, X509Certificate issuerCertificate, DateTime
             validationDate)
        {
            if (!IsCRLOK(x509crl, issuerCertificate, validationDate))
            {
                return false;
            }
            else
            {
                logger.Info("CRL number: " + GetCrlNumber(x509crl));
                return true;
            }
        }

        private bool IsCRLOK(X509Crl x509crl, X509Certificate issuerCertificate, DateTime
             validationDate)
        {
            if (issuerCertificate == null)
            {
                throw new ArgumentNullException("Must provide a issuer certificate to validate the signature");
            }
            if (!x509crl.IssuerDN.Equals(issuerCertificate.SubjectDN))
            {
                logger.Warn("The CRL must be signed by the issuer (" + issuerCertificate.SubjectDN
                    + " ) but instead is signed by " + x509crl.IssuerDN);
                return false;
            }
            try
            {
                x509crl.Verify(issuerCertificate.GetPublicKey());
            }
            catch (Exception e)
            {
                logger.Warn("The signature verification for CRL cannot be performed : " + e.Message);
                return false;
            }
            DateTime thisUpdate = x509crl.ThisUpdate;
            logger.Info("validation date: " + validationDate);
            logger.Info("CRL this update: " + thisUpdate);
            //        if (thisUpdate.after(validationDate)) {
            //            logger.warning("CRL too young");
            //            return false;
            //        }
            logger.Info("CRL next update: " + x509crl.NextUpdate);
            if (x509crl.NextUpdate != null && validationDate.CompareTo(x509crl.NextUpdate.Value) > 0) //jbonilla After
            {
                logger.Info("CRL too old");
                return false;
            }
            // assert cRLSign KeyUsage bit
            if (null == issuerCertificate.GetKeyUsage())
            {
                logger.Warn("No KeyUsage extension for CRL issuing certificate");
                return false;
            }
            if (false == issuerCertificate.GetKeyUsage()[6])
            {
                logger.Warn("cRLSign bit not set for CRL issuing certificate");
                return false;
            }
            return true;
        }

        private BigInteger GetCrlNumber(X509Crl crl)
        {
            //byte[] crlNumberExtensionValue = crl.GetExtensionValue(X509Extensions.CrlNumber);
            Asn1OctetString crlNumberExtensionValue = crl.GetExtensionValue(X509Extensions.CrlNumber);
            if (null == crlNumberExtensionValue)
            {
                return null;
            }
            //try
            //{
            //DerOctetString octetString = (DerOctetString)(new ASN1InputStream(new ByteArrayInputStream
            //    (crlNumberExtensionValue)).ReadObject());
            DerOctetString octetString = (DerOctetString)crlNumberExtensionValue;
            byte[] octets = octetString.GetOctets();
            DerInteger integer = (DerInteger)new Asn1InputStream(octets).ReadObject();
            BigInteger crlNumber = integer.PositiveValue;
            return crlNumber;
            //}
            //catch (IOException e)
            //{
            //    throw new RuntimeException("IO error: " + e.Message, e);
            //}
        }
    }
}
