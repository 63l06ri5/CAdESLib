using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
namespace CAdESLib.Document.Validation
{
    // <summary>SignedToken containing a TimeStamp.</summary>
    public class TimestampToken : ISignedToken
    {
        /// <summary>
        /// Source of the timestamp
        /// <p>
        /// DISCLAIMER: Project owner DG-MARKT.
        /// </summary>
        /// <remarks>
        /// Source of the timestamp
        /// <p>
        /// DISCLAIMER: Project owner DG-MARKT.
        /// </remarks>
        /// <author><a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
        /// 	</author>
        public enum TimestampType
        {
            CONTENT_TIMESTAMP,
            INDIVIDUAL_CONTENT_TIMESTAMP,
            SIGNATURE_TIMESTAMP,
            VALIDATION_DATA_REFSONLY_TIMESTAMP,
            VALIDATION_DATA_TIMESTAMP,
            ARCHIVE_TIMESTAMP
        }

        private readonly TimeStampToken timeStamp;

        private readonly TimestampToken.TimestampType timeStampType;

        public TimestampToken(TimeStampToken timeStamp)
        {
            // CAdES: id-aa-ets-contentTimestamp, XAdES: AllDataObjectsTimeStamp, PAdES standard
            // timestamp
            // XAdES: IndividualDataObjectsTimeStamp
            // CAdES: id-aa-signatureTimeStampToken, XAdES: SignatureTimeStamp
            // CAdES: id-aa-ets-certCRLTimestamp, XAdES: RefsOnlyTimeStamp
            // CAdES: id-aa-ets-escTimeStamp, XAdES: SigAndRefsTimeStamp
            // CAdES: id-aa-ets-archiveTimestamp, XAdES: ArchiveTimeStamp, PAdES-LTV "document timestamp"
            this.timeStamp = timeStamp;
        }

        /// <summary>
        /// Constructor with an indication of the time-stamp type The default constructor for TimestampToken.
        /// </summary>
        public TimestampToken(TimeStampToken timeStamp, TimestampToken.TimestampType type)
        {
            this.timeStamp = timeStamp;
            timeStampType = type;
        }

        public virtual X509Name GetSignerSubjectName()
        {
            ICollection<X509Certificate> certs = ((CAdESCertificateSource)GetWrappedCertificateSource()).GetCertificates
                ();
            foreach (X509Certificate cert in certs)
            {
                if (timeStamp.SignerID.Match(cert))
                {
                    return cert.SubjectDN;
                }
            }
            return null;
        }

        public virtual X509Certificate GetSigner()
        {
            ICollection<X509Certificate> certs = ((CAdESCertificateSource)GetWrappedCertificateSource()).GetCertificates();
            foreach (X509Certificate cert in certs)
            {
                if (timeStamp.SignerID.Match(cert))
                {
                    return cert;
                }
            }
            return null;
        }

        public virtual bool IsSignedBy(X509Certificate potentialIssuer)
        {
            try
            {
                //timeStamp.Validate(potentialIssuer, "BC");
                timeStamp.Validate(potentialIssuer);
                return true;
            }
            catch (CertificateExpiredException)
            {
                return false;
            }
            catch (CertificateNotYetValidException)
            {
                return false;
            }
            catch (TspValidationException)
            {
                return false;
            }
            /*catch (NoSuchProviderException e)
			{
				throw new RuntimeException(e);
			}*/
            catch (TspException)
            {
                return false;
            }
        }

        public virtual ICertificateSource GetWrappedCertificateSource()
        {
            return new CAdESCertificateSource(timeStamp.ToCmsSignedData());
        }

        /// <returns>
        /// the timeStampType
        /// </returns>
        public virtual TimestampToken.TimestampType GetTimeStampType()
        {
            return timeStampType;
        }

        /// <returns>
        /// the timeStamp token
        /// </returns>
        public virtual TimeStampToken GetTimeStamp()
        {
            return timeStamp;
        }

        /// <summary>
        /// Check if the TimeStampToken matches the data
        /// </summary>
        /// <returns>
        /// true if the data are verified by the TimeStampToken
        /// </returns>
        public virtual bool MatchData(byte[] data)
        {
            string hashAlgorithm = timeStamp.TimeStampInfo.HashAlgorithm.Algorithm.Id;
            byte[] computedDigest = DigestUtilities.CalculateDigest(hashAlgorithm, data);
            return computedDigest.SequenceEqual(timeStamp.TimeStampInfo.GetMessageImprintDigest());
        }

        /// <summary>
        /// Retrieve the timestamp generation date
        /// </summary>
        public virtual DateTime GetGenTimeDate()
        {
            return timeStamp.TimeStampInfo.GenTime;
        }
    }
}
