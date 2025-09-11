using CAdESLib.Document.Signature;
using CAdESLib.Helpers;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
namespace CAdESLib.Document.Validation
{
    // <summary>SignedToken containing a TimeStamp.</summary>
    public class TimestampToken : ISignedToken, ICertsAndVals
    {
        private readonly TimeStampToken timeStamp;

        public List<object?> RootCause { get; } = new List<object?>();

        public TimestampToken(TimeStampToken timeStamp, object? rootCause = null)
        {
            // CAdES: id-aa-ets-contentTimestamp, XAdES: AllDataObjectsTimeStamp, PAdES standard
            // timestamp
            // XAdES: IndividualDataObjectsTimeStamp
            // CAdES: id-aa-signatureTimeStampToken, XAdES: SignatureTimeStamp
            // CAdES: id-aa-ets-certCRLTimestamp, XAdES: RefsOnlyTimeStamp
            // CAdES: id-aa-ets-escTimeStamp, XAdES: SigAndRefsTimeStamp
            // CAdES: id-aa-ets-archiveTimestamp, XAdES: ArchiveTimeStamp, PAdES-LTV "document timestamp"
            this.timeStamp = timeStamp;
            RootCause.Add(rootCause);
        }

        public virtual X509Name? GetSignerSubjectName()
        {
            ICollection<X509Certificate> certs = ((CAdESCertificateSource)GetWrappedCertificateSource()).GetCertificates(true);
            foreach (X509Certificate cert in certs)
            {
                if (timeStamp.SignerID.Match(cert))
                {
                    return cert.SubjectDN;
                }
            }
            return null;
        }

        public virtual X509Certificate? GetSigner()
        {
            ICollection<X509Certificate> certs = ((CAdESCertificateSource)GetWrappedCertificateSource()).GetCertificates(true);
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

        public DateTime ThisUpdate => GetGenTimeDate();
        /// <returns>
        /// the timeStamp token
        /// </returns>
        public virtual TimeStampToken GetTimeStamp()
        {
            return timeStamp;
        }

        public override int GetHashCode()
        {
            return this.timeStamp.ToCmsSignedData().ContentInfo.GetHashCode();
        }


        /// <summary>
        /// Check if the TimeStampToken matches the data
        /// </summary>
        /// <returns>
        /// true if the data are verified by the TimeStampToken
        /// </returns>
        public virtual bool MatchData(ICryptographicProvider cryptographicProvider, byte[] data)
        {
            string hashAlgorithm = timeStamp.TimeStampInfo.HashAlgorithm.Algorithm.Id;
            byte[] computedDigest = cryptographicProvider.CalculateDigest(hashAlgorithm, data);
            return computedDigest.SequenceEqual(timeStamp.TimeStampInfo.GetMessageImprintDigest());
        }

        /// <summary>
        /// Retrieve the timestamp generation date
        /// </summary>
        public virtual DateTime GetGenTimeDate()
        {
            return timeStamp.TimeStampInfo.GenTime;
        }
        
        public virtual IList<X509Certificate> AllCertificates => Certificates;

        public virtual IList<X509Certificate> Certificates => timeStamp.UnsignedAttributes?.GetEtsCertValues() ?? Array.Empty<X509Certificate>();

        public virtual IList<CertificateRef> AllCertificateRefs => CertificateRefs;

        public virtual IList<CertificateRef> CertificateRefs => timeStamp.UnsignedAttributes?.GetEtsCertificateRefs() ?? Array.Empty<CertificateRef>();

        public virtual IList<CRLRef> AllCRLRefs => CRLRefs;

        public virtual IList<CRLRef> CRLRefs => timeStamp.UnsignedAttributes.GetEtsCrlRefs() ?? Array.Empty<CRLRef>();

        public virtual IList<OCSPRef> AllOCSPRefs => OCSPRefs;

        public virtual IList<OCSPRef> OCSPRefs => timeStamp.UnsignedAttributes.GetEtsOcspRefs() ?? Array.Empty<OCSPRef>();

        public virtual IList<X509Crl> AllCRLs => CRLs;

        public virtual IList<X509Crl> CRLs
        {
            get
            {
                var list = new List<X509Crl>();

                foreach (var crl in timeStamp.GetCrls("Collection").GetMatches(null).Cast<X509Crl>())
                {
                    list.Add(crl);
                }

                list.AddRange(timeStamp.UnsignedAttributes?.GetCrls() ?? new List<X509Crl>());

                return list;
            }

        }

        public virtual IList<BasicOcspResp> AllOCSPs => OCSPs;
        
        public virtual IList<BasicOcspResp> OCSPs => timeStamp.UnsignedAttributes?.GetOcspReps() ?? Array.Empty<BasicOcspResp>();

        public override string ToString()
        {
            return $"Timestamp[GenTime={GetGenTimeDate()}, SerialNumber={timeStamp.TimeStampInfo.SerialNumber}]";
        }
    }
}
