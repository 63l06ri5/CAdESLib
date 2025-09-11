using System.Collections.Generic;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace CAdESLib.Document.Signature
{
    /// <summary>
    /// Provides an abstraction for an access to refs and vals of certs and revs
    /// </summary>
    public interface ICertsAndVals
    {
        /// <summary>
        /// Get certificates embedded in the signature
        /// </summary>
        /// <reutrn>a list of certificate contained in the signature</reutrn>
        IList<X509Certificate> AllCertificates { get; }

        /// <summary>
        /// Get certificates embedded in the signature, but not in the timestamps
        /// </summary>
        /// <reutrn>a list of certificate contained in the signature</reutrn>
        IList<X509Certificate> Certificates { get; }

        /// <summary>
        /// Retrieve list of certificate ref
        /// </summary>
        IList<CertificateRef> AllCertificateRefs { get; }
        
        /// <summary>
        /// Retrieve list of certificate ref, but not in the timestamps
        /// </summary>
        IList<CertificateRef> CertificateRefs { get; }
        
        /// <returns>
        /// The list of CRLRefs contained in the Signature
        /// </returns>
        IList<CRLRef> AllCRLRefs { get; }

        /// <returns>
        /// The list of CRLRefs contained in the Signature, but not in the timestamps
        /// </returns>
        IList<CRLRef> CRLRefs { get; }

        /// <returns>
        /// The list of OCSPRef contained in the Signature
        /// </returns>
        IList<OCSPRef> AllOCSPRefs { get; }

        /// <returns>
        /// The list of OCSPRef contained in the Signature, but not in the timestamps
        /// </returns>
        IList<OCSPRef> OCSPRefs { get; }
        
        /// <returns>
        /// The list of X509Crl contained in the Signature
        /// </returns>
        IList<X509Crl> AllCRLs { get; }

        /// <returns>
        /// The list of X509Crl contained in the Signature, but not in the timestamps
        /// </returns>
        IList<X509Crl> CRLs { get; }

        /// <returns>
        /// The list of BasicOCSResp contained in the Signature
        /// </returns>
        IList<BasicOcspResp> AllOCSPs { get; }

        /// <returns>
        /// The list of BasicOCSResp contained in the Signature, but not in the timestamps
        /// </returns>
        IList<BasicOcspResp> OCSPs { get; }
    }
}
