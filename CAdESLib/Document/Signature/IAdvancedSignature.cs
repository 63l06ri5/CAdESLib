using CAdESLib.Document.Validation;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.X509;
using System.Collections.Generic;

namespace CAdESLib.Document.Signature
{
    /// <summary>
    /// Provides an abstraction for an Advanced Electronic Signature.
    /// </summary>
    /// <remarks>
    /// Provides an abstraction for an Advanced Electronic Signature. This ease the validation process. Every signature
    /// format : XAdES, CAdES and PAdES are treated the same.
    /// </remarks>
    public interface IAdvancedSignature
    {
        /// <summary>
        /// Retrieves the signature algorithm (or cipher) used for generating the signature
        /// </summary>
        string SignatureAlgorithm { get; }

        /// <summary>
        /// Gets a certificate source for the ALL certificates embedded in the signature
        /// </summary>
        ICertificateSource CertificateSource { get; }

        /// <summary>
        /// Get certificates embedded in the signature
        /// </summary>
        /// <reutrn>a list of certificate contained in the signature</reutrn>
        IList<X509Certificate> Certificates { get; }

        /// <summary>
        /// Gets a CRL source for the CRLs embedded in the signature
        /// </summary>
        ICrlSource CRLSource { get; }

        /// <summary>
        /// Gets an OCSP source for the OCSP responses embedded in the signature
        /// </summary>
        IOcspSource OCSPSource { get; }

        /// <summary>
        /// Get the signing certificate
        /// </summary>
        X509Certificate SigningCertificate { get; }

        /// <summary>
        /// Returns the signing time information
        /// </summary>
        DateTimeObject SigningTime { get; }

        /// <summary>
        /// Returns the Signature Policy OID from the signature
        /// </summary>
        PolicyValue PolicyId { get; }

        /// <summary>
        /// Return information about the place where the signature was generated
        /// </summary>
        string Location { get; }

        /// <summary>
        /// Returns the content type of the signed data
        /// </summary>
        string ContentType { get; }

        /// <summary>
        /// Returns the claimed role of the signer.
        /// </summary>
        string[] ClaimedSignerRoles { get; }

        /// <summary>
        /// Returns the signature timestamps
        /// </summary>
        IList<TimestampToken> SignatureTimestamps { get; }

        /// <summary>
        /// Returns the data that is timestamped in the SignatureTimeStamp
        /// </summary>
        byte[] SignatureTimestampData { get; }

        /// <summary>
        /// Archive timestamp seals the data of the signature in a specific order.
        /// </summary>
        /// <remarks>
        /// Archive timestamp seals the data of the signature in a specific order. We need to retrieve the data for each
        /// timestamp.
        /// </remarks>
        /// <param name="originalData">
        /// For a detached signature, the original data are needed
        /// </param>
        byte[] GetArchiveTimestampData(int index, IDocument originalData);

        /// <summary>
        /// Returns the timestamp over the certificate/revocation references (and optionally other fields), used in -X
        /// profiles
        /// </summary>
        IList<TimestampToken> TimestampsX1 { get; }

        IList<TimestampToken> TimestampsX2 { get; }

        /// <summary>
        /// Returns the archive TimeStamps
        /// </summary>
        IList<TimestampToken> ArchiveTimestamps { get; }

        /// <summary>
        /// All timestamp tokens
        /// </summary>
        IList<TimestampToken> AllTimestampTokens { get; }

        /// <summary>
        /// Verify the signature integrity; checks if the signed content has not been tampered with
        /// </summary>
        /// <param name="detachedDocument">
        /// the original document concerned by the signature if not part of the actual object
        /// </param>
        /// <returns>
        /// true if the signature is valid
        /// </returns>
        bool CheckIntegrity(IDocument detachedDocument);

        /// <summary>
        /// Returns a list of counter signatures applied to this signature
        /// </summary>
        /// <returns>
        /// a list of AdvancedSignatures representing the counter signatures
        /// </returns>
        IList<IAdvancedSignature> CounterSignatures { get; }

        /// <summary>
        /// Retrieve list of certificate ref
        /// </summary>
        IList<CertificateRef> CertificateRefs { get; }

        /// <returns>
        /// The list of CRLRefs contained in the Signature
        /// </returns>
        IList<CRLRef> CRLRefs { get; }

        /// <returns>
        /// The list of OCSPRef contained in the Signature
        /// </returns>
        IList<OCSPRef> OCSPRefs { get; }

        /// <returns>
        /// The list of X509Crl contained in the Signature
        /// </returns>
        IList<X509Crl> CRLs { get; }

        /// <returns>
        /// The list of BasicOCSResp contained in the Signature
        /// </returns>
        IList<BasicOcspResp> OCSPs { get; }

        /// <returns>
        /// The byte array digested to create a TimeStamp X1
        /// </returns>
        byte[] TimestampX1Data { get; }

        /// <returns>
        /// The byte array digested to create a TimeStamp X2
        /// </returns>
        byte[] TimestampX2Data { get; }
    }
}
