using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tsp;
using CAdESLib.Document;
using CAdESLib.Document.Signature;

namespace CAdESLib.Service
{
    /// <summary>
    /// Abstraction of a Time Stamping authority which delivers RFC 3161 Time Stamp Responses containing tokens, from Time
    /// Stamp Requests.
    /// </summary>
    public interface ITspSource : ITSAClient
    {
        /// <summary>
        /// Gets a TimeStampResponse relevant to the provided digest
        /// </summary>
        TimeStampResponse GetTimeStampResponse(DigestAlgorithm algorithm, byte[] digest);
    }

    /**
   * Time Stamp Authority client (caller) interface.
   * <p>
   * Interface used by the PdfPKCS7 digital signature builder to call
   * Time Stamp Authority providing RFC 3161 compliant time stamp token.
   * @author Martin Brunecky, 07/17/2007
   * @since    2.1.6
   */
    public interface ITSAClient
    {
        /**
        * Get the time stamp token size estimate.
        * Implementation must return value large enough to accomodate the entire token
        * returned by getTimeStampToken() _prior_ to actual getTimeStampToken() call.
        * @return   an estimate of the token size
        */
        int GetTokenSizeEstimate();

        /**
         * Gets the MessageDigest to digest the data imprint
         * @return the digest algorithm name
         */
        IDigest GetMessageDigest();

        /**
         * Get RFC 3161 timeStampToken.
         * Method may return null indicating that timestamp should be skipped.
         * @param imprint byte[] - data imprint to be time-stamped
         * @return byte[] - encoded, TSA signed data of the timeStampToken
         * @throws Exception - TSA request failed
         */
        byte[] GetTimeStampToken(byte[] imprint);

        /** URL of the Time Stamp Authority */
        string TsaURL { get; }
        /** TSA Username */
        string TsaUsername { get; }
        /** TSA password */
        string TsaPassword { get; }
    }

    /**
   * Interface you can implement and pass to TSAClientBouncyCastle in case
   * you want to do something with the information returned
   */
    public interface ITSAInfoBouncyCastle
    {

        /**
         * When a timestamp is created using TSAClientBouncyCastle,
         * this method is triggered passing an object that contains
         * info about the timestamp and the time stamping authority.
         * @param info a TimeStampTokenInfo object
         */
        void InspectTimeStampTokenInfo(TimeStampTokenInfo info);
    }
}
