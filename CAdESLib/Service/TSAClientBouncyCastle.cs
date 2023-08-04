using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using System;
using System.IO;
using System.Net;
using System.Text;

namespace CAdESLib.Service
{
    /**
    * Time Stamp Authority Client interface implementation using Bouncy Castle
    * org.bouncycastle.tsp package.
    * <p>
    * Created by Aiken Sam, 2006-11-15, refactored by Martin Brunecky, 07/15/2007
    * for ease of subclassing.
    * </p>
    * @since	2.1.6
    */
    public class TSAClientBouncyCastle : ITSAClient
    {

        /** The Logger instance. */
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        /** An interface that allows you to inspect the timestamp info. */
        protected ITSAInfoBouncyCastle tsaInfo;
        /** The default value for the hash algorithm */
        public const int DEFAULTTOKENSIZE = 4096;

        /** Estimate of the received time stamp token */
        protected internal int tokenSizeEstimate = DEFAULTTOKENSIZE;

        /** The default value for the hash algorithm */
        public const string DEFAULTHASHALGORITHMOID = "2.16.840.1.101.3.4.2.1";

        public virtual string TsaDigestAlgorithmOID { get; private set; }

        public virtual string TsaURL { get; private set; }

        public virtual string TsaUsername { get; private set; }

        public virtual string TsaPassword { get; private set; }

        private readonly Func<IHTTPDataLoader> httpDataLoaderFunc;

        public TSAClientBouncyCastle()
        {
        }

        public TSAClientBouncyCastle(Func<IHTTPDataLoader> httpDataLoaderFunc)
        {
            this.httpDataLoaderFunc = httpDataLoaderFunc;
        }

        /**
* Creates an instance of a TSAClient that will use BouncyCastle.
* @param url String - Time Stamp Authority URL (i.e. "http://tsatest1.digistamp.com/TSA")
*/
        public TSAClientBouncyCastle(string url)
            : this(url, null, null, DEFAULTTOKENSIZE, DEFAULTHASHALGORITHMOID)
        {
        }

        /**
        * Creates an instance of a TSAClient that will use BouncyCastle.
        * @param url String - Time Stamp Authority URL (i.e. "http://tsatest1.digistamp.com/TSA")
        * @param username String - user(account) name
        * @param password String - password
        */
        public TSAClientBouncyCastle(string url, string username, string password)
            : this(url, username, password, DEFAULTTOKENSIZE, DEFAULTHASHALGORITHMOID)
        {
        }

        /**
        * Constructor.
        * Note the token size estimate is updated by each call, as the token
        * size is not likely to change (as long as we call the same TSA using
        * the same imprint length).
        * @param url String - Time Stamp Authority URL (i.e. "http://tsatest1.digistamp.com/TSA")
        * @param username String - user(account) name
        * @param password String - password
        * @param tokSzEstimate int - estimated size of received time stamp token (DER encoded)
        */
        public TSAClientBouncyCastle(string url, string username, string password, int tokSzEstimate, string digestAlgorithmOid)
        {
            TsaURL = url;
            TsaUsername = username;
            TsaPassword = password;
            tokenSizeEstimate = tokSzEstimate;
            TsaDigestAlgorithmOID = digestAlgorithmOid;
        }

        /**
         * @param tsaInfo the tsaInfo to set
         */
        public void SetTSAInfo(ITSAInfoBouncyCastle tsaInfo)
        {
            this.tsaInfo = tsaInfo;
        }

        /**
        * Get the token size estimate.
        * Returned value reflects the result of the last succesfull call, padded
        * @return an estimate of the token size
        */
        public virtual int GetTokenSizeEstimate()
        {
            return tokenSizeEstimate;
        }

        /**
         * Gets the MessageDigest to digest the data imprint
         * @return the digest algorithm name
         */
        public IDigest GetMessageDigest()
        {
            return DigestAlgorithms.GetMessageDigestFromOid(TsaDigestAlgorithmOID);
        }

        /**
         * Get RFC 3161 timeStampToken.
         * Method may return null indicating that timestamp should be skipped.
         * @param imprint data imprint to be time-stamped
         * @return encoded, TSA signed data of the timeStampToken
         */
        public virtual byte[] GetTimeStampToken(byte[] imprint)
        {
            // Setup the time stamp request
            TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
            tsqGenerator.SetCertReq(true);
            // tsqGenerator.setReqPolicy("1.3.6.1.4.1.601.10.3.1");
            BigInteger nonce = BigInteger.ValueOf(DateTime.Now.Ticks + Environment.TickCount);
            TimeStampRequest request = tsqGenerator.Generate(TsaDigestAlgorithmOID, imprint, nonce);
            byte[] requestBytes = request.GetEncoded();

            // Call the communications layer
            var respBytes = GetTSAResponse(requestBytes);

            // Handle the TSA response
            TimeStampResponse response = new TimeStampResponse(respBytes);

            // validate communication level attributes (RFC 3161 PKIStatus)
            response.Validate(request);
            var failure = response.GetFailInfo();
            int value = (failure == null) ? 0 : failure.IntValue;
            if (value != 0)
            {
                // @todo: Translate value of 15 error codes defined by PKIFailureInfo to string
                throw new IOException($"invalid.tsa.1.response.code.2, {TsaURL}, {value}");
            }
            // @todo: validate the time stap certificate chain (if we want
            //        assure we do not sign using an invalid timestamp).

            // extract just the time stamp token (removes communication status info)
            TimeStampToken tsToken = response.TimeStampToken;
            if (tsToken == null)
            {
                throw new IOException($"tsa.1.failed.to.return.time.stamp.token.2, {TsaURL}, {response.GetStatusString()}");
            }
            TimeStampTokenInfo tsTokenInfo = tsToken.TimeStampInfo; // to view details
            byte[] encoded = tsToken.GetEncoded();

            logger.Trace("Timestamp generated: " + tsTokenInfo.GenTime);
            if (tsaInfo != null)
            {
                tsaInfo.InspectTimeStampTokenInfo(tsTokenInfo);
            }
            // Update our token size estimate for the next call (padded to be safe)
            tokenSizeEstimate = encoded.Length + 32;
            return encoded;
        }

        /**
        * Get timestamp token - communications layer
        * @return - byte[] - TSA response, raw bytes (RFC 3161 encoded)
        */
        protected internal virtual byte[] GetTSAResponse(byte[] requestBytes)
        {
            Stream inp;
            HttpWebResponse response = null;
            string autorizationHeader = null;
            Func<string, Func<byte[], byte[]>> postProcessFunc = (string encoding) => (byte[] respBytes) =>
            {
                if (this.httpDataLoaderFunc == null)
                {
                    if (encoding != null && encoding.Equals("base64", StringComparison.OrdinalIgnoreCase))
                    {
                        return Convert.FromBase64String(Encoding.ASCII.GetString(respBytes));
                    }
                }

                return respBytes;
            };

            Func<byte[], byte[]> postProcessHandler = null;

            if ((TsaUsername != null) && !TsaUsername.Equals(""))
            {
                string authInfo = TsaUsername + ":" + TsaPassword;
                authInfo = Convert.ToBase64String(Encoding.Default.GetBytes(authInfo), Base64FormattingOptions.None);
                autorizationHeader = "Basic " + authInfo;
            }

            if (this.httpDataLoaderFunc != null)
            {
                var con = this.httpDataLoaderFunc();
                con.ContentType = "application/timestamp-query";
                if (!string.IsNullOrEmpty(autorizationHeader))
                {
                    con.Headers["Authorization"] = autorizationHeader;
                }
                inp = con.Post(TsaURL, new MemoryStream(requestBytes));
            }
            else
            {
                HttpWebRequest con = (HttpWebRequest) WebRequest.Create(TsaURL);
                con.ContentLength = requestBytes.Length;
                con.ContentType = "application/timestamp-query";
                con.Method = "POST";
                if (!string.IsNullOrEmpty(autorizationHeader))
                {
                    con.Headers["Authorization"] = autorizationHeader;
                }
                Stream outp = con.GetRequestStream();
                outp.Write(requestBytes, 0, requestBytes.Length);
                outp.Close();
                response = (HttpWebResponse) con.GetResponse();
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    throw new IOException($"invalid.http.response.1, {(int) response.StatusCode}");
                }

                inp = response.GetResponseStream();
                string encoding = response.ContentEncoding;
                

                postProcessHandler = postProcessFunc(encoding);
            }

            using MemoryStream baos = new MemoryStream();
            byte[] buffer = new byte[1024];
            int bytesRead = 0;
            while ((bytesRead = inp.Read(buffer, 0, buffer.Length)) > 0)
            {
                baos.Write(buffer, 0, bytesRead);
            }

            inp.Close();
            response?.Close();

            byte[] respBytes = baos.ToArray();

            if (postProcessHandler != null)
            {
                respBytes = postProcessHandler(respBytes);
            }


            return respBytes;
        }
    }
}
