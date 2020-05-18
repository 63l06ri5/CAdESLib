using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Ocsp;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Utility class used to convert OcspResp to BasicOcspResp
    /// </summary>
    public abstract class OCSPUtils
    {
        /// <summary>
        /// Convert a OcspResp in a BasicOcspResp
        /// </summary>
        public static BasicOcspResp FromRespToBasic(OcspResp ocspResp)
        {
            return (BasicOcspResp)ocspResp.GetResponseObject();

        }

        /// <summary>
        /// Convert a BasicOcspResp in OcspResp (connection status is set to SUCCESSFUL).
        /// </summary>
        public static OcspResp FromBasicToResp(BasicOcspResp basicOCSPResp)
        {
            return FromBasicToResp(basicOCSPResp.GetEncoded());
        }

        /// <summary>
        /// Convert a BasicOcspResp in OcspResp (connection status is set to SUCCESSFUL).
        /// </summary>
        public static OcspResp FromBasicToResp(byte[] basicOCSPResp)
        {
            OcspResponse response = new OcspResponse(new OcspResponseStatus(OcspResponseStatus
                .Successful), new ResponseBytes(OcspObjectIdentifiers.PkixOcspBasic, new DerOctetString
                (basicOCSPResp)));
            OcspResp resp = new OcspResp(response);
            return resp;
        }
    }
}
