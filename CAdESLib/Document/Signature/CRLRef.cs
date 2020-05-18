using System;
using System.Linq;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;

namespace CAdESLib.Document.Signature
{
    /// <summary>
    /// Reference to a X509Crl
    /// </summary>
    public class CRLRef
    {
        private X509Name crlIssuer;

        private DateTime crlIssuedTime;

        private BigInteger crlNumber;

        private string algorithm;

        private byte[] digestValue;

        public CRLRef()
        {
        }

        public CRLRef(CrlValidatedID cmsRef)
        {
            crlIssuer = cmsRef.CrlIdentifier.CrlIssuer;
            crlIssuedTime = cmsRef.CrlIdentifier.CrlIssuedTime;
            crlNumber = cmsRef.CrlIdentifier.CrlNumber;
            algorithm = cmsRef.CrlHash.HashAlgorithm.Algorithm.Id;
            digestValue = cmsRef.CrlHash.GetHashValue();
        }

        public virtual bool Match(X509Crl crl)
        {
            byte[] computedValue = DigestUtilities.CalculateDigest
                (algorithm, crl.GetEncoded());
            return digestValue.SequenceEqual(computedValue);
        }
    }
}
