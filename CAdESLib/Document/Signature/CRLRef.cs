using CAdESLib.Helpers;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.X509;
using System;
using System.Linq;

namespace CAdESLib.Document.Signature
{
    /// <summary>
    /// Reference to a X509Crl
    /// </summary>
    public class CRLRef
    {
        private readonly string algorithm;

        private readonly byte[] digestValue;

        public CRLRef(CrlValidatedID cmsRef)
        {
            algorithm = cmsRef.CrlHash.HashAlgorithm.Algorithm.Id;
            digestValue = cmsRef.CrlHash.GetHashValue();
        }

        public virtual bool Match(ICryptographicProvider cryptographicProvider, X509Crl crl)
        {
            byte[] computedValue = cryptographicProvider.CalculateDigest(algorithm, crl.GetEncoded());
            return digestValue.SequenceEqual(computedValue);
        }
    }
}
