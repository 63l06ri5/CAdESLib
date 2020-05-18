using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System.IO;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Check if a certificate has a specific policy id
    /// </summary>
    [System.Serializable]
    public class PolicyIdCondition : Condition
    {
        private const long serialVersionUID = 7590885101177874819L;

        private readonly string policyOid;

        public PolicyIdCondition()
        {
        }

        public PolicyIdCondition(string policyId)
        {
            policyOid = policyId;
        }

        /// <returns>
        /// the policyOid
        /// </returns>
        public virtual string GetPolicyOid()
        {
            return policyOid;
        }

        public virtual bool Check(CertificateAndContext cert)
        {
            if (cert is null)
            {
                throw new System.ArgumentNullException(nameof(cert));
            }
            Asn1OctetString certificatePolicies = cert.Certificate.GetExtensionValue(X509Extensions.CertificatePolicies);
            if (certificatePolicies != null)
            {
                DerOctetString s = (DerOctetString)certificatePolicies;
                byte[] content = s.GetOctets();
                using (Asn1InputStream input = new Asn1InputStream(content))
                {
                    DerSequence seq = (DerSequence)input.ReadObject();
                    for (int i = 0; i < seq.Count; i++)
                    {
                        PolicyInformation policyInfo = PolicyInformation.GetInstance(seq[i]);
                        if (policyInfo.PolicyIdentifier.Id.Equals(policyOid, System.StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }

            }
            return false;
        }
    }
}
