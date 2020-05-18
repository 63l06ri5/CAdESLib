using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Signature
{
    /// <summary>
    /// Represent the value of a SignaturePolicy
    /// </summary>
    public class PolicyValue
    {
        public PolicyValue(string signaturePolicyId)
        {
            this.SignaturePolicyId = signaturePolicyId;
            Policy = SignaturePolicy.EXPLICIT;
        }

        public PolicyValue()
        {
            Policy = SignaturePolicy.IMPLICIT;
        }

        /// <returns>
        /// the signaturePolicyId
        /// </returns>
        public virtual string SignaturePolicyId { get; private set; }

        /// <returns>
        /// the policy
        /// </returns>
        public virtual SignaturePolicy Policy { get; private set; }

        public override string ToString()
        {
            switch (Policy)
            {
                case SignaturePolicy.EXPLICIT:
                    {
                        return SignaturePolicyId;
                    }

                default:
                    {
                        return Policy.ToString();
                    }
            }
        }
    }
}
