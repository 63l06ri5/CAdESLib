using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using System.Collections;
using System.Collections.Generic;

namespace CAdESLib.Document.Signature.Extensions
{
    /// <summary>
    /// This class holds the CAdES-EPES signature profile; it supports the inclusion of the mandatory signed
    /// id_aa_ets_sigPolicyId attribute as specified in ETSI TS 101 733 V1.8.1, clause 5.8.1.
    /// </summary>
    public class CAdESProfileEPES : CAdESProfileBES
    {
        public CAdESProfileEPES()
        {
        }

        public override IDictionary<DerObjectIdentifier, Asn1Encodable> GetSignedAttributes(SignatureParameters parameters)
        {
            var signedAttrs = base.GetSignedAttributes(parameters);
            Attribute policy;
            SignaturePolicyIdentifier sigPolicy;
            switch (parameters.SignaturePolicy)
            {
                case SignaturePolicy.EXPLICIT:
                    {
                        sigPolicy = new SignaturePolicyIdentifier(
                            new SignaturePolicyId(new DerObjectIdentifier(parameters.SignaturePolicyID),
                            new OtherHashAlgAndValue(new AlgorithmIdentifier(new DerObjectIdentifier(DigestAlgorithm.GetByName(parameters.SignaturePolicyHashAlgo).OID)),
                            new DerOctetString(parameters.SignaturePolicyHashValue))));
                        policy = new Attribute(PkcsObjectIdentifiers.IdAAEtsSigPolicyID, new DerSet(sigPolicy));
                        signedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsSigPolicyID, policy);
                        break;
                    }

                case SignaturePolicy.IMPLICIT:
                    {
                        sigPolicy = new SignaturePolicyIdentifier();
                        policy = new Attribute(PkcsObjectIdentifiers.IdAAEtsSigPolicyID, new DerSet(sigPolicy));
                        signedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsSigPolicyID, policy);
                        break;
                    }

                case SignaturePolicy.NO_POLICY:
                    {
                        break;
                    }
            }
            return signedAttrs;
        }
    }
}
