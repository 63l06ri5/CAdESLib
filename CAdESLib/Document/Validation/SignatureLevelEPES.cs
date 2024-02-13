using CAdESLib.Document.Signature;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Validation information for level EPES.
    /// </summary>
    public class SignatureLevelEPES : SignatureLevel
    {
        private readonly PolicyValue? signaturePolicy;

        public SignatureLevelEPES(IAdvancedSignature signature, SignatureValidationResult levelReached) : base
            (levelReached)
        {
            if (signature != null)
            {
                signaturePolicy = signature.PolicyId;
            }
        }

        public virtual PolicyValue? PolicyId => signaturePolicy;
    }
}
