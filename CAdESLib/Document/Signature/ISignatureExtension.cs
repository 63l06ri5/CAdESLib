using CAdESLib.Document.Validation;
using System.Collections.Generic;

namespace CAdESLib.Document.Signature
{
    public interface ISignatureExtension
    {
        /// <summary>
        /// Extend the level of the signatures contained in a document.
        /// </summary>
        (IDocument, ICollection<IValidationContext?>?) ExtendSignatures(IDocument document, IDocument originalData, SignatureParameters parameters);

        SignatureProfile SignatureProfile { get; }

    }
}
