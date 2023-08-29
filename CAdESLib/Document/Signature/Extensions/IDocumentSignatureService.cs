using CAdESLib.Document.Validation;
using System.Collections.Generic;
using System.IO;

namespace CAdESLib.Document.Signature
{
    public interface IDocumentSignatureService
    {
        /// <summary>
        /// Extend signature to specified level
        /// </summary>
        /// <param name="originalDocument">
        /// Нужен для создания подписи уровня A
        /// </param>
        (IDocument, ValidationReport) ExtendDocument(IDocument document, IDocument originalDocument, SignatureParameters parameters);

        ValidationReport ValidateDocument(IDocument document, bool checkIntegrity, IDocument externalContent = null, ICollection<IValidationContext> validationContexts = null);

        /// <summary>
        /// Prerate data for singing
        /// </summary>
        /// <param name="document"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        Stream ToBeSigned(IDocument document, SignatureParameters parameters);

        /// <summary>
        /// Build PKCS#7-format signature file
        /// </summary>
        /// <param name="document">file</param>
        /// <param name="parameters"></param>
        /// <param name="signatureValue">generated signature</param>
        /// <returns></returns>
        (IDocument, ValidationReport) GetSignedDocument(IDocument document, SignatureParameters parameters, byte[] signatureValue);
    }
}
