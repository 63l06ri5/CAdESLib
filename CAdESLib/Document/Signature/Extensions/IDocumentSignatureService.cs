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
        /// <param name="signedDocument"></param>
        /// <param name="originalDocument">
        /// For an A profile signing
        /// </param>
        /// <param name="parameters"></param>
        (IDocument, ValidationReport) ExtendDocument(
                IDocument signedDocument,
                IDocument? originalDocument,
                SignatureParameters parameters);

        /// <summary>
        /// Validate document
        /// </summary>
        /// <param name="strictValidation">only matter for XL types, cause it enables check with an available data in a signature</param>
        ///
        ValidationReport ValidateDocument(
                IDocument document,
                bool checkIntegrity,
                IDocument? externalContent = null,
                ICollection<IValidationContext?>? validationContexts = null,
                bool strictValidation = false);

        /// <summary>
        /// Prerate data for singing
        /// </summary>
        /// <param name="document"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        Stream ToBeSigned(IDocument document, SignatureParameters parameters);

        /// <summary>
        /// Prerate data for singing with hash
        /// </summary>
        /// <param name="hash">Hash of content</param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        Stream ToBeSignedWithHash(IDocument hash, SignatureParameters parameters);

        /// <summary>
        /// Build PKCS#7-format signature file
        /// </summary>
        /// <param name="document">file</param>
        /// <param name="parameters"></param>
        /// <param name="signatureValue">generated signature</param>
        /// <returns></returns>
        (IDocument, ValidationReport) GetSignedDocument(
                IDocument document,
                SignatureParameters parameters,
                byte[] signatureValue);

        /// <summary>
        /// Build PKCS#7-format signature file
        /// </summary>
        /// <param name="signedAttributes">signature attributes der set</param>
        /// <param name="parameters"></param>
        /// <param name="signatureValue">generated signature</param>
        /// <returns></returns>
        (IDocument, ValidationReport) GetSignedDocumentWithSignedAttributes(
            IDocument signedAttributes,
            SignatureParameters parameters,
            byte[] signatureValue);
    }
}
