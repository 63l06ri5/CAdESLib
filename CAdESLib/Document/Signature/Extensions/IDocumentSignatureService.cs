using System.IO;
using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using CAdESLib.Service;

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
        Document ExtendDocument(Document document, Document originalDocument, SignatureParameters parameters);

        ValidationReport ValidateDocument(Document document, bool checkIntegrity, Document externalContent = null);

        /// <summary>
        /// Prerate data for singing
        /// </summary>
        /// <param name="document"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public Stream ToBeSigned(Document document, SignatureParameters parameters);

        /// <summary>
        /// Build PKCS#7-format signature file
        /// </summary>
        /// <param name="document">file</param>
        /// <param name="parameters"></param>
        /// <param name="signatureValue">generated signature</param>
        /// <returns></returns>
        public Document GetSignedDocument(Document document, SignatureParameters parameters, byte[] signatureValue);
    }
}
