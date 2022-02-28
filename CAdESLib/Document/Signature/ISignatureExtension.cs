namespace CAdESLib.Document.Signature
{
    public interface ISignatureExtension
    {
        /// <summary>
        /// Extend the level of the signatures contained in a document.
        /// </summary>
        IDocument ExtendSignatures(IDocument document, IDocument originalData, SignatureParameters parameters);

    }
}
