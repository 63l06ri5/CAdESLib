using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Validation report containing all the validation check for a document.
    /// </summary>
    public class ValidationReport
    {
        public TimeInformation TimeInformation { get; private set; }

        /// <returns>
        /// the signatureInformation
        /// </returns>
        public IList<SignatureInformation?> SignatureInformationList { get; private set; }

        public ValidationReport(TimeInformation timeInformation, IList<SignatureInformation?> signatureInformationList)
        {
            TimeInformation = timeInformation;
            SignatureInformationList = signatureInformationList;
        }
    }
}
