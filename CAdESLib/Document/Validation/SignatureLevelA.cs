using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Validation information for level A (CAdES and XAdES).
    /// </summary>
    public class SignatureLevelA : SignatureLevel
    {
        private readonly IList<TimestampVerificationResult> archiveTimestampsVerification;

        public SignatureLevelA(SignatureValidationResult levelReached, IList<TimestampVerificationResult> archiveTimestampsVerification) : base(levelReached)
        {
            this.archiveTimestampsVerification = archiveTimestampsVerification;
        }

        /// <returns>
        /// the archiveTimestampsVerification
        /// </returns>
        public virtual IList<TimestampVerificationResult> ArchiveTimestampsVerification => archiveTimestampsVerification;
    }
}
