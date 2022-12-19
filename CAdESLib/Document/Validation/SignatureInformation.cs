using CAdESLib.Helpers;
using NLog;
using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Validation information about a Signature.
    /// </summary>
    public class SignatureInformation
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public IEnumerable<ICAdESLoggerEntry> ValidationLog { get; set; } = new List<ICAdESLoggerEntry>();

        /// <returns>
        /// the signatureVerification
        /// </returns>
        public SignatureVerification SignatureVerification { get; private set; }

        /// <returns>
        /// the certPathRevocationAnalysis
        /// </returns>
        public CertPathRevocationAnalysis CertPathRevocationAnalysis { get; private set; }

        /// <returns>
        /// the signatureLevelAnalysis
        /// </returns>
        public SignatureLevelAnalysis SignatureLevelAnalysis { get; private set; }

        /// <returns>
        /// the qualificationsVerification
        /// </returns>
        public QualificationsVerification QualificationsVerification { get; private set; }

        /// <returns>
        /// the qcStatementInformation
        /// </returns>
        public QCStatementInformation QcStatementInformation { get; private set; }

        /// <returns>
        /// the finalConclusion
        /// </returns>
        public FinalConclusions FinalConclusion { get; private set; }

        /// <returns>
        /// the finalConclusionComment
        /// </returns>
        public string FinalConclusionComment { get; private set; }
        public IValidationContext ValidationContext { get; }
        public IEnumerable<CertificateVerification> UsedCertsWithVerification { get; }

        public SignatureInformation(SignatureVerification signatureVerification, CertPathRevocationAnalysis
             certPathRevocationAnalysis, SignatureLevelAnalysis signatureLevelAnalysis, QualificationsVerification
             qualificationsVerification, QCStatementInformation qcStatementInformation, IEnumerable<CertificateVerification> usedCerts, IValidationContext ctx)
        {
            ValidationContext = ctx;
            UsedCertsWithVerification = usedCerts;
            SignatureVerification = signatureVerification;
            CertPathRevocationAnalysis = certPathRevocationAnalysis;
            SignatureLevelAnalysis = signatureLevelAnalysis;
            QualificationsVerification = qualificationsVerification;
            QcStatementInformation = qcStatementInformation;
            int tlContentCase = -1;
            if (certPathRevocationAnalysis.TrustedListInformation.IsServiceWasFound)
            {
                tlContentCase = 0;
            }
            if (certPathRevocationAnalysis.TrustedListInformation.IsServiceWasFound &&
                 qualificationsVerification != null && qualificationsVerification.QCWithSSCD.IsValid)
            {
                tlContentCase = 1;
            }
            if (certPathRevocationAnalysis.TrustedListInformation.IsServiceWasFound &&
                 qualificationsVerification != null && qualificationsVerification.QCNoSSCD.IsValid)
            {
                tlContentCase = 2;
            }
            if (certPathRevocationAnalysis.TrustedListInformation.IsServiceWasFound &&
                 qualificationsVerification != null && qualificationsVerification.QCSSCDStatusAsInCert.IsValid)
            {
                tlContentCase = 3;
            }
            if (certPathRevocationAnalysis.TrustedListInformation.IsServiceWasFound &&
                 qualificationsVerification != null && qualificationsVerification.QCForLegalPerson.IsValid)
            {
                tlContentCase = 4;
            }
            if (!certPathRevocationAnalysis.TrustedListInformation.IsServiceWasFound)
            {
                // Case 5 and 6 are not discriminable */
                tlContentCase = 5;
                FinalConclusionComment = "no.tl.confirmation";
            }
            if (certPathRevocationAnalysis.TrustedListInformation.IsServiceWasFound &&
                 !certPathRevocationAnalysis.TrustedListInformation.IsWellSigned)
            {
                tlContentCase = 7;
                FinalConclusionComment = "unsigned.tl.confirmation";
            }
            int certContentCase = -1;
            if (qcStatementInformation != null && !qcStatementInformation.QcCompliancePresent.IsValid && !qcStatementInformation.QCPPlusPresent.IsValid && qcStatementInformation
                .QCPPresent.IsValid && !qcStatementInformation.QcSCCDPresent.IsValid)
            {
                certContentCase = 0;
            }
            if (qcStatementInformation != null && qcStatementInformation.QcCompliancePresent.IsValid && !qcStatementInformation.QCPPlusPresent.IsValid && qcStatementInformation
                .QCPPresent.IsValid && !qcStatementInformation.QcSCCDPresent.IsValid)
            {
                certContentCase = 1;
            }
            if (qcStatementInformation != null && qcStatementInformation.QcCompliancePresent.IsValid && !qcStatementInformation.QCPPlusPresent.IsValid && qcStatementInformation
                .QCPPresent.IsValid && qcStatementInformation.QcSCCDPresent.IsValid)
            {
                certContentCase = 2;
            }
            if (qcStatementInformation != null && !qcStatementInformation.QcCompliancePresent.IsValid && qcStatementInformation.QCPPlusPresent.IsValid && !qcStatementInformation
                .QCPPresent.IsValid && !qcStatementInformation.QcSCCDPresent.IsValid)
            {
                certContentCase = 3;
            }
            if (qcStatementInformation != null && qcStatementInformation.QcCompliancePresent.IsValid && qcStatementInformation.QCPPlusPresent.IsValid && !qcStatementInformation
                .QCPPresent.IsValid && !qcStatementInformation.QcSCCDPresent.IsValid)
            {
                certContentCase = 4;
            }
            if (qcStatementInformation != null && qcStatementInformation.QcCompliancePresent.IsValid && qcStatementInformation.QCPPlusPresent.IsValid && qcStatementInformation
                .QcSCCDPresent.IsValid)
            {
                // QCPPlus stronger than QCP. If QCP is present, then it's ok.
                // && !qcStatementInformation.QCPPresent.isValid
                certContentCase = 5;
            }
            if (qcStatementInformation != null && qcStatementInformation.QcCompliancePresent.IsValid && !qcStatementInformation.QCPPlusPresent.IsValid && !qcStatementInformation
                .QCPPresent.IsValid && !qcStatementInformation.QcSCCDPresent.IsValid)
            {
                certContentCase = 6;
            }
            if (qcStatementInformation != null && !qcStatementInformation.QcCompliancePresent.IsValid && !qcStatementInformation.QCPPlusPresent.IsValid && !qcStatementInformation
                .QCPPresent.IsValid && qcStatementInformation.QcSCCDPresent.IsValid)
            {
                certContentCase = 7;
            }
            if (qcStatementInformation != null && qcStatementInformation.QcCompliancePresent.IsValid && !qcStatementInformation.QCPPlusPresent.IsValid && !qcStatementInformation
                .QCPPresent.IsValid && qcStatementInformation.QcSCCDPresent.IsValid)
            {
                certContentCase = 8;
            }
            if (qcStatementInformation == null || (!qcStatementInformation.QcCompliancePresent.IsValid && !qcStatementInformation.QCPPlusPresent.IsValid && !qcStatementInformation
                .QCPPresent.IsValid && !qcStatementInformation.QcSCCDPresent.IsValid))
            {
                certContentCase = 9;
            }
            logger.Trace("TLCase : " + (tlContentCase + 1) + " - CertCase : " + (certContentCase + 1));
            try
            {
                FinalConclusions[][] matrix = new FinalConclusions[][] {
                        new FinalConclusions[] { FinalConclusions.AdES_QC, FinalConclusions.AdES_QC, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.AdES_QC, FinalConclusions.AdES, FinalConclusions.QES, FinalConclusions.AdES },
                        new FinalConclusions[] { FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.AdES, FinalConclusions.QES, FinalConclusions.AdES },
                        new FinalConclusions[] { FinalConclusions.AdES_QC, FinalConclusions.AdES_QC, FinalConclusions.AdES_QC, FinalConclusions.AdES_QC, FinalConclusions.AdES_QC, FinalConclusions.AdES_QC, FinalConclusions.AdES_QC, FinalConclusions.AdES, FinalConclusions.AdES_QC, FinalConclusions.AdES },
                        new FinalConclusions[] { FinalConclusions.AdES_QC, FinalConclusions.AdES_QC, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.AdES_QC, FinalConclusions.AdES, FinalConclusions.QES, FinalConclusions.AdES },
                        new FinalConclusions[] { FinalConclusions.AdES_QC, FinalConclusions.AdES_QC, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.AdES_QC, FinalConclusions.AdES, FinalConclusions.QES, FinalConclusions.AdES },
                        new FinalConclusions[] { FinalConclusions.AdES_QC, FinalConclusions.AdES_QC, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.AdES_QC, FinalConclusions.AdES, FinalConclusions.QES, FinalConclusions.AdES },
                        new FinalConclusions[] { FinalConclusions.AdES_QC, FinalConclusions.AdES_QC, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.AdES_QC, FinalConclusions.AdES, FinalConclusions.QES, FinalConclusions.AdES },
                        new FinalConclusions[] { FinalConclusions.AdES_QC, FinalConclusions.AdES_QC, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.QES, FinalConclusions.AdES_QC, FinalConclusions.AdES, FinalConclusions.QES, FinalConclusions.AdES } };
                FinalConclusion = matrix[tlContentCase][certContentCase];
            }
            catch (IndexOutOfRangeException)
            {
                FinalConclusion = FinalConclusions.UNDETERMINED;
            }
        }

        public enum FinalConclusions
        {
            /// <summary>
            /// QES (Qualified Electronic Signature) – the highest level of e-signatures, which are equal to handwritten signatures and are also called digital signatures. The signature meets the technological requirements established in standards. The backgrounds of both the owner of the signature and the issuer of the certificate are checked. Additionally, the signature is given with a means that is deemed suitable (ID-cards and mobile ID).
            /// </summary>

            [Description("QES (Qualified Electronic Signature)")]
            QES,
            /// <summary>
            ///  AdES/QC (Advanced Electronic Signature with a Qualified Certificate) – the signature meets the technological requirements established in standards. The backgrounds of both the owner of the signature and the issuer of the certificate are checked.
            /// </summary>
            [Description("AdES/QC (Advanced Electronic Signature with a Qualified Certificate)")]
            AdES_QC,
            /// <summary>
            /// AdES (Advanced Electronic Signature) – the signature meets the technological requirements established in standards, but the background of the holder of the certificate used to give the signature as well as the background of the issuer of the certificate may be unknown.
            /// </summary>
            [Description("AdES (Advanced Electronic Signature)")]
            AdES,
            [Description("UNDETERMINED")]
            UNDETERMINED
        }
    }
}
