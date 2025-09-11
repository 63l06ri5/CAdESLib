using CAdESLib.Helpers;
using NLog;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using static CAdESLib.Document.Validation.SignatureValidationResult;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Validation information about a Signature.
    /// </summary>
    public class SignatureInformation
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

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
        /// the finalConclusion
        /// </returns>
        public FinalConclusions FinalConclusion { get; private set; }

        /// <returns>
        /// the finalConclusionComment
        /// </returns>
        public string? FinalConclusionComment { get; private set; }
        public IValidationContext ValidationContext { get; }

        public bool LevelAReached => SignatureLevelAnalysis.LevelA.LevelReached.IsValid;

        public bool LevelXLType1Reached =>
            LevelXLReached &&
            (SignatureLevelAnalysis.LevelX.
                 SignatureAndRefsTimestampsVerification?.All(
                     x => x.SameDigest?.IsValid ?? false && x.CertPathVerification.IsValid) ?? false);

        public bool LevelXLReached => SignatureLevelAnalysis.LevelXL.LevelReached.IsValid;

        public bool LevelXLType2Reached =>
            LevelXLReached &&
            (SignatureLevelAnalysis.LevelX.
                ReferencesTimestampsVerification?
                        .All(x => x.SameDigest?.IsValid ?? false && x.CertPathVerification.IsValid) ?? false);

        public bool LevelXReached => SignatureLevelAnalysis.LevelX.LevelReached.IsValid;

        public bool LevelXType1Reached =>
            LevelXReached &&
            (SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?.Any() ?? false);

        public bool LevelXType2Reached =>
            LevelXReached &&
            (SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification?.Any() ?? false);

        public bool LevelCReached =>
            SignatureLevelAnalysis.LevelC.LevelReached.IsValid ||
            SignatureLevelAnalysis.LevelC.LevelReached.IsUndetermined;

        public bool LevelTReached =>
            SignatureLevelAnalysis.LevelT.LevelReached.IsValid ||
            SignatureLevelAnalysis.LevelT.LevelReached.IsUndetermined;

        public bool LevelEPESReached => SignatureLevelAnalysis.LevelEPES.LevelReached.IsValid;

        public bool LevelBESReached => SignatureLevelAnalysis.LevelBES.LevelReached.IsValid;

        public SignatureInformation(
                SignatureVerification signatureVerification,
                CertPathRevocationAnalysis certPathRevocationAnalysis,
                SignatureLevelAnalysis signatureLevelAnalysis,
                IValidationContext ctx)
        {
            ValidationContext = ctx;
            SignatureVerification = signatureVerification;
            CertPathRevocationAnalysis = certPathRevocationAnalysis;
            SignatureLevelAnalysis = signatureLevelAnalysis;
        }
        public List<string[]> GetLevelDescriptionForTarget(
            SignatureProfile targetSignatureProfile)
        {
            var result = new List<string[]>();

            if (new[]
                {
                    SignatureProfile.T,
                    SignatureProfile.C,
                    SignatureProfile.XL,
                    SignatureProfile.XLType1,
                    SignatureProfile.XLType2,
                    SignatureProfile.XType1,
                    SignatureProfile.XType2,
                    SignatureProfile.A
                }.Any(x => x == targetSignatureProfile) || this.SignatureLevelAnalysis.LevelT.LevelReached.IsValid)
            {
                result.Add(
                new string[]{
                    SignatureProfile.T.GetDescription() ?? string.Empty,
                        this.SignatureLevelAnalysis.LevelT.LevelReached.Status.GetDescription() ?? string.Empty,
                        string.Join(". ", new[]
                        {
                            PrepareForLocalization(this.SignatureLevelAnalysis.LevelT.LevelReached.Description),
                            GetTimestampLocalizationString(this.SignatureLevelAnalysis.LevelT.SignatureTimestampVerification),
                        }.Where(x => !string.IsNullOrEmpty(x)))
                });
            }

            if (new[]
                {
                    SignatureProfile.C,
                    SignatureProfile.XL,
                    SignatureProfile.XLType1,
                    SignatureProfile.XLType2,
                    SignatureProfile.XType1,
                    SignatureProfile.XType2,
                    SignatureProfile.A

                }.Any(x => x == targetSignatureProfile) || this.SignatureLevelAnalysis.LevelC.LevelReached.IsValid)
            {
                result.Add(new string[]{
                        SignatureProfile.C.GetDescription() ?? string.Empty,
                        this.SignatureLevelAnalysis.LevelC.LevelReached.Status.GetDescription() ?? string.Empty,
                        string.Join(". ", new[]
                        {
                            PrepareForLocalization(this.SignatureLevelAnalysis.LevelC.LevelReached.Description),
                            PrepareForLocalization(this.SignatureLevelAnalysis.LevelC.CertificateRefsVerification?.Description),
                            PrepareForLocalization(this.SignatureLevelAnalysis.LevelC.RevocationRefsVerification?.Description),
                        }.Where(x => !string.IsNullOrEmpty(x)))
                    }
                );
            }

            if (new[] { SignatureProfile.XLType1, SignatureProfile.XType1, SignatureProfile.A }.Any(x => x == targetSignatureProfile)
                || this.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?.Length > 0)
            {
                result.Add(new string[]{
                        SignatureProfile.XType1.GetDescription() ?? string.Empty,
                        this.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?.Length > 0
                            ? this.SignatureLevelAnalysis.LevelX.LevelReached.Status.GetDescription() ?? string.Empty
                            : ResultStatus.INVALID.GetDescription() ?? string.Empty,
                        string.Join(". ", new[]
                        {
                            PrepareForLocalization(this.SignatureLevelAnalysis.LevelX.LevelReached.Description),
                            GetTimestampLocalizationString(this.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification),
                        }.Where(x => !string.IsNullOrEmpty(x)))
                    }
                );
            }

            if (new[] { SignatureProfile.XLType2, SignatureProfile.XType2 }.Any(x => x == targetSignatureProfile)
                || this.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification?.Length > 0)
            {
                result.Add(new string[]{
                        SignatureProfile.XType2.GetDescription() ?? string.Empty,
                        this.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification?.Length > 0
                            ? this.SignatureLevelAnalysis.LevelX.LevelReached.Status.GetDescription() ?? string.Empty
                            : ResultStatus.INVALID.GetDescription() ?? string.Empty,
                        string.Join(". ", new[]
                        {
                            PrepareForLocalization(this.SignatureLevelAnalysis.LevelX.LevelReached.Description),
                            GetTimestampLocalizationString(this.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification),
                        }.Where(x => !string.IsNullOrEmpty(x)))
                    }
                );
            }

            if (new[] { SignatureProfile.XL, SignatureProfile.XLType1, SignatureProfile.XLType2, SignatureProfile.A }.Any(x => x == targetSignatureProfile)
                || this.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid)
            {
                result.Add(new string[]{
                        SignatureProfile.XL.GetDescription() ?? string.Empty,
                        this.SignatureLevelAnalysis.LevelXL.LevelReached.Status.GetDescription() ?? string.Empty,
                        string.Join(". ",
                            new[]
                            {
                                PrepareForLocalization(this.SignatureLevelAnalysis.LevelXL.LevelReached.Description),
                                PrepareForLocalization(this.SignatureLevelAnalysis.LevelXL.CertificateValuesVerification?.Description),
                                PrepareForLocalization(this.SignatureLevelAnalysis.LevelXL.RevocationValuesVerification?.Description),
                            }.Where(x => !string.IsNullOrEmpty(x)))
                    }
                );
            }

            if (SignatureProfile.A == targetSignatureProfile
                || this.SignatureLevelAnalysis.LevelA.LevelReached.IsValid)
            {
                result.Add(new string[]{
                        SignatureProfile.A.GetDescription() ?? string.Empty,
                        this.SignatureLevelAnalysis.LevelA.ArchiveTimestampsVerification?.Count > 0
                            ? this.SignatureLevelAnalysis.LevelA.LevelReached.Status.GetDescription() ?? string.Empty
                            : ResultStatus.INVALID.GetDescription() ?? string.Empty,
                        string.Join(". ", new[]
                        {
                            PrepareForLocalization(this.SignatureLevelAnalysis.LevelA.LevelReached.Description),
                            GetTimestampLocalizationString(this.SignatureLevelAnalysis.LevelA.ArchiveTimestampsVerification),
                        }.Where(x => !string.IsNullOrEmpty(x)))
                    }
                );
            }

            return result;
        }

        public static string GetTimestampLocalizationString(ICollection<TimestampVerificationResult>? timestamps)
        {
            if (timestamps is not { Count: > 0 })
            {
                return string.Empty;
            }

            return string.Join(
                ", ",
                timestamps
                    .Select(x => PrepareForLocalization(x.CertPathVerification?.Description))
                    .Where(x => !string.IsNullOrEmpty(x)));
        }

        public static string? PrepareForLocalization(string? str) =>
            string.IsNullOrEmpty(str) ? str : $"{{{str}}}";

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
