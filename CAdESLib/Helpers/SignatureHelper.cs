using CAdESLib.Document.Validation;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using System.Linq;
using CAdESLib.Document.Signature.Extensions;
using NLog;

namespace CAdESLib.Helpers
{

    /// <summary>
    /// Состояние подписи для версии файла.
    /// </summary>
    public enum FileSignatureState
    {
        /// <summary>
        /// Подпись не была проверена.
        /// </summary>
        NotChecked = 0,

        /// <summary>
        /// Подпись была успешно проверена.
        /// </summary>
        Checked = 1,

        /// <summary>
        /// Подпись была неудачно проверена.
        /// </summary>
        Failed = 2,

        /// <summary>
        /// Целостность подписи проверена, но есть "один нюанс"
        /// </summary>
        CheckedWithWarning = 3
    }

    public static class Extensions
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        public static SignatureProfile GetWannaBeProfile(SignerInformation si)
        {
            if (si is null)
            {
                return SignatureProfile.None;
            }

            var result = SignatureProfile.BES;
            var unsignedAttributes = si.UnsignedAttributes;
            if (unsignedAttributes == null)
            {
                return result;
            }

            if (unsignedAttributes[PkcsObjectIdentifiers.IdAASignatureTimeStampToken] != null)
            {
                result = SignatureProfile.T;
            }
            else
            {
                return result;
            }

            if (unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertificateRefs] != null
                    || unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationRefs] != null)
            {
                result = SignatureProfile.C;
            }
            else
            {
                return result;
            }

            if (unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertValues] != null
                    || unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationValues] != null)
            {
                if (unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsEscTimeStamp] != null)
                {
                    result = SignatureProfile.XLType1;
                }
                else if (unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertCrlTimestamp] != null)
                {
                    result = SignatureProfile.XLType2;
                }
                else
                {
                    result = SignatureProfile.XL;
                }

            }
            else if (unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsEscTimeStamp] != null)
            {
                result = SignatureProfile.XType1;
            }
            else if (unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertCrlTimestamp] != null)
            {
                result = SignatureProfile.XType2;
            }
            if (unsignedAttributes[CAdESProfileA.id_aa_ets_archiveTimestamp_v3] != null)
            {
                result = SignatureProfile.A;
            }

            return result;
        }

        public static FileSignatureState GetSignatureState(
            SignatureInformation info,
            SignatureProfile targetSignatureProfile,
            bool strictValidation = false)
        {
            nloglogger.Trace("GetSignatureState");
            if (nloglogger.IsTraceEnabled)
            {
                nloglogger.Trace($"CertPath={info.CertPathRevocationAnalysis.Summary}");
                nloglogger.Trace($"LevelT={info.SignatureLevelAnalysis.LevelT.LevelReached}");
                nloglogger.Trace($"LevelC={info.SignatureLevelAnalysis.LevelC.LevelReached}");
                nloglogger.Trace($"LevelXL={info.SignatureLevelAnalysis.LevelXL.LevelReached}");
                nloglogger.Trace($"LevelX={info.SignatureLevelAnalysis.LevelX.LevelReached}");
                if (info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification is { } x1timestamps)
                {
                    nloglogger.Trace($"\tLevelX1");
                    foreach (var ts in x1timestamps)
                    {
                        nloglogger.Trace($"\t\tcertPath={ts.CertPathUpToTrustedList}");
                    }
                }
                if (info.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification is { } x2timestamps)
                {
                    nloglogger.Trace($"\tLevelX2");
                    foreach (var ts in x2timestamps)
                    {
                        nloglogger.Trace($"\t\tcertPath={ts.CertPathUpToTrustedList}");
                    }
                }
                nloglogger.Trace($"LevelA={info.SignatureLevelAnalysis.LevelA.LevelReached}");
                if (info.SignatureLevelAnalysis.LevelA.ArchiveTimestampsVerification is { } atimestamps)
                {
                    nloglogger.Trace($"\tLevelA");
                    foreach (var ts in atimestamps)
                    {
                        nloglogger.Trace($"\t\tcertPath={ts.CertPathUpToTrustedList}");
                    }
                }
            }

            if (info.CertPathRevocationAnalysis.Summary.IsInvalid)
            {
                return FileSignatureState.Failed;
            }

            switch (targetSignatureProfile)
            {
                case SignatureProfile.T:
                    if (!info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid)
                    {
                        if (info.SignatureLevelAnalysis.LevelT.LevelReached.IsUndetermined)
                        {
                            return FileSignatureState.CheckedWithWarning;
                        }
                        return FileSignatureState.Failed;
                    }

                    break;

                case SignatureProfile.C:
                    if (!info.SignatureLevelAnalysis.LevelC.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid)
                    {
                        return FileSignatureState.Failed;
                    }

                    break;

                case SignatureProfile.XType1:
                    if (!info.SignatureLevelAnalysis.LevelC.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid
                        || !(info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?.Length > 0)
                        || info.SignatureLevelAnalysis.LevelX.LevelReached.IsInvalid
                        || info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.Any(x => x.CertPathUpToTrustedList.IsInvalid)
                        )
                    {
                        return FileSignatureState.Failed;
                    }
                    else if (info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.Any(x => x.CertPathUpToTrustedList.IsUndetermined))
                    {
                        return FileSignatureState.CheckedWithWarning;
                    }

                    break;

                case SignatureProfile.XType2:
                    if (!info.SignatureLevelAnalysis.LevelC.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid
                        || !(info.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification?.Length > 0)
                        || info.SignatureLevelAnalysis.LevelX.LevelReached.IsInvalid
                        || info.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification.Any(x => x.CertPathUpToTrustedList.IsInvalid)
                        )
                    {
                        return FileSignatureState.Failed;
                    }
                    else if (info.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification.Any(x => x.CertPathUpToTrustedList.IsUndetermined))
                    {
                        return FileSignatureState.CheckedWithWarning;
                    }

                    break;

                case SignatureProfile.XL:
                    if (!info.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelC.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid)
                    {
                        return FileSignatureState.Failed;
                    }

                    break;

                case SignatureProfile.XLType1:
                    if (
                           !info.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelC.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid
                        || !(info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?.Length > 0)
                        || info.SignatureLevelAnalysis.LevelX.LevelReached.IsInvalid
                        || info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.Any(x => x.CertPathUpToTrustedList.IsInvalid)
                        )
                    {
                        return FileSignatureState.Failed;
                    }
                    else if (info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.Any(x => x.CertPathUpToTrustedList.IsUndetermined))
                    {
                        return FileSignatureState.CheckedWithWarning;
                    }


                    break;

                case SignatureProfile.XLType2:
                    if (
                           !info.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelC.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid
                        || !(info.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification?.Length > 0)
                        || info.SignatureLevelAnalysis.LevelX.LevelReached.IsInvalid
                        || info.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification.Any(x => x.CertPathUpToTrustedList.IsInvalid)
                        )
                    {
                        return FileSignatureState.Failed;
                    }
                    else if (info.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification.Any(x => x.CertPathUpToTrustedList.IsUndetermined))
                    {
                        return FileSignatureState.CheckedWithWarning;
                    }


                    break;

                case SignatureProfile.A:
                    if (
                           !info.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelC.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid
                        || !(info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?.Length > 0)
                        || !info.SignatureLevelAnalysis.LevelX.LevelReached.IsValid
                        || info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.Any(x => !x.CertPathUpToTrustedList.IsValid)
                        || !(info.SignatureLevelAnalysis.LevelA.ArchiveTimestampsVerification?.Count > 0)
                        || !info.SignatureLevelAnalysis.LevelA.LevelReached.IsValid)
                    {
                        return FileSignatureState.Failed;
                    }

                    var archiveTimestampsVerification = info.SignatureLevelAnalysis.LevelA.ArchiveTimestampsVerification;
                    if (archiveTimestampsVerification.Any(x => x.CertPathVerification.IsInvalid))
                    {
                        return FileSignatureState.Failed;
                    }

                    if (archiveTimestampsVerification.Any(x => !x.CertPathVerification.IsValid))
                    {
                        return FileSignatureState.CheckedWithWarning;
                    }

                    break;
            }

            if (targetSignatureProfile != SignatureProfile.A)
            {
                var signatureTimestampsVerification = info.SignatureLevelAnalysis.LevelT.SignatureTimestampVerification;
                if (signatureTimestampsVerification.Any(x => x.CertPathVerification.IsInvalid))
                {
                    return FileSignatureState.Failed;
                }

                if (signatureTimestampsVerification.Any(x => !x.CertPathVerification.IsValid))
                {
                    return FileSignatureState.CheckedWithWarning;
                }
            }

            // here than intermediate result is a checked
            if (info.CertPathRevocationAnalysis.Summary.IsValid)
            {
                return FileSignatureState.Checked;
            }
            else
            {
                if (targetSignatureProfile == SignatureProfile.A ||
                        targetSignatureProfile == SignatureProfile.XLType1 ||
                        targetSignatureProfile == SignatureProfile.XLType2)
                {
                    return FileSignatureState.Failed;
                }
                else
                {
                    return FileSignatureState.CheckedWithWarning;
                }
            }
        }

        public static SignatureProfile GetLevelReached(SignatureInformation info)
        {
            if (info is null)
            {
                return SignatureProfile.None;
            }

            if (info.LevelAReached)
            {
                return SignatureProfile.A;
            }

            if (info.LevelXLType1Reached)
            {
                return SignatureProfile.XLType1;
            }

            if (info.LevelXLType2Reached)
            {
                return SignatureProfile.XLType2;
            }

            if (info.LevelXLReached)
            {
                return SignatureProfile.XL;
            }

            if (info.LevelXType1Reached)
            {
                return SignatureProfile.XType1;
            }

            if (info.LevelXType2Reached)
            {
                return SignatureProfile.XType2;
            }

            if (info.LevelCReached)
            {
                return SignatureProfile.C;
            }

            if (info.LevelTReached)
            {
                return SignatureProfile.T;
            }

            if (info.LevelEPESReached)
            {
                return SignatureProfile.EPES;
            }

            if (info.LevelBESReached)
            {
                return SignatureProfile.BES;
            }

            return SignatureProfile.None;
        }
    }
}
