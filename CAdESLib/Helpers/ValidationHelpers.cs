using System;
using System.Linq;
using System.Collections.Generic;
using CAdESLib.Document.Validation;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Cms;
using NLog;
using Org.BouncyCastle.Asn1;
using PkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
using System.Text.RegularExpressions;
using static CAdESLib.Document.Validation.SignatureValidationResult;

namespace CAdESLib.Helpers
{
    public class ValidationHelper
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        public static List<SignatureValidationInfo> GetValidationInfos(
        SignatureType targetSignatureType,
        SignatureProfile targetSignatureProfile,
        ValidationReport? report, 
        ICurrentTimeGetter? currentTimeGetter = null)
        {
            currentTimeGetter ??= new CurrentTimeGetter();
            var signaturesValidations = new List<SignatureValidationInfo>();

            if (report is null)
            {
                return signaturesValidations;
            }

            foreach (var signatureInfo in report.SignatureInformationList)
            {
                if (signatureInfo is null)
                {
                    signaturesValidations.Add(
                        new SignatureValidationInfo
                        {
                            State = FileSignatureState.NotChecked
                        });
                    continue;
                }

                var reachedLevel = Extensions.GetLevelReached(signatureInfo);
                var cert = signatureInfo.SignatureLevelAnalysis.Signature.SigningCertificate!;
                var signingDate = signatureInfo.SignatureLevelAnalysis.Signature.SigningTime?.Value;
                var startDate =
                    signatureInfo
                        .SignatureLevelAnalysis
                        .Signature
                        .SignatureTimestamps?
                        .FirstOrDefault()?
                        .GetGenTimeDate()
                    ?? signingDate
                    ?? currentTimeGetter.CurrentUtcTime;
                var endDate =
                    signatureInfo.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?.Select(x => x.CreationTime).FirstOrDefault() ??
                    signatureInfo.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification?.Select(x => x.CreationTime).FirstOrDefault() ??
                    currentTimeGetter.CurrentUtcTime;
                var endDateForXLT1 =
                    signatureInfo.SignatureLevelAnalysis.LevelA.ArchiveTimestampsVerification?.Select(x => x.CreationTime).OrderBy(x => x).FirstOrDefault() ??
                    currentTimeGetter.CurrentUtcTime;
                var archiveTimes = new List<DateTime?>
                {
                    currentTimeGetter.CurrentUtcTime
                };
                var archiveTimestamps = signatureInfo.SignatureLevelAnalysis.LevelA.ArchiveTimestampsVerification?.OrderByDescending(x => x.CreationTime);
                if (archiveTimestamps is not null)
                {
                    archiveTimes.AddRange(archiveTimestamps.Select(x => x.CreationTime));
                }

                var revocationInfo = signatureInfo.ValidationContext.RevocationInfoDict[cert.GetHashCode()];

                signaturesValidations.Add(
                    new SignatureValidationInfo
                    {
                        State = Extensions.GetSignatureState(signatureInfo, (SignatureProfile)targetSignatureProfile),
                        SigningCertificateValidityDesc = signatureInfo.CertPathRevocationAnalysis.Summary.Description,
                        SigningCertificate = GetCertificateObject(cert),
                        SigningDate = signingDate,
                        VerifiedSigningDate = signatureInfo.SignatureLevelAnalysis.Signature.SignatureTimestamps?.FirstOrDefault()?.GetGenTimeDate(),
                        ReachedLevelErrorDesc = signatureInfo.GetLevelDescriptionForTarget((SignatureProfile)targetSignatureProfile).ToArray(),
                        TimestampsT = GetTimestampObject(signatureInfo.SignatureLevelAnalysis.LevelT.SignatureTimestampVerification, signatureInfo, endDate),
                        TimestampsXRefs = GetTimestampObject(signatureInfo.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification, signatureInfo, endDateForXLT1),
                        TimestampsXSigAndRefs = GetTimestampObject(signatureInfo.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification, signatureInfo, endDateForXLT1),
                        TimestampsA = archiveTimestamps?.Zip(
                                archiveTimes,
                                (t, d) =>
                                    GetTimestampObject(new List<TimestampVerificationResult> { t }, signatureInfo, d!.Value)
                        ).SelectMany(x => x).ToArray() ?? new TimestampInfo[0],
                        Log = signatureInfo.ValidationLog
                            .Select(l =>
                                new LoggerEntry
                                {
                                    LogLevel = (LogLevel)l.LogLevel,
                                    LogMessage = l.Message
                                })
                            .ToArray(),
                        ReachedSignatureType = (SignatureType)SignatureType.CAdES,
                        ReachedSignatureProfile = (SignatureProfile)reachedLevel,
                        TargetSignatureProfile = targetSignatureProfile,
                        TargetSignatureType = targetSignatureType,
                        CertsData = GetCertsDataForCertAndTime(revocationInfo, cert, startDate, endDate),
                    });
            }

            return signaturesValidations;
        }

        private static Dictionary<string, CertificateVerificationData>? GetCertsDataForCertAndTime(
                RevocationInfo revocationInfo,
                X509Certificate cert,
                DateTime startDate,
                DateTime endDate)
        {
            var chain = revocationInfo.GetCertsChain(
                                cert!,
                                startDate,
                                endDate);

            if (nloglogger.IsTraceEnabled)
            {
                nloglogger.Trace("certsdata for cert:" + cert.SubjectDN);
                foreach (var a in chain)
                {
                    nloglogger.Trace("\t" + a.Certificate.SubjectDN);
                    nloglogger.Trace($"\t\tverifCount={a.CertificateVerifications.Count}, subjectDN={a.Certificate.SubjectDN}");
                    nloglogger.Trace($"\t\tverifs={string.Join(", ", a.CertificateVerifications.Select(x => x.CertificateStatus.CertificateStatus.StatusSource))}");
                }
            }

            return GetCertsData(
                            chain!
                            .Select(x =>
                                x.CertificateVerifications.FirstOrDefault(x => x.CertificateStatus.CertificateStatus.IsValidForTime(startDate, endDate))!
                            ),
                        startDate,
                        endDate,
                        revocationInfo);
        }


        public static X509Certificate[]? GetSignatureCertificateChain(byte[] sig)
        {
            try
            {
                return new CmsSignedData(sig).GetCertificates("Collection").GetMatches(null).Cast<X509Certificate>().ToArray();
            }
            catch (Exception ex)
            {
                nloglogger.Warn(ex.Message + "\n" + ex.StackTrace);
                return null;
            }
        }

        public static (DateTime? dateTime, string? encryptOid, string? digestOid) GetDateTimeDigestAndEcryptOid(byte[] eds)
        {
            DateTime? dateTime = null;
            string? encryptOid = null;
            string? digestOid = null;
            try
            {
                var cms = new CmsSignedData(eds);
                var e = cms.GetSignerInfos().GetSigners().GetEnumerator();

                if (!e.MoveNext()
                    || e.Current is not SignerInformation si)
                {
                    return default;
                }

                digestOid = si.DigestAlgOid;
                encryptOid = si.EncryptionAlgOid;
                dateTime = ((DerUtcTime)si.SignedAttributes[PkcsObjectIdentifiers.Pkcs9AtSigningTime].AttrValues[0]).ToDateTime();
            }
            catch (Exception ex)
            {
                nloglogger.Warn(ex.Message + "\n" + ex.StackTrace);
            }

            return (dateTime, encryptOid, digestOid);

        }

        public static CertificateData GetCertificateObject(X509Certificate? cert)
        {
            var subject = cert?.SubjectDN.ToString() ?? string.Empty;
            var subjectName = EDSCertificateHelper.GetSubjectNameAdvanced(subject);
            var issuerName = EDSCertificateHelper.GetSubjectNameAdvanced(cert?.IssuerDN.ToString() ?? string.Empty);

            return new CertificateData
            {
                SubjectName = subjectName,
                IssuerName = issuerName,
                ValidFrom = cert?.NotBefore,
                ValidTo = cert?.NotAfter,
                Company = EDSCertificateHelper.ParseSubject(subject, EDSCertificateHelper.CompanyFindString),
                SerialNumber = cert?.SerialNumber.ToString(16) ?? string.Empty
            };
        }

        public static TimestampInfo[] GetTimestampObject(
            ICollection<TimestampVerificationResult>? collection,
            SignatureInformation signatureInfo,
            DateTime endDate)
        {
            if (collection is not { Count: > 0 })
            {
                return new TimestampInfo[0];
            }

            return collection
                .Select(t =>
                        {
                            var revocationInfo = signatureInfo.ValidationContext.RevocationInfoDict[t.Token!.GetHashCode()];
                            return new TimestampInfo
                            {
                                SerialNumber = t.SerialNumber,
                                CreationTime = t.CreationTime,
                                IssuerName = t.IssuerName,
                                IssuerSerialNumber = t.Issuer?.SerialNumber?.ToString(16),
                                Status = t.SameDigest!.Status.GetDescription(),
                                StatusDescription = t.SameDigest.Description,
                                CertStatus = t.CertPathVerification.Status.GetDescription(),
                                CertStatusDescription = t.CertPathVerification.Description,
                                State = GetSignatureState(t.SameDigest.Status, t.CertPathVerification.Status),
                                CertsData = GetCertsDataForCertAndTime(revocationInfo, t.Issuer!, t.CreationTime!.Value, endDate),
                            };
                        })
                .ToArray();
        }

        public static FileSignatureState GetSignatureState(ResultStatus signatureStatus, ResultStatus certRevocationStatus)
        {
            var result = signatureStatus switch
            {
                ResultStatus.VALID => FileSignatureState.Checked,
                ResultStatus.INVALID => FileSignatureState.Failed,
                ResultStatus.UNDETERMINED => FileSignatureState.NotChecked,
                ResultStatus.VALID_WITH_WARNINGS => FileSignatureState.CheckedWithWarning,
                ResultStatus.INFORMATION => FileSignatureState.NotChecked,
                _ => FileSignatureState.NotChecked,
            };

            return result switch
            {
                FileSignatureState.Checked => certRevocationStatus switch
                {
                    ResultStatus.INVALID => FileSignatureState.CheckedWithWarning,
                    ResultStatus.UNDETERMINED => FileSignatureState.CheckedWithWarning,
                    ResultStatus.VALID_WITH_WARNINGS => FileSignatureState.CheckedWithWarning,
                    _ => result,
                },
                _ => result,
            };
        }


        public static Dictionary<string, CertificateVerificationData> GetCertsData(
            IEnumerable<CertificateVerification> x509Certificates,
            DateTime startDate,
            DateTime endDate,
            RevocationInfo revocationInfo)
        {
            var result = new Dictionary<string, CertificateVerificationData>();
            foreach (var cert in x509Certificates)
            {
                nloglogger.Trace($"GetCertsData item. validity={cert?.CertificateStatus?.CertificateStatus?.Validity}, source={cert?.CertificateStatus?.CertificateStatus?.StatusSource}");
                if (cert?.Certificate is null)
                {
                    continue;
                }

                var subject = cert.Certificate.SubjectDN.ToString();

                var subjectName = EDSCertificateHelper.GetSubjectNameAdvanced(subject);
                var issuerName = EDSCertificateHelper.GetSubjectNameAdvanced(cert.Certificate.IssuerDN.ToString() ?? string.Empty);
                var issuerSerialNumber = cert.CertificateAndContext.IssuerCertificate?.Certificate.SerialNumber;

                var ocspRespTokens = revocationInfo.GetRelatedOCSPRespTokens(
                            cert.CertificateAndContext,
                            startDate,
                            endDate,
                            true)
                        .Distinct();

                result.Add(cert.Certificate.SerialNumber.ToString(16), new CertificateVerificationData
                {
                    SubjectName = subjectName,
                    IssuerName = issuerName,
                    IssuerSerialNumber = issuerSerialNumber?.ToString(16),
                    ValidFrom = cert.Certificate.NotBefore,
                    ValidTo = cert.Certificate.NotAfter,
                    Company = EDSCertificateHelper.ParseSubject(subject, EDSCertificateHelper.CompanyFindString),
                    SerialNumber = cert.Certificate.SerialNumber.ToString(16) ?? string.Empty,
                    Data = cert.Certificate.GetEncoded(),
                    Status = cert.Summary.Status.GetDescription(),
                    StatusDescription = cert.Summary.Description,
                    CertificateSourceType = cert.CertificateAndContext.CertificateSource,
                    OcspInfos = ocspRespTokens
                        .Select(x => GetOcspTokenObject(x, startDate, endDate, revocationInfo))
                        .ToArray(),
                    CrlInfos = revocationInfo.GetRelatedCRLTokens(
                            cert.CertificateAndContext,
                            startDate,
                            endDate,
                            true)
                        .Distinct()
                        .Select(x => GetCrlTokenObject(x, startDate, endDate, revocationInfo))
                        .ToArray()
                });
            }

            return result;
        }

        public static CrlInfo GetCrlTokenObject(
            CRLToken crlToken,
            DateTime startDate,
            DateTime endDate,
            RevocationInfo revocationInfo)
        {
            var crl = crlToken.Crl;
            var issuerDN = EDSCertificateHelper.GetSubjectNameAdvanced(crl.IssuerDN?.ToString() ?? string.Empty);
            var issueSerialNumber = crlToken.GetSigner()?.SerialNumber;
            return new CrlInfo
            {
                IssuerDN = issuerDN,
                IssuerSerialNumber = issueSerialNumber?.ToString(16),
                NextUpdate = crl.NextUpdate?.Value,
                ThisUpdate = crl.ThisUpdate,
                SigAlgName = crl.SigAlgName,
                SigAlgOid = crl.SigAlgOid,
                Data = crl.GetEncoded(),
                Status = revocationInfo.GetCrlStatus(crlToken, startDate, endDate).Status.GetDescription()
            };
        }

        public static OcspInfo GetOcspTokenObject(
            OCSPRespToken ocspRespToken,
            DateTime startDate,
            DateTime endDate,
            RevocationInfo revocationInfo)
        {
            var x = ocspRespToken.OcspResp;
            var subjectDN = EDSCertificateHelper.GetSubjectNameAdvanced(ocspRespToken.GetSignerSubjectName()?.ToString() ?? string.Empty);
            var signerSerialNumber = ocspRespToken.GetSignerSerialNumber()?.ToString(16);
            if (string.IsNullOrEmpty(subjectDN) || string.IsNullOrEmpty(signerSerialNumber))
            {
                var relatedCert = revocationInfo.GetIssuerCertificateAndContext(ocspRespToken).FirstOrDefault();
                if (relatedCert is not null)
                {
                    subjectDN = EDSCertificateHelper.GetSubjectNameAdvanced(relatedCert.Certificate.SubjectDN.ToString() ?? string.Empty);
                    signerSerialNumber = relatedCert.Certificate.SerialNumber.ToString(16);
                }
            }

            return new OcspInfo
            {
                SignaturePart = BitConverter.ToString(x.GetSignature()[0..8]),
                ProducedAt = x.ProducedAt,
                ThisUpdate = x.Responses.FirstOrDefault()?.ThisUpdate,
                NextUpdate = x.Responses.FirstOrDefault()?.NextUpdate?.Value,
                SubjectDN = subjectDN,
                SignerSerialNumber = signerSerialNumber,
                SigAlgName = x.SignatureAlgName,
                SigAlgOid = x.SignatureAlgOid,
                Status = revocationInfo.GetOcspStatus(x, startDate, endDate).Status.GetDescription()
            };
        }
    }

    public class SignatureValidationInfo
    {
        #region Properties

        public FileSignatureState Integrity { get; set; }

        public FileSignatureState State { get; set; }

        public string? SigningCertificateValidityDesc { get; set; }

        public CertificateData? SigningCertificate { get; set; }

        public DateTime? SigningDate { get; set; }

        public DateTime? VerifiedSigningDate { get; set; }

        public string[][]? ReachedLevelErrorDesc { get; set; }

        public SignatureType ReachedSignatureType { get; set; }

        public SignatureProfile ReachedSignatureProfile { get; set; }

        public SignatureProfile TargetSignatureProfile { get; set; }

        public SignatureType TargetSignatureType { get; set; }

        public IReadOnlyList<LoggerEntry>? Log { get; set; }

        public Dictionary<string, CertificateVerificationData>? CertsData { get; set; }

        public IReadOnlyList<TimestampInfo>? TimestampsT { get; set; }

        public IReadOnlyList<TimestampInfo>? TimestampsXRefs { get; set; }

        public IReadOnlyList<TimestampInfo>? TimestampsXSigAndRefs { get; set; }

        public IReadOnlyList<TimestampInfo>? TimestampsA { get; set; }

        #endregion

    }

    public class LoggerEntry
    {
        #region Properties

        public LogLevel LogLevel { get; set; }

        public string? LogMessage { get; set; }

        #endregion
    }

    public class CertificateData
    {
        #region Properties

        /// <summary>
        /// Наименование организации субъекта сертификата.
        /// </summary>
        public string? Company { get; set; }

        /// <summary>
        /// Имя субъекта сертификата.
        /// </summary>
        public string? SubjectName { get; set; }

        /// <summary>
        /// Имя издателя сертификата.
        /// </summary>
        public string? IssuerName { get; set; }

        /// <summary>
        /// Серийный номер сертификата.
        /// </summary>
        public string? SerialNumber { get; set; }

        /// <summary>
        /// Дата начала срока действия сертификата.
        /// </summary>
        public DateTime? ValidFrom { get; set; }

        /// <summary>
        /// Дата окончания срока действия сертификата.
        /// </summary>
        public DateTime? ValidTo { get; set; }

        /// <summary>
        /// Строковое представление отпечатка сертификата.
        /// </summary>
        public string? Thumbprint { get; set; }

        #endregion

    }

    public static class EDSCertificateHelper
    {
        #region Internal Constants

        public const string CompanyFindString = "O=";
        public const string SubjectlNameFindString = "CN=";
        public const string IssuerNameFindString = "CN=";
        public const string CompanyUnitFindString = "OU=";
        public const string WinSurnameFindString = "SN=";
        public const string WinGivennameFindString = "G=";
        public const string BcSurnameFindString = "SURNAME=";
        public const string BcGivennameFindString = "GIVENNAME=";

        #endregion

        #region Methods

        public static string? ParseSubject(string str, string findString)
        {
            var indexOfFind = str.IndexOf(findString, StringComparison.Ordinal);
            if (indexOfFind == -1)
            {
                return null;
            }

            var tmpString = str[(indexOfFind + findString.Length)..];
            var match = Regex.Match(tmpString, "[+,]");

            var indexOfCompanyEnd = -1;

            if (match.Success)
            {
                indexOfCompanyEnd = match.Index;
            }

            return UnescapeQuotes(indexOfCompanyEnd != -1
                ? tmpString[..indexOfCompanyEnd].Trim()
                : tmpString);
        }

        public static string? UnescapeQuotes(string? v) => v?.Replace("\\\"", "\"", StringComparison.Ordinal);

        public static string GetSubjectNameAdvanced(string subjectStr) =>
            GetSurnameGivenname(subjectStr, WinSurnameFindString, WinGivennameFindString)
            ?? GetSurnameGivenname(subjectStr, BcSurnameFindString, BcGivennameFindString)
            ?? string.Join(", ", new[] { ParseSubject(subjectStr, CompanyUnitFindString), ParseSubject(subjectStr, SubjectlNameFindString) }.Where(x => !string.IsNullOrEmpty(x)));


        #endregion

        #region public Methods

        public static string? GetSurnameGivenname(string subjectStr, string surnameFindString, string givennameFindString)
        {
            // bounceCastel symbols
            var snStr = ParseSubject(subjectStr, surnameFindString);
            var gStr = ParseSubject(subjectStr, givennameFindString);

            // Если есть фамилия
            if (!string.IsNullOrEmpty(snStr))
            {
                // Если есть имя (имя  + отчество)
                if (!string.IsNullOrEmpty(gStr))
                {
                    return snStr + " " + gStr;
                }

                return snStr;
            }

            return null;
        }

        #endregion
    }

    public class TimestampInfo
    {
        #region Properties

        public string? SerialNumber { get; set; }

        public DateTime? CreationTime { get; set; }

        public string? IssuerName { get; set; }

        public string? Status { get; set; }

        public string? StatusDescription { get; set; }

        public string? CertStatus { get; set; }

        public string? CertStatusDescription { get; set; }

        public FileSignatureState State { get; set; }

        public string? IssuerSerialNumber { get; set; }

        public Dictionary<string, CertificateVerificationData>? CertsData { get; set; }

        #endregion
    }

    public class CertificateVerificationData : CertificateData
    {
        #region Properties

        public byte[]? Data { get; set; }

        public string? Status { get; set; }

        public string? StatusDescription { get; set; }

        public CertificateSourceType CertificateSourceType { get; set; }

        public IReadOnlyList<OcspInfo>? OcspInfos { get; set; }

        public IReadOnlyList<CrlInfo>? CrlInfos { get; set; }

        public string? IssuerSerialNumber { get; set; }

        #endregion
    }

    public class OcspInfo
    {
        public string? SignaturePart { get; set; }

        public string? SubjectDN { get; set; }

        public DateTime? ProducedAt { get; set; }

        public DateTime? ThisUpdate { get; set; }

        public DateTime? NextUpdate { get; set; }

        public string? SigAlgName { get; set; }

        public string? SigAlgOid { get; set; }

        public string? SignerSerialNumber { get; set; }

        public string? Status { get; set; }
    }


    public class CrlInfo
    {

        public string? IssuerDN { get; set; }

        public DateTime? NextUpdate { get; set; }

        public DateTime? ThisUpdate { get; set; }

        public string? SigAlgName { get; set; }

        public string? SigAlgOid { get; set; }

        public string? IssuerSerialNumber { get; set; }

        public byte[]? Data { get; set; }

        public string? Status { get; set; }
    }
}
