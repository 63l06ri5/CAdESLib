﻿using CAdESLib.Document;
using CAdESLib.Document.Signature;
using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using CAdESLib.Service;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using Unity;
using Unity.Lifetime;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.Math;
using System.Collections;
using Org.BouncyCastle.X509.Store;

namespace CAdESLib.Tests
{
    [TestFixture]
    public class Tests
    {
        private UnityContainer unityContainer;

        private AsymmetricCipherKeyPair ocspCAKeyPair;
        private X509Certificate ocspCACert;
        private AsymmetricCipherKeyPair ocspKeyPair;
        private X509Certificate ocspCert;

        private AsymmetricCipherKeyPair crlCAKeyPair;
        private X509Certificate crlCACert;
        private AsymmetricCipherKeyPair crlKeyPair;
        private X509Certificate crlCert;

        private AsymmetricCipherKeyPair tspCAKeyPair;
        private X509Certificate tspCACert;
        private AsymmetricCipherKeyPair tspKeyPair;
        private X509Certificate tspCert;

        [TestCaseSource("BESTestCaseSource")]
        public void TestSigProfiles(SignatureParams sigParams, SignatureVerificationResults sigResult)
        {
            var ca = new X509Name("CN=ca");
            var caKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            var caCert = CryptoHelpers.GenerateCertificate(ca, ca, caKeyPair.Private, caKeyPair.Public);

            var notBefore = DateTime.Now;
            var notAfter = DateTime.Now.AddHours(1);
            if (!(sigParams.SignatureCertTimeValid ?? true))
            {
                notBefore = DateTime.Now.AddHours(-2);
                notAfter = DateTime.Now.AddHours(-1);
            }
            var signingCertName = new X509Name("CN=singing_cert");
            var signingKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            var signingCert = CryptoHelpers.GenerateCertificate(ca, signingCertName, caKeyPair.Private, signingKeyPair.Public, notBefore, notAfter);

            var cadesSettings = new CAdESServiceSettings();
            if (sigParams.SignatureCertTrusted ?? true)
            {
                cadesSettings.TrustedCerts.Add(caCert);
            }
            if (sigParams.SignatureCertOCSP ?? true)
            {
                var fakeOcsp = unityContainer.Resolve<IOcspSource>() as FakeOnlineOcspSource;
                fakeOcsp.AddNotRevokedCert(signingCert, caCert);
            }
            if (sigParams.OCSPCertTrusted ?? true)
            {
                cadesSettings.TrustedCerts.Add(ocspCACert);
            }
            if ((sigParams.SignatureCertCRL ?? true))
            {
                var fakeCrl = unityContainer.Resolve<ICrlSource>() as FakeOnlineCrlSource;
                fakeCrl.AddRevokedCert(!(sigParams.SignatureCertCRL ?? true) ? signingCert : null, caCert, caKeyPair);
            }
            if (sigParams.TSSignatureCertTrusted ?? true)
            {
                cadesSettings.TrustedCerts.Add(tspCACert);
            }
            var cadesService = unityContainer.Resolve<Func<ICAdESServiceSettings, IDocumentSignatureService>>()(cadesSettings);
            // to be signed
            var inputData = Encoding.UTF8.GetBytes("anydataanydataanydataanydataanydataanydataanydataanydata");
            var inputDocument = new InMemoryDocument(inputData);
            var signingTime = DateTime.Now;
            var parameters = new SignatureParameters
            {
                SigningCertificate = signingCert,
                CertificateChain = new X509Certificate[] {  signingCert },
                SignaturePackaging = SignaturePackaging.DETACHED,
                SignatureProfile = sigParams.SignatureProfile,
                SigningDate = signingTime,
                DigestAlgorithmOID = DigestAlgorithm.SHA256.OID,
                EncriptionAlgorithmOID = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption.Id
            };
            var toBeSignedStream = cadesService.ToBeSigned(inputDocument, parameters);
            // sign
            ISigner signer = SignerUtilities.InitSigner(parameters.DigestWithEncriptionOID, true, signingKeyPair.Private, null);
            toBeSignedStream.Position = 0;
            toBeSignedStream.Seek(0, SeekOrigin.Begin);
            var b = Streams.ReadAll(toBeSignedStream);
            signer.BlockUpdate(b, 0, b.Length);
            var signatureValue = signer.GenerateSignature();
            if (!(sigParams.SignatureValid ?? false))
            {
                signatureValue[0] ^= 1;
            }
            // make pkcs7
            var signedDocument = cadesService.GetSignedDocument(inputDocument, parameters, signatureValue);

            // validate
            var report = cadesService.ValidateDocument(signedDocument, true, inputDocument);
            var sigInfo = report.SignatureInformationList[0];
            Assert.AreEqual(sigResult.SignatureVerification, sigInfo.SignatureVerification.SignatureVerificationResult.IsValid, "Signature value is invalid");
            Assert.AreEqual(sigResult.CertPathVerification, sigInfo.CertPathRevocationAnalysis.Summary.IsValid, $"Cert path is invalid: {sigInfo.CertPathRevocationAnalysis.Summary.Description}");

            if (sigResult.BESLevel.HasValue)
            {
                Assert.AreEqual(sigInfo.SignatureLevelAnalysis.LevelBES.LevelReached.IsValid, sigResult.BESLevel, "BES is not reached");
            }

            if (sigResult.TLevel.HasValue)
            {
                Assert.AreEqual(sigResult.TLevel, sigInfo.SignatureLevelAnalysis.LevelT.LevelReached.IsValid, "T is not reached");
                Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelT.SignatureTimestampVerification.All(x => (sigResult.TSignatureVerifications ?? true) && x.SameDigest.IsValid || !(sigResult.TSignatureVerifications ?? true) && !x.SameDigest.IsValid), "T timestamps are not valid");
                Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelT.SignatureTimestampVerification.All(x => (sigResult.TCertPathVerifications ?? true) && x.CertPathVerification.IsValid || !(sigResult.TCertPathVerifications ?? true) && !x.CertPathVerification.IsValid), "T cert paths are not valid");
            }

            if (sigResult.CLevel.HasValue)
            {
                Assert.AreEqual(sigResult.CLevel, sigInfo.SignatureLevelAnalysis.LevelC.LevelReached.IsValid, "C is not reached");
                Assert.AreEqual(sigResult.CCertRefs, sigInfo.SignatureLevelAnalysis.LevelC.CertificateRefsVerification.IsValid, "C cert refs are not valid");
                Assert.AreEqual(sigResult.CRevocationRefs, sigInfo.SignatureLevelAnalysis.LevelC.RevocationRefsVerification.IsValid, "C cert revocations refs are not valid");
            }

            if (sigResult.XLLevel.HasValue)
            {
                Assert.AreEqual(sigResult.XLLevel, sigInfo.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid, "XL is not reached");
                Assert.AreEqual(sigResult.CCertValues, sigInfo.SignatureLevelAnalysis.LevelXL.CertificateValuesVerification.IsValid, "XL cert values are not valid");
                Assert.AreEqual(sigResult.CRevocationRefs, sigInfo.SignatureLevelAnalysis.LevelXL.RevocationValuesVerification.IsValid, "XL cert revocations values are not valid");
            }

            if (sigResult.XType1Level.HasValue)
            {
                Assert.AreEqual(sigResult.XType1Level, sigInfo.SignatureLevelAnalysis.LevelX.LevelReached.IsValid, "XType1 is not reached");
                Assert.AreEqual(sigResult.CLevel, sigInfo.SignatureLevelAnalysis.LevelC.LevelReached.IsValid, "C is not reached");
                Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.All(x => (sigResult.XType1SignatureVerifications ?? true) && x.SameDigest.IsValid || !(sigResult.XType1SignatureVerifications ?? true) && !x.SameDigest.IsValid), "XType1 timestamps are not valid");
                Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.All(x => (sigResult.XType1CertPathVerifications ?? true) && x.CertPathVerification.IsValid || !(sigResult.XType1CertPathVerifications ?? true) && !x.CertPathVerification.IsValid), "XType1 cert paths are not valid");
            }

            if (sigResult.XType2Level.HasValue)
            {
                Assert.AreEqual(sigResult.XType2Level, sigInfo.SignatureLevelAnalysis.LevelX.LevelReached.IsValid, "XType2 is not reached");
                Assert.AreEqual(sigResult.CLevel, sigInfo.SignatureLevelAnalysis.LevelC.LevelReached.IsValid, "C is not reached");
                Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification.All(x => (sigResult.XType2SignatureVerifications ?? true) && x.SameDigest.IsValid || !(sigResult.XType2SignatureVerifications ?? true) && !x.SameDigest.IsValid), "XType2 timestamps are not valid");
                Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification.All(x => (sigResult.XType2CertPathVerifications ?? true) && x.CertPathVerification.IsValid || !(sigResult.XType2CertPathVerifications ?? true) && !x.CertPathVerification.IsValid), "XType2 cert paths are not valid");
            }

            if (sigResult.XLType1Level.HasValue)
            {
                Assert.AreEqual(sigResult.XLType1Level, sigInfo.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid, "XLType1 is not reached");
                Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.All(x => (sigResult.XType1SignatureVerifications ?? true) && x.SameDigest.IsValid || !(sigResult.XType1SignatureVerifications ?? true) && !x.SameDigest.IsValid), "XType1 timestamps are not valid");
                Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.All(x => (sigResult.XType1CertPathVerifications ?? true) && x.CertPathVerification.IsValid || !(sigResult.XType1CertPathVerifications ?? true) && !x.CertPathVerification.IsValid), "XType1 cert paths are not valid");
            }

            if (sigResult.XLType2Level.HasValue)
            {
                Assert.AreEqual(sigResult.XLType2Level, sigInfo.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid, "XLType2 is not reached");
                Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification.All(x => (sigResult.XType2SignatureVerifications ?? true) && x.SameDigest.IsValid || !(sigResult.XType2SignatureVerifications ?? true) && !x.SameDigest.IsValid), "XType2 timestamps are not valid");
                Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification.All(x => (sigResult.XType2CertPathVerifications ?? true) && x.CertPathVerification.IsValid || !(sigResult.XType2CertPathVerifications ?? true) && !x.CertPathVerification.IsValid), "XType2 cert paths are not valid");
            }

            if (sigResult.ALevel.HasValue)
            {
                Assert.AreEqual(sigResult.ALevel, sigInfo.SignatureLevelAnalysis.LevelA.LevelReached.IsValid, "A is not reached");
                Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelA.ArchiveTimestampsVerification.All(x => (sigResult.ASignatureVerifications ?? true) && x.SameDigest.IsValid || !(sigResult.ASignatureVerifications ?? true) && !x.SameDigest.IsValid), "A timestamps are not valid");
                Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelA.ArchiveTimestampsVerification.All(x => (sigResult.ACertPathVerifications ?? true) && x.CertPathVerification.IsValid || !(sigResult.ACertPathVerifications ?? true) && !x.CertPathVerification.IsValid), "A cert paths are not valid");
            }

        }

        [OneTimeSetUp]
        public void Setup()
        {
            {
                var ocspCA = new X509Name("CN=ocspCA");
                ocspCAKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
                ocspCACert = CryptoHelpers.GenerateCertificate(ocspCA, ocspCA, ocspCAKeyPair.Private, ocspCAKeyPair.Public);

                var ocsp = new X509Name("CN=ocsp");
                ocspKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
                ocspCert = CryptoHelpers.GenerateCertificate(ocspCA, ocsp, ocspCAKeyPair.Private, ocspKeyPair.Public);
            }

            {
                var crlCA = new X509Name("CN=crlCA");
                crlCAKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
                crlCACert = CryptoHelpers.GenerateCertificate(crlCA, crlCA, crlCAKeyPair.Private, crlCAKeyPair.Public);

                var crl = new X509Name("CN=crl");
                crlKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
                crlCert = CryptoHelpers.GenerateCertificate(crlCA, crl, crlCAKeyPair.Private, crlKeyPair.Public);
            }

            {
                var tspCA = new X509Name("CN=tspCA");
                tspCAKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
                tspCACert = CryptoHelpers.GenerateCertificate(tspCA, tspCA, tspCAKeyPair.Private, tspCAKeyPair.Public);

                var tsp = new X509Name("CN=tsp");
                tspKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
                tspCert = CryptoHelpers.GenerateCertificate(tspCA, tsp, tspCAKeyPair.Private, tspKeyPair.Public);
            }


            var fakeOnlineOCSPSource = new FakeOnlineOcspSource(ocspCert, ocspKeyPair);
            var fakeOnlineCrlSource = new FakeOnlineCrlSource(crlCert, crlKeyPair);
            var fakeOnlineTspSource = new FakeOnlineTspSource(tspCert, tspKeyPair);

            unityContainer = new UnityContainer();

            unityContainer
                .RegisterFactory<Func<ICAdESServiceSettings, IDocumentSignatureService>>(c => new Func<ICAdESServiceSettings, IDocumentSignatureService>(
                    (settings) => new CAdESService(c.Resolve<Func<ICAdESServiceSettings, ITspSource>>()(settings), c.Resolve<Func<ICAdESServiceSettings, ICertificateVerifier>>()(settings), c.Resolve<Func<ICAdESServiceSettings, ISignedDocumentValidator>>()(settings))
                    ))


                .RegisterFactory<Func<ICAdESServiceSettings, ICertificateVerifier>>(c => new Func<ICAdESServiceSettings, ICertificateVerifier>((settings) => new TrustedListCertificateVerifier(c.Resolve<Func<ICAdESServiceSettings, Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext>>>()(settings))))

                .RegisterFactory<Func<ICAdESServiceSettings, ISignedDocumentValidator>>(c => new Func<ICAdESServiceSettings, ISignedDocumentValidator>((settings) => new SignedDocumentValidator(c.Resolve<Func<ICAdESServiceSettings, ICertificateVerifier>>()(settings), c.Resolve<Func<ICAdESLogger>>())))


                .RegisterType<ICAdESLogger, CAdESLogger>(new TransientLifetimeManager())

                // for testing purposes
                .RegisterFactory<IOcspSource>(c => fakeOnlineOCSPSource)
                // for testing purposes
                .RegisterFactory<ICrlSource>(c => fakeOnlineCrlSource)

                .RegisterFactory<Func<ICAdESServiceSettings, ITspSource>>(c => new Func<ICAdESServiceSettings, ITspSource>((settings) => fakeOnlineTspSource))

                .RegisterFactory<Func<ICAdESServiceSettings, IOcspSource>>(c => new Func<ICAdESServiceSettings, IOcspSource>((settings) => fakeOnlineOCSPSource))

                .RegisterFactory<Func<ICAdESServiceSettings, ICrlSource>>(c => new Func<ICAdESServiceSettings, ICrlSource>((settings) => fakeOnlineCrlSource))

                .RegisterFactory<Func<ICAdESServiceSettings, ICertificateSource>>(c => new Func<ICAdESServiceSettings, ICertificateSource>((settings) => new ListCertificateSourceWithSetttings(settings)))

                .RegisterType<ICertificateSourceFactory, FakeAIACertificateFactoryImpl>(new TransientLifetimeManager())

                .RegisterFactory<Func<ICAdESServiceSettings, Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext>>>(c => new Func<ICAdESServiceSettings, Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext>>(
                  (settings) => (cert, date, logger) => new ValidationContext(cert, date, logger, c.Resolve<Func<ICAdESServiceSettings, IOcspSource>>()(settings), c.Resolve<Func<ICAdESServiceSettings, ICrlSource>>()(settings), c.Resolve<Func<ICAdESServiceSettings, ICertificateSource>>()(settings), c.Resolve<Func<IOcspSource, ICrlSource, ICertificateStatusVerifier>>(), c.Resolve<Func<CertificateAndContext, CertificateToken>>()))
                )
                .RegisterFactory<Func<IOcspSource, ICrlSource, ICertificateStatusVerifier>>(c =>
                    new Func<IOcspSource, ICrlSource, ICertificateStatusVerifier>((ocspVerifier, crlVerifier) => new OCSPAndCRLCertificateVerifier(new OCSPCertificateVerifier(ocspVerifier), new CRLCertificateVerifier(crlVerifier)))
                )
                .RegisterFactory<Func<CertificateAndContext, CertificateToken>>(c =>
                    new Func<CertificateAndContext, CertificateToken>((context) => new CertificateToken(context, c.Resolve<ICertificateSourceFactory>()))
                )
            ;
        }

        static IEnumerable<object> BESTestCaseSource()
        {
            using (var file = File.OpenText("TestCases.csv"))
            {
                // header
                var line = file.ReadLine();
                line = file.ReadLine();

                while ((line = file.ReadLine()) != null)
                {
                    if (line == null)
                    {
                        yield break;
                    }

                    var values = line.Split('\t');
                    // params
                    if (values[0]=="no")
                    {
                        continue;
                    }
                    var startIndex = 1;
                    SignatureProfile SignatureProfile = Enum.Parse<SignatureProfile>(values[startIndex + 0]);
                    bool? SignatureValid = GetBoolValue(values[startIndex + 1]);
                    bool? SignatureCertTimeValid = GetBoolValue(values[startIndex + 2]);
                    bool? SignatureCertTrusted = GetBoolValue(values[startIndex + 3]);
                    bool? SignatureCertOCSP = GetBoolValue(values[startIndex + 4]);
                    bool? SignatureCertCRL = GetBoolValue(values[startIndex + 5]);
                    bool? OCSPCertTrusted = GetBoolValue(values[startIndex + 6]);
                    //bool? CRLCertTrusted = GetBoolValue(values[startIndex + 7]);
                    bool? TSSignatureCertTrusted = GetBoolValue(values[startIndex + 8]);
                    // results
                    bool SignatureVerification = GetBoolValue(values[startIndex + 9]).Value;
                    bool CertPathVerification = GetBoolValue(values[startIndex + 10]).Value;
                    bool? BESLevel = GetBoolValue(values[startIndex + 11]);
                    bool? TLevel = GetBoolValue(values[startIndex + 12]);
                    bool? TSignatureVerifications = GetBoolValue(values[startIndex + 13]);
                    bool? TCertPathVerifications = GetBoolValue(values[startIndex + 14]);
                    bool? CLevel = GetBoolValue(values[startIndex + 15]);
                    bool? CCertRefs = GetBoolValue(values[startIndex + 16]);
                    bool? CRevocationRefs = GetBoolValue(values[startIndex + 17]);
                    bool? XType1Level = GetBoolValue(values[startIndex + 18]);
                    bool? XType1SignatureVerifications = GetBoolValue(values[startIndex + 19]);
                    bool? XType1CertPathVerifications = GetBoolValue(values[startIndex + 20]);
                    bool? XType2Level = GetBoolValue(values[startIndex + 21]);
                    bool? XType2SignatureVerifications = GetBoolValue(values[startIndex + 22]);
                    bool? XType2CertPathVerifications = GetBoolValue(values[startIndex + 23]);
                    bool? XLLevel = GetBoolValue(values[startIndex + 24]);
                    bool? CCertValues = GetBoolValue(values[startIndex + 25]);
                    bool? CRevocationValues = GetBoolValue(values[startIndex + 26]);
                    bool? XLType1Level = GetBoolValue(values[startIndex + 27]);
                    bool? XLType2Level = GetBoolValue(values[startIndex + 28]);
                    bool? ALevel = GetBoolValue(values[startIndex + 29]);
                    bool? ASignatureVerifications = GetBoolValue(values[startIndex + 30]);
                    bool? ACertPathVerifications = GetBoolValue(values[startIndex + 31]);

                    yield return new object[] {
                        new SignatureParams {
                            SignatureProfile = SignatureProfile,
                            SignatureValid = SignatureValid,
                            SignatureCertTimeValid = SignatureCertTimeValid,
                            SignatureCertTrusted = SignatureCertTrusted,
                            SignatureCertOCSP = SignatureCertOCSP,
                            SignatureCertCRL = SignatureCertCRL,
                            OCSPCertTrusted = OCSPCertTrusted,
                            //CRLCertTrusted = CRLCertTrusted,
                            TSSignatureCertTrusted = TSSignatureCertTrusted
                        },
                        new SignatureVerificationResults {
                            SignatureVerification = SignatureVerification,
                            CertPathVerification= CertPathVerification,
                            BESLevel= BESLevel,
                            TLevel= TLevel,
                            TSignatureVerifications= TSignatureVerifications,
                            TCertPathVerifications= TCertPathVerifications,
                            CLevel= CLevel,
                            CCertRefs= CCertRefs,
                            CRevocationRefs= CRevocationRefs,
                            XType1Level= XType1Level,
                            XType1SignatureVerifications= XType1SignatureVerifications,
                            XType1CertPathVerifications= XType1CertPathVerifications,
                            XType2Level= XType2Level,
                            XType2SignatureVerifications= XType2SignatureVerifications,
                            XType2CertPathVerifications= XType2CertPathVerifications,
                            XLLevel= XLLevel,
                            CCertValues= CCertValues,
                            CRevocationValues= CRevocationValues,
                            XLType1Level= XLType1Level,
                            XLType2Level= XLType2Level,
                            ALevel= ALevel,
                            ASignatureVerifications= ASignatureVerifications,
                            ACertPathVerifications= ACertPathVerifications,
                         }
                    };
                }
            }
        }

        private static bool? GetBoolValue(string str)
        {
            return str == "yes" ? true : str == "no" ? false : (bool?)null;
        }

        public class SignatureParams
        {
            public SignatureProfile SignatureProfile { get; set; }
            public bool? SignatureValid { get; set; }
            public bool? SignatureCertTimeValid { get; set; }
            public bool? SignatureCertTrusted { get; set; }
            public bool? SignatureCertOCSP { get; set; }
            public bool? SignatureCertCRL { get; set; }
            public bool? OCSPCertTrusted { get; set; }
            public bool? TSSignatureCertTrusted { get; set; }
            
            public override string ToString()
            {
                var builder = new List<string>();

                builder.Add($"Profile{Enum.GetName(SignatureProfile.GetType(), SignatureProfile)}");

                if (SignatureValid.HasValue) { builder.Add("Sign" + (SignatureValid.Value ? "Valid" : "NotValid")); };
                if (SignatureCertTimeValid.HasValue) { builder.Add("CertTime" + (SignatureCertTimeValid.Value ? "Valid" : "NotValid")); };

                if (SignatureCertTrusted.HasValue) { builder.Add("SignatureCertTrusted" + (SignatureCertTrusted.Value ? "Valid" : "NotValid")); }
                if (SignatureCertOCSP.HasValue) { builder.Add("SignatureCertOCSP" + (SignatureCertOCSP.Value ? "Valid" : "NotValid")); }
                if (SignatureCertCRL.HasValue) { builder.Add("SignatureCertCRL" + (SignatureCertCRL.Value ? "Valid" : "NotValid")); }
                if (OCSPCertTrusted.HasValue) { builder.Add("OCSPCertTrusted" + (OCSPCertTrusted.Value ? "Valid" : "NotValid")); }
                if (TSSignatureCertTrusted.HasValue) { builder.Add("TSSignatureCertTrusted" + (TSSignatureCertTrusted.Value ? "Valid" : "NotValid")); }

                return string.Join(",", builder);
            }
        }

        public class SignatureVerificationResults
        {
            public bool SignatureVerification { get; set; }

            public bool CertPathVerification { get; set; }

            #region BES 

            public bool? BESLevel { get; set; }

            #endregion

            #region T

            public bool? TLevel { get; set; }
            public bool? TSignatureVerifications { get; set; }
            public bool? TCertPathVerifications { get; set; }


            #endregion

            #region C 
            public bool? CLevel { get; set; }
            public bool? CCertRefs { get; set; }
            public bool? CRevocationRefs { get; set; }
            #endregion

            #region XType1 
            public bool? XType1Level { get; set; }
            public bool? XType1SignatureVerifications { get; set; }
            public bool? XType1CertPathVerifications { get; set; }
            #endregion

            #region XType2
            public bool? XType2Level { get; set; }
            public bool? XType2SignatureVerifications { get; set; }
            public bool? XType2CertPathVerifications { get; set; }
            #endregion

            #region XL 
            public bool? XLLevel { get; set; }
            public bool? CCertValues { get; set; }
            public bool? CRevocationValues { get; set; }
            #endregion

            #region XLType1
            public bool? XLType1Level { get; set; }
            #endregion

            #region XLType2
            public bool? XLType2Level { get; set; }
            #endregion

            #region A
            public bool? ALevel { get; set; }
            public bool? ASignatureVerifications { get; set; }
            public bool? ACertPathVerifications { get; set; }
            #endregion



            public override string ToString()
            {
                var builder = new List<string>();

                builder.Add($"Sign" + (SignatureVerification ? "Valid" : "NotValid"));
                builder.Add($"CertPath" + (CertPathVerification ? "Valid" : "NotValid"));

                if (BESLevel.HasValue) { builder.Add($"BESLevel" + (BESLevel.Value ? "Valid" : "NotValid")); }
                if (TLevel.HasValue) { builder.Add($"TLevel" + (TLevel.Value ? "Valid" : "NotValid")); }
                if (TSignatureVerifications.HasValue) { builder.Add($"TSignVerif" + (TSignatureVerifications.Value ? "Valid" : "NotValid")); }
                if (TCertPathVerifications.HasValue) { builder.Add($"TCertPath" + (TCertPathVerifications.Value ? "Valid" : "NotValid")); }
                if (CLevel.HasValue) { builder.Add($"CLevel" + (CLevel.Value ? "Valid" : "NotValid")); }
                if (CCertRefs.HasValue) { builder.Add($"CCertRefs" + (CCertRefs.Value ? "Valid" : "NotValid")); }
                if (CRevocationRefs.HasValue) { builder.Add($"CRevocationRefs" + (CRevocationRefs.Value ? "Valid" : "NotValid")); }
                if (XType1Level.HasValue) { builder.Add($"XType1Level" + (XType1Level.Value ? "Valid" : "NotValid")); }
                if (XType1SignatureVerifications.HasValue) { builder.Add($"XType1SignatureVerifications" + (XType1SignatureVerifications.Value ? "Valid" : "NotValid")); }
                if (XType1CertPathVerifications.HasValue) { builder.Add($"XType1CertPathVerifications" + (XType1CertPathVerifications.Value ? "Valid" : "NotValid")); }
                if (XType2Level.HasValue) { builder.Add($"XType2Level" + (XType2Level.Value ? "Valid" : "NotValid")); }
                if (XType2SignatureVerifications.HasValue) { builder.Add($"XType2SignatureVerifications" + (XType2SignatureVerifications.Value ? "Valid" : "NotValid")); }
                if (XType2CertPathVerifications.HasValue) { builder.Add($"XType2CertPathVerifications" + (XType2CertPathVerifications.Value ? "Valid" : "NotValid")); }
                if (XLLevel.HasValue) { builder.Add($"XLLevel" + (XLLevel.Value ? "Valid" : "NotValid")); }
                if (CCertValues.HasValue) { builder.Add($"CCertValues" + (CCertValues.Value ? "Valid" : "NotValid")); }
                if (CRevocationValues.HasValue) { builder.Add($"CRevocationValues" + (CRevocationValues.Value ? "Valid" : "NotValid")); }
                if (XLType1Level.HasValue) { builder.Add($"XLType1Level" + (XLType1Level.Value ? "Valid" : "NotValid")); }
                if (XLType2Level.HasValue) { builder.Add($"XLType2Level" + (XLType2Level.Value ? "Valid" : "NotValid")); }
                if (ALevel.HasValue) { builder.Add($"ALevel" + (ALevel.Value ? "Valid" : "NotValid")); }
                if (ASignatureVerifications.HasValue) { builder.Add($"ASignatureVerifications" + (ASignatureVerifications.Value ? "Valid" : "NotValid")); }
                if (ACertPathVerifications.HasValue) { builder.Add($"ACertPathVerifications" + (ACertPathVerifications.Value ? "Valid" : "NotValid")); }

                return string.Join(",", builder);
            }
        }
    }

    class CAdESServiceSettings : ICAdESServiceSettings
    {
        public SignaturePackaging SignaturePackaging { get; set; }

        public SignatureProfile SignatureProfile { get; set; }

        public SignatureType SignatureType { get; set; }

        public string TspSource { get; set; }

        public string TspUsername { get; set; }

        public string TspPassword { get; set; }
        
        public string TspDigestAlgorithmOID { get; set; }

        public string OcspSource { get; set; }

        public string CrlSource { get; set; }

        public IList<X509Certificate> TrustedCerts { get; set; } = new List<X509Certificate>();

    }   
}
