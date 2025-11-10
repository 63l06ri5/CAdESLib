using CAdESLib.Document.Signature;
using CAdESLib.Document.Validation;
using CAdESLib.Document;
using CAdESLib.Helpers;
using CAdESLib.Service;
using CAdESSignatureExtension = CAdESLib.Document.Signature.Extensions.CAdESSignatureExtension;
using Moq;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.X509;
using PkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
using System.Collections.Generic;
using System.Collections;
using System.IO;
using System.Linq;
using System.Text;
using System;
using Unity;
using Newtonsoft.Json;
using static CAdESLib.Helpers.ValidationHelper;
using NLog;
using Org.BouncyCastle.Asn1.Esf;
using CAdESLib.Document.Signature.Extensions;

namespace CAdESLib.Tests
{
    [Parallelizable(scope: ParallelScope.All)]
    [TestFixture]
    public class ComplexTests
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        [TestCase(true, Description = "crlOnline")]
        [TestCase(false, Description = "crlOffline")]
        public void XLT1_with_same_issuers_chain(bool crlOnline)
        {
            var (container, fakeHttpDataLoader) = Setup();
            // Signer certificate issued by Intermediate, Intermediate by CA.
            // Signer verified by OCSP, which issued by an ocsp provider
            // An ocsp provider was issued by Intermediate
            // An ocsp provider does not have revocation info
            // Intermediate verified by crl 
            // TSP issued by Intermediate
            // TSP verified by OCSP, which issued by an ocsp provider

            // check that refs and values of Signer is present in a main section
            // check that refs and values of TSP is present in a timestamp section
            // check that refs and values are matched

            // TODO additional test cases: a settings crl should only be used, when crl records are present; same with ocsp; flag noocsp should be respected            

            var cadesSettings = container.Resolve<CAdESServiceSettings>();
            var certsParams = container.Resolve<ParamsResolver>().Resolve(UrlType.Signer, UrlType.Signer).First().Item2.Item2;
            if (!crlOnline)
            {
                if (cadesSettings.Crls == null)
                {
                    cadesSettings.Crls = new List<X509Crl>();
                }

                cadesSettings.Crls.Add(GetX509Crl(certsParams.IntermediateCert, certsParams.IntermediateKeyPair, certsParams.CaCert.SigAlgOid));
                cadesSettings.Crls.Add(GetX509Crl(certsParams.CaCert, certsParams.CaKeyPair, certsParams.CaCert.SigAlgOid));
                var tspCertsParams = container.Resolve<ParamsResolver>().Resolve(UrlType.Tsp, UrlType.Signer).First().Item2.Item2;
                cadesSettings.Crls.Add(GetX509Crl(tspCertsParams.IntermediateCert, tspCertsParams.IntermediateKeyPair, tspCertsParams.CaCert.SigAlgOid));
                cadesSettings.Crls.Add(GetX509Crl(tspCertsParams.CaCert, tspCertsParams.CaKeyPair, tspCertsParams.CaCert.SigAlgOid));
            }

            var cadesService = container.Resolve<Func<ICAdESServiceSettings, IDocumentSignatureService>>()(cadesSettings);
            // to be signed
            var inputData = Encoding.UTF8.GetBytes("anydataanydataanydataanydataanydataanydataanydataanydata");
            var inputDocument = new InMemoryDocument(inputData);
            var signingTime = DateTime.UtcNow;
            var parameters = new SignatureParameters
            {
                SigningCertificate = certsParams.SignerCert,
                CertificateChain = new X509Certificate[] { certsParams.SignerCert },
                SignaturePackaging = SignaturePackaging.DETACHED,
                //SignatureProfile = SignatureProfile.XLType1,
                SigningDate = signingTime,
                DigestAlgorithmOID = DigestAlgorithm.SHA256.OID,
                EncriptionAlgorithmOID = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption.Id
            };
            var toBeSignedStream = cadesService.ToBeSigned(inputDocument, parameters);
            // sign
            ISigner signer = SignerUtilities.InitSigner(parameters.DigestWithEncriptionOID, true, certsParams.SignerKeyPair.Private, null);
            toBeSignedStream.Position = 0;
            toBeSignedStream.Seek(0, SeekOrigin.Begin);
            var b = Streams.ReadAll(toBeSignedStream);
            signer.BlockUpdate(b, 0, b.Length);
            var signatureValue = signer.GenerateSignature();

            // make pkcs7
            parameters.SignatureProfile = SignatureProfile.BES;
            var (signedDocument, validationReport) = cadesService.GetSignedDocument(inputDocument, parameters, signatureValue);

            parameters.SignatureProfile = SignatureProfile.XLType1;
            (signedDocument, validationReport) = cadesService.ExtendDocument(signedDocument, inputDocument, parameters);

            Action callsChecker = () =>
            {
                // sign: ocsp - 1   
                // extend: tsp - 2, ocsp for signer - 1, ocsp for tsp - 2
                fakeHttpDataLoader.Verify(x => x.Post(It.IsAny<string>(), It.IsAny<Stream>()), Times.Exactly(1 + 5));
                // sign: intermediate - 1, crl - 2 (1 - inter, 1 - ocsp) if crlOnline else 0, 
                // extend: intermediate - 2 (signer, tsp), crl - 4 (2 - inter, 2 - ocsp) if crlOnline else 0, ca - 0 (it is present because of a trusted list)
                fakeHttpDataLoader.Verify(x => x.Get(It.IsAny<string>()), Times.Exactly(crlOnline ? 9 : 3));
            };

            callsChecker();

            // validate
            //cadesService = container.Resolve<Func<ICAdESServiceSettings, IDocumentSignatureService>>()(cadesSettings);
            //var report = cadesService.ValidateDocument(signedDocument, true, inputDocument);
            var sigInfo = validationReport.SignatureInformationList[0]!;

            // No new calls, so there was a validation without network access
            callsChecker();

            // XLT1 level is reached and it is a solid one
            Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid);
            Assert.IsTrue(
                    sigInfo.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?
                        .All(x => x.SameDigest?.IsValid ?? false), "XType1 timestamps are not valid");
            Assert.IsTrue(
                    sigInfo.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?
                        .All(x => x.CertPathVerification.IsValid), "XType1 cert paths are not valid");

            var cms = new CmsSignedData(Streams.ReadAll(signedDocument.OpenStream()));
            var signerInformation = cms.GetSignerInfos().GetSigners().OfType<SignerInformation>().First();
            Assert.IsNotNull(signerInformation);

            Action<string, X509Certificate, Org.BouncyCastle.Asn1.Cms.AttributeTable> refsValsChecker = (label, cert, unsignedAttributes) =>
            {
                var mainRefs = unsignedAttributes.GetEtsCertificateRefs();
                var mainValues = unsignedAttributes.GetEtsCertValues();

                Assert.AreEqual(3, mainRefs.Count, $"{label} ref count");
                Assert.AreEqual(4, mainValues.Count, $"{label} vals count");

                Assert.IsTrue(cert.Equals(mainValues[0]), $"{label} signer is not matched");

                for (var i = 0; i < mainRefs.Count; i++)
                {
                    var referencedCert = mainRefs[i];
                    var valueCert = mainValues[i + 1];
                    byte[] hash = new BouncyCastleCryptographicProvider().CalculateDigest(referencedCert.DigestAlgorithm!, valueCert.GetEncoded());
                    Assert.IsTrue(hash.SequenceEqual(referencedCert.DigestValue!), $"{label} cert ref index={i} is not matched");
                }
            };

            // main refs and vals should match 
            refsValsChecker("main", certsParams.SignerCert, signerInformation.UnsignedAttributes);

            // tsp refs and vals should match 
            var timestamp = signerInformation.GetSignatureTimestamps()!.First()!;
            var tspUnsignedAttributes = timestamp.GetTimeStamp().UnsignedAttributes;
            refsValsChecker("tsp", timestamp.GetSigner()!, tspUnsignedAttributes);
        }

        [Test]
        public void T_with_same_issuers_chain()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var cadesSettings = container.Resolve<CAdESServiceSettings>();
            var cadesService = container.Resolve<Func<ICAdESServiceSettings, IDocumentSignatureService>>()(cadesSettings);
            // to be signed
            var inputData = Encoding.UTF8.GetBytes("anydataanydataanydataanydataanydataanydataanydataanydata");
            var inputDocument = new InMemoryDocument(inputData);
            var signingTime = DateTime.UtcNow;
            var certsParams = container.Resolve<ParamsResolver>().Resolve(UrlType.Signer, UrlType.Signer).First().Item2.Item2;
            var parameters = new SignatureParameters
            {
                SigningCertificate = certsParams.SignerCert,
                CertificateChain = new X509Certificate[] { certsParams.SignerCert },
                SignaturePackaging = SignaturePackaging.DETACHED,
                SignatureProfile = SignatureProfile.T,
                SigningDate = signingTime,
                DigestAlgorithmOID = DigestAlgorithm.SHA256.OID,
                EncriptionAlgorithmOID = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption.Id,
            };
            var toBeSignedStream = cadesService.ToBeSigned(inputDocument, parameters);
            // sign
            ISigner signer = SignerUtilities.InitSigner(parameters.DigestWithEncriptionOID, true, certsParams.SignerKeyPair.Private, null);
            toBeSignedStream.Position = 0;
            toBeSignedStream.Seek(0, SeekOrigin.Begin);
            var b = Streams.ReadAll(toBeSignedStream);
            signer.BlockUpdate(b, 0, b.Length);
            var signatureValue = signer.GenerateSignature();

            // make pkcs7
            var (signedDocument, validationReport) = cadesService.GetSignedDocument(inputDocument, parameters, signatureValue);

            Action callsChecker = () =>
            {
                // tsp - 1, ocsp - 2(on validation)
                fakeHttpDataLoader.Verify(x => x.Post(It.IsAny<string>(), It.IsAny<Stream>()), Times.Exactly(3));
                // intermediate - 2 (signer, tsp), crl - 4 
                fakeHttpDataLoader.Verify(x => x.Get(It.IsAny<string>()), Times.Exactly(6));
            };

            callsChecker();

            // validate
            var sigInfo = validationReport.SignatureInformationList[0]!;

            // XLT1 level is reached and it is a solid one
            Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelT.LevelReached.IsValid);
            Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelT.SignatureTimestampVerification.All(x => x.SameDigest?.IsValid ?? false), "timestamps are not valid");
        }

        [Test]
        public void BesDoesntAddSectionForUnsignedAttributes()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var cadesSettings = container.Resolve<CAdESServiceSettings>();
            var cadesService = container.Resolve<Func<ICAdESServiceSettings, IDocumentSignatureService>>()(cadesSettings);
            // to be signed
            var inputData = Encoding.UTF8.GetBytes("anydataanydataanydataanydataanydataanydataanydataanydata");
            var inputDocument = new InMemoryDocument(inputData);
            var signingTime = DateTime.UtcNow;
            var certsParams = container.Resolve<ParamsResolver>().Resolve(UrlType.Signer, UrlType.Signer).First().Item2.Item2;
            var parameters = new SignatureParameters
            {
                SigningCertificate = certsParams.SignerCert,
                CertificateChain = new X509Certificate[] { certsParams.SignerCert },
                SignaturePackaging = SignaturePackaging.DETACHED,
                SignatureProfile = SignatureProfile.BES,
                SigningDate = signingTime,
                DigestAlgorithmOID = DigestAlgorithm.SHA256.OID,
                EncriptionAlgorithmOID = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption.Id
            };
            var toBeSignedStream = cadesService.ToBeSigned(inputDocument, parameters);
            // sign
            ISigner signer = SignerUtilities.InitSigner(parameters.DigestWithEncriptionOID, true, certsParams.SignerKeyPair.Private, null);
            toBeSignedStream.Position = 0;
            toBeSignedStream.Seek(0, SeekOrigin.Begin);
            var b = Streams.ReadAll(toBeSignedStream);
            signer.BlockUpdate(b, 0, b.Length);
            var signatureValue = signer.GenerateSignature();

            // make pkcs7
            var (signedDocument, validationReport) = cadesService.GetSignedDocument(inputDocument, parameters, signatureValue);

            // validate
            var sigInfo = validationReport.SignatureInformationList[0]!;
            Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelBES.LevelReached.IsValid);

            var cms = new CmsSignedData(Streams.ReadAll(signedDocument.OpenStream()));
            var signerInformation = cms.GetSignerInfos().GetSigners().OfType<SignerInformation>().FirstOrDefault();
            Assert.IsNotNull(signerInformation);
            Assert.IsNull(signerInformation!.UnsignedAttributes);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.CheckedWithWarning, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.CheckedWithWarning, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.CheckedWithWarning, SignatureProfile.XLType2)]
        public void check_no_net(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile,
                noNetworkAfterSigning: true);

            var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);

            var levelReached = Extensions.GetLevelReached(signatureInformation);
            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));

            Assert.AreEqual(expectedLevel, levelReached);
            Assert.AreEqual(expectedState, state);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Checked, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Checked, SignatureProfile.XLType2)]
        public void check_signer_revoked(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (signedDocument, inputDocument, cadesService, validationReport) = SomeSetupSigning(
                container,
                signatureProfile,
                signerRevokedAfterSigning: true);
            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);
            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));
            Assert.AreEqual(FileSignatureState.Checked, state);
            Assert.AreEqual(signatureProfile, levelReached);

            nloglogger.Trace("--validate--");

            validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
            signatureInformation = validationReport.SignatureInformationList.First()!;
            state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            levelReached = Extensions.GetLevelReached(signatureInformation);
            valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Checked, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Checked, SignatureProfile.XLType2)]
        public void check_intermediate_revoked(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile,
                intermediateRevokedAfterSigning: true);

            var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);
            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.XLType2)]
        public void check_signer_after_NotAfter(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (_, certsParams) = GetSignerCert(container, signerOverdue: true);
            var cadesSettings = container.Resolve<CAdESServiceSettings>();
            cadesSettings.TrustedCerts.Add(certsParams.CaCert);

            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile,
                certsParams: certsParams);

            var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);
            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.XLType2)]
        public void signer_signer_after_NotAfter(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (_, certsParams) = GetSignerCert(container, signerOverdue: true);

            var (_, _, _, validationReport) = SomeSetupSigning(
                container,
                signatureProfile,
                certsParams: certsParams);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);

        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.BES)]
        public void sign_no_net(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            Assert.Throws<ArgumentNullException>(() => SomeSetupSigning(
                container,
                signatureProfile,
                noNetworkBeforeSigning: true));
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.BES)]
        public void sign_no_net_for_tsp(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            Assert.Throws<ArgumentNullException>(() => SomeSetupSigning(
                container,
                signatureProfile,
                noNetworkForTspBeforeSigning: true));
        }

        [TestCase(SignatureProfile.T, FileSignatureState.CheckedWithWarning, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.T)]
        public void sign_no_net_for_inter(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (t, _, _, validationReport) = SomeSetupSigning(
                container,
                signatureProfile,
                noNetworkForInterBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.CheckedWithWarning, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.T)]
        public void sign_no_net_for_revocation(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (_, _, _, validationReport) = SomeSetupSigning(
                container,
                signatureProfile,
                noNetworkForOcspBeforeSigning: true,
                noNetworkForCrlBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.XLType2)]
        public void sign_signer_revoked(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (_, _, _, validationReport) = SomeSetupSigning(
                container,
                signatureProfile,
                signerRevokedBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.BES)]
        public void sign_ocsp_revoked(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (_, signerCertsParams) = GetSignerCert(container, useCrl: false);
            var (tspUrl, tspCertsParams) = GetSignerCert(container, tsp: true, useCrl: false);
            container.RegisterInstance(new CAdESServiceSettings
            {
                TspSource = tspUrl,
                TrustedCerts = new List<X509Certificate> { signerCertsParams.CaCert, tspCertsParams.CaCert },
                TspDigestAlgorithmOID = DigestAlgorithm.SHA256.OID
            });
            var (_, _, _, validationReport) = SomeSetupSigning(
                container,
                signatureProfile,
                ocspRevokedBeforeSigning: true,
                certsParams: signerCertsParams);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.XLType2)]
        public void sign_inter_revoked(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (_, _, _, validationReport) = SomeSetupSigning(
                container,
                signatureProfile,
                intermediateRevokedBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.BES)]
        public void sign_tsp_revoked(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (_, _, _, validationReport) = SomeSetupSigning(
                container,
                signatureProfile,
                tspRevokedBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Checked, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Checked, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Checked, SignatureProfile.XLType2)]
        public void sign_ocsp_revoked_with_no_check(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (_, certsParams) = GetSignerCert(container, ocsp: (true, true));
            var cadesSettings = container.Resolve<CAdESServiceSettings>();
            cadesSettings.TrustedCerts.Add(certsParams.CaCert);
            var (_, _, _, validationReport) = SomeSetupSigning(
                container,
                signatureProfile,
                certsParams: certsParams);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);
            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Checked, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Checked, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Checked, SignatureProfile.XLType2)]
        public void sign_ocsp_resp_publickey(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (signedDocument, inputDocument, cadesService, validationReportInSigning) = SomeSetupSigning(
                container,
                signatureProfile,
                ocspRespIDPublicKey: true);

            nloglogger.Trace("");
            nloglogger.Trace("Second validation");
            nloglogger.Trace("");

            var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);
            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));
            nloglogger.Trace("trustedcerts");
            foreach (var c in container.Resolve<CAdESServiceSettings>().TrustedCerts)
            {
                nloglogger.Trace(Convert.ToBase64String(c.GetEncoded()));
            }

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [Test]
        public void when_extend_to_XL_IdAAEtsCertCrlTimestamp_should_have_refs_and_vals_w_enrichXTimestamp()
        {
            var testFunc = (bool enrichXTimestamp, SignatureProfile signatureProfile, Action<OrderedAttributeTable> assertFunc) =>
            {
                var attributeId = signatureProfile == SignatureProfile.XLType1 ? PkcsObjectIdentifiers.IdAAEtsEscTimeStamp : PkcsObjectIdentifiers.IdAAEtsCertCrlTimestamp;
                var (container, fakeHttpDataLoader) = Setup();
                var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                    container,
                    signatureProfile,
                    enrichXTimestamp: enrichXTimestamp);
                var cms = new CmsSignedData(Streams.ReadAll(signedDocument.OpenStream()));
                var si = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
                var cmsUnsigneds = new OrderedAttributeTable(si.ToSignerInfo().UnauthenticatedAttributes);
                var tCms = new CmsSignedData(
                        cmsUnsigneds[attributeId]!
                            .First().AttrValues[0].GetDerEncoded());
                var tSi = tCms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
                var tCmsUnsigneds = new OrderedAttributeTable(tSi.ToSignerInfo().UnauthenticatedAttributes);

                assertFunc(tCmsUnsigneds);

            };

            testFunc(false, SignatureProfile.XLType1, (unsigned) =>
            {
                Assert.IsNull(unsigned[PkcsObjectIdentifiers.IdAAEtsCertificateRefs], "There is IdAAEtsCertificateRefs");
                Assert.IsNull(unsigned[PkcsObjectIdentifiers.IdAAEtsRevocationRefs], "There is IdAAEtsRevocationRefs");
                Assert.IsNull(unsigned[PkcsObjectIdentifiers.IdAAEtsCertValues], "There is IdAAEtsCertValues");
                Assert.IsNull(unsigned[PkcsObjectIdentifiers.IdAAEtsRevocationValues], "There is IdAAEtsRevocationValues");
            });

            testFunc(true, SignatureProfile.XLType1, (unsigned) =>
            {
                Assert.IsTrue(unsigned[PkcsObjectIdentifiers.IdAAEtsCertificateRefs]?.Any(), "There is no IdAAEtsCertificateRefs");
                Assert.IsTrue(unsigned[PkcsObjectIdentifiers.IdAAEtsRevocationRefs]?.Any(), "There is no IdAAEtsRevocationRefs");
                Assert.IsTrue(unsigned[PkcsObjectIdentifiers.IdAAEtsCertValues]?.Any(), "There is no IdAAEtsCertValues");
                Assert.IsTrue(unsigned[PkcsObjectIdentifiers.IdAAEtsRevocationValues]?.Any(), "There is no IdAAEtsRevocationValues");
            });

            testFunc(false, SignatureProfile.XLType2, (unsigned) =>
            {
                Assert.IsNull(unsigned[PkcsObjectIdentifiers.IdAAEtsCertificateRefs], "There is IdAAEtsCertificateRefs");
                Assert.IsNull(unsigned[PkcsObjectIdentifiers.IdAAEtsRevocationRefs], "There is IdAAEtsRevocationRefs");
                Assert.IsNull(unsigned[PkcsObjectIdentifiers.IdAAEtsCertValues], "There is IdAAEtsCertValues");
                Assert.IsNull(unsigned[PkcsObjectIdentifiers.IdAAEtsRevocationValues], "There is IdAAEtsRevocationValues");
            });

            testFunc(true, SignatureProfile.XLType2, (unsigned) =>
            {
                Assert.IsTrue(unsigned[PkcsObjectIdentifiers.IdAAEtsCertificateRefs]?.Any(), "There is no IdAAEtsCertificateRefs");
                Assert.IsTrue(unsigned[PkcsObjectIdentifiers.IdAAEtsRevocationRefs]?.Any(), "There is no IdAAEtsRevocationRefs");
                Assert.IsTrue(unsigned[PkcsObjectIdentifiers.IdAAEtsCertValues]?.Any(), "There is no IdAAEtsCertValues");
                Assert.IsTrue(unsigned[PkcsObjectIdentifiers.IdAAEtsRevocationValues]?.Any(), "There is no IdAAEtsRevocationValues");
            });
        }

        [Test]
        public void when_extend_to_XL_IdAASignatureTimeStampToken_should_have_refs_and_vals()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile: SignatureProfile.XLType1);
            var cms = new CmsSignedData(Streams.ReadAll(signedDocument.OpenStream()));
            var si = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var cmsUnsigneds = new OrderedAttributeTable(si.ToSignerInfo().UnauthenticatedAttributes);
            var tCms = new CmsSignedData(
                    cmsUnsigneds[PkcsObjectIdentifiers.IdAASignatureTimeStampToken]!
                        .First().AttrValues[0].GetDerEncoded());
            var tSi = tCms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var tCmsUnsigneds = new OrderedAttributeTable(tSi.ToSignerInfo().UnauthenticatedAttributes);
            Assert.IsTrue(tCmsUnsigneds[PkcsObjectIdentifiers.IdAAEtsCertificateRefs]?.Any(), "There is no IdAAEtsCertificateRefs");
            Assert.IsTrue(tCmsUnsigneds[PkcsObjectIdentifiers.IdAAEtsRevocationRefs]?.Any(), "There is no IdAAEtsRevocationRefs");
            Assert.IsTrue(tCmsUnsigneds[PkcsObjectIdentifiers.IdAAEtsCertValues]?.Any(), "There is no IdAAEtsCertValues");
            Assert.IsTrue(tCmsUnsigneds[PkcsObjectIdentifiers.IdAAEtsRevocationValues]?.Any(), "There is no IdAAEtsRevocationValues");
        }

        // This is a preparation for an A profile signature
        // For it we need to enrich a subject signature and all it timestamps with refs and vals
        // And if we don't have all needed vals and refs inside of one CmsSignedData we should not accept it as valid
        // But we did create a XLT signatures without enriched second timestamp and that is ok for xlt1
        // But it is not enough for A profile
        // So what should i test and fix? 
        // I need a strict validation of XLT profiles before A, so i need a new validation mode
        // In that mode i should check every CmsSignedData in a vacuum (not to take in vals and refs got from other parts checking)
        // And i should be capable to enrich all parts if that information is available
        // So first i need a strict method of checking
        // And second i need an enricher 
        // So create tests accordingly
        [Test]
        public void strict_XLT_validation()
        {
            var (container, fakeHttpDataLoader) = Setup();
            // 1. generate XLT signature with same tsp
            // 2. remove unsigned attributes for a second timestamp
            // 3. old validation should succeed
            // 4. strict validation should failed

            // 1.
            var signatureProfile = SignatureProfile.XLType1;
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile: signatureProfile);

            // 2.
            var cmsBefore = new CmsSignedData(signedDocument.OpenStream());
            var siCms = cmsBefore.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var cmsUnsignedAttrs = new OrderedAttributeTable(
                    siCms.ToSignerInfo().UnauthenticatedAttributes);
            var tsAttribute = cmsUnsignedAttrs[PkcsObjectIdentifiers.IdAAEtsEscTimeStamp]!.First();
            var ets = new CmsSignedData(tsAttribute.AttrValues[0].GetDerEncoded());
            var siEts = ets.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();

            cmsUnsignedAttrs.ReplaceAttribute(
                    tsAttribute,
                    new DerSet(Asn1Object.FromByteArray(
                        CAdESSignatureExtension.ReplaceSigners(
                            ets,
                            new List<SignerInfo> {
                                CAdESSignatureExtension.ReplaceUnsignedAttributes(
                                        siEts, new OrderedAttributeTable())}).GetEncoded())));


            var cms = CAdESSignatureExtension.ReplaceSigners(
                cmsBefore,
                new List<SignerInfo> {
                    CAdESSignatureExtension.ReplaceUnsignedAttributes(
                            siCms, cmsUnsignedAttrs)});
            signedDocument = new InMemoryDocument(cms.GetEncoded());

            // 3.
            var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(FileSignatureState.Checked, state);
            Assert.AreEqual(signatureProfile, levelReached);

            // 4. 

            validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument, strictValidation: true);

            signatureInformation = validationReport.SignatureInformationList.First()!;
            state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));

            Assert.AreEqual(FileSignatureState.CheckedWithWarning, state, "Strict validation is not failed");
        }

        [Test]
        public void ocsp_producedAt_before_thisUpdate()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var signatureProfile = SignatureProfile.XLType1;
            var thisUpdate = DateTime.UtcNow.AddMinutes(-1);
            var producedAt = thisUpdate.AddMinutes(-1);
            var (signedDocument, _, _, validationReport) = SomeSetupSigning(
                container,
                signatureProfile: signatureProfile,
                ocspProducedAt: producedAt,
                ocspThisUpdate: thisUpdate);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));

            Assert.AreEqual(FileSignatureState.Checked, state);

            var cms = new CmsSignedData(Streams.ReadAll(signedDocument.OpenStream()));
            var si = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var cmsUnsigneds = new OrderedAttributeTable(si.ToSignerInfo().UnauthenticatedAttributes);
            var ocspExist = (cmsUnsigneds[PkcsObjectIdentifiers.IdAAEtsRevocationValues]!
                    .First().AttrValues[0] as Asn1Sequence)?.Cast<Asn1TaggedObject>().Any(x => x.TagNo == 1);

            Assert.False(ocspExist);
        }

        [Test]
        public void timestamp_ocsp_thisUpdate_before_timestamp_time_with_no_nextUpdate()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (tspUrl, tspCertsParams) = GetSignerCert(container, useCrl: false, tsp: true);
            var cadesSettings = container.Resolve<CAdESServiceSettings>();
            cadesSettings.TspSource = tspUrl;
            cadesSettings.TrustedCerts.Add(tspCertsParams.CaCert);

            var signatureProfile = SignatureProfile.XLType1;
            var timestampTime = DateTime.UtcNow;
            var thisUpdate = timestampTime.AddHours(-1);
            var producedAt = thisUpdate.AddMinutes(1);

            var (signedDocument, _, _, validationReport) = SomeSetupSigning(
                container,
                signatureProfile: signatureProfile,
                timestampTime: timestampTime,
                ocspThisUpdate: thisUpdate,
                ocspProducedAt: producedAt);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);
            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));

            Assert.AreEqual(FileSignatureState.Failed, state, "Outdated OCSP is valid");
            Assert.AreEqual(SignatureProfile.T, levelReached);
        }

        [Test]
        public void timestamp_ocsp_nextUpdate_before_timestamp_time()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (tspUrl, tspCertsParams) = GetSignerCert(container, useCrl: false, tsp: true);
            var cadesSettings = container.Resolve<CAdESServiceSettings>();
            cadesSettings.TspSource = tspUrl;
            cadesSettings.TrustedCerts.Add(tspCertsParams.CaCert);

            var signatureProfile = SignatureProfile.XLType1;
            var timestampTime = DateTime.UtcNow;
            var thisUpdate = timestampTime.AddHours(-2);
            var producedAt = timestampTime.AddMinutes(1);
            var nextUpdate = timestampTime.AddHours(-1);
            var (signedDocument, _, _, validationReport) = SomeSetupSigning(
                container,
                signatureProfile: signatureProfile,
                timestampTime: timestampTime,
                ocspThisUpdate: thisUpdate,
                ocspProducedAt: producedAt,
                ocspNextUpdate: nextUpdate);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            // var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport);
            Assert.AreEqual(FileSignatureState.Failed, state, "Outdated OCSP is valid");
            Assert.AreEqual(SignatureProfile.T, levelReached);
        }

        [Test]
        public void ocsp_just_right_with_timestamp()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var signatureProfile = SignatureProfile.XLType1;
            var timestampTime = DateTime.UtcNow;
            var thisUpdate = timestampTime.AddHours(-1);
            var producedAt = timestampTime.AddMinutes(1);
            var nextUpdate = thisUpdate.AddHours(2);
            var (signedDocument, _, _, validationReport) = SomeSetupSigning(
                container,
                signatureProfile: signatureProfile,
                timestampTime: timestampTime,
                ocspThisUpdate: thisUpdate,
                ocspProducedAt: producedAt,
                ocspNextUpdate: nextUpdate);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);

            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));

            Assert.AreEqual(FileSignatureState.Checked, state);
        }

        [Test]
        public void crl_outdated()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (_, certsParams) = GetSignerCert(container, ocsp: (false, false));
            var signatureProfile = SignatureProfile.XLType1;
            var (_, _, _, validationReport) = SomeSetupSigning(
                container,
                certsParams: certsParams,
                signatureProfile: signatureProfile,
                crlOutdated: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);

            Assert.AreEqual(FileSignatureState.Failed, state, "Outdated CRL is valid");
        }

        [Test]
        public void crl_too_young()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var signatureProfile = SignatureProfile.XL;
            var signingDate = DateTime.UtcNow;
            var timestampTime = signingDate;
            var ocspProducedAt = timestampTime;
            var ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
            var ocspNextUpdate = ocspProducedAt.AddMinutes(60);
            var crlThisUpdate = timestampTime.AddMinutes(60);
            var crlNextUpdate = timestampTime.AddMinutes(120);
            var (signedDocument, inputDocument, cadesService, validationReport) = SomeSetupSigning(
                container,
                signatureProfile: signatureProfile,
                signingDate: signingDate,
                timestampTime: timestampTime,
                ocspProducedAt: ocspProducedAt,
                ocspNextUpdate: ocspNextUpdate,
                ocspThisUpdate: ocspThisUpdate,
                crlThisUpdate: crlThisUpdate,
                crlNextUpdate: crlNextUpdate);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));

            Assert.AreEqual(FileSignatureState.Failed, state);
            Assert.AreEqual(SignatureProfile.T, levelReached);
        }

        [Test]
        public void ocsp_too_young()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var signatureProfile = SignatureProfile.XLType1;
            var (_, signerCertsParams) = GetSignerCert(container, useCrl: false);
            var cadesSettings = container.Resolve<CAdESServiceSettings>();
            cadesSettings.TrustedCerts.Add(signerCertsParams.CaCert);

            var signingDate = DateTime.UtcNow;
            var timestampTime = signingDate;
            var ocspProducedAt = DateTime.UtcNow.AddYears(1);
            var ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
            var ocspNextUpdate = ocspProducedAt.AddMinutes(60);
            var (signedDocument, inputDocument, cadesService, validationReport) = SomeSetupSigning(
                container,
                signatureProfile: signatureProfile,
                signingDate: signingDate,
                timestampTime: timestampTime,
                ocspProducedAt: ocspProducedAt,
                ocspNextUpdate: ocspNextUpdate,
                ocspThisUpdate: ocspThisUpdate,
                certsParams: signerCertsParams);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));

            Assert.AreEqual(FileSignatureState.Failed, state);
            Assert.AreEqual(signatureProfile, levelReached);
        }

        [Test]
        public void when_extend_XLT1_to_XLT1_all_timestamps_should_be_enriched_with_refs_and_vals_for_strict_validation()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var signatureProfile = SignatureProfile.XLType1;
            var ocspProducedAt = DateTime.UtcNow;
            var ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
            var ocspNextUpdate = ocspProducedAt.AddMinutes(60);
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile: signatureProfile,
                ocspProducedAt: ocspProducedAt,
                ocspNextUpdate: ocspNextUpdate,
                ocspThisUpdate: ocspThisUpdate);

            // delete unsigned attributes for second ts. 
            var cmsBefore = new CmsSignedData(signedDocument.OpenStream());
            var siCms = cmsBefore.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var cmsUnsignedAttrs = new OrderedAttributeTable(
                    siCms.ToSignerInfo().UnauthenticatedAttributes);
            var tsAttribute = cmsUnsignedAttrs[PkcsObjectIdentifiers.IdAAEtsEscTimeStamp]!.First();
            var ets = new CmsSignedData(tsAttribute.AttrValues[0].GetDerEncoded());
            var siEts = ets.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();

            cmsUnsignedAttrs.ReplaceAttribute(
                    tsAttribute,
                    new DerSet(Asn1Object.FromByteArray(
                        CAdESSignatureExtension.ReplaceSigners(
                            ets,
                            new List<SignerInfo> {
                                CAdESSignatureExtension.ReplaceUnsignedAttributes(
                                        siEts, new OrderedAttributeTable())}).GetEncoded())));


            var cms = CAdESSignatureExtension.ReplaceSigners(
                cmsBefore,
                new List<SignerInfo> {
                    CAdESSignatureExtension.ReplaceUnsignedAttributes(
                            siCms, cmsUnsignedAttrs)});
            signedDocument = new InMemoryDocument(cms.GetEncoded());

            // check validation
            var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(FileSignatureState.Checked, state);
            Assert.AreEqual(signatureProfile, levelReached);

            // then extend
            IDocument extendedSignedDocument;
            var newSignatureProfile = SignatureProfile.XLType1;
            (extendedSignedDocument, validationReport) = cadesService.ExtendDocument(
                    signedDocument,
                    null,
                    parameters: new SignatureParameters
                    {
                        SignatureProfile = newSignatureProfile,
                        EnrichXTimestamp = true
                        // CreateNewAttributeIfExist = false // false is default, but for explicity
                    });
            signatureInformation = validationReport.SignatureInformationList.First()!;
            state = Extensions.GetSignatureState(signatureInformation, newSignatureProfile);
            levelReached = Extensions.GetLevelReached(signatureInformation);
            var valInfos = GetValidationInfos(SignatureType.CAdES, newSignatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(extendedSignedDocument.OpenStream())));

            Assert.AreEqual(FileSignatureState.Checked, state);
            Assert.AreEqual(newSignatureProfile, levelReached);

            var cmsNew = new CmsSignedData(extendedSignedDocument.OpenStream());
            var siCmsNew = cmsNew.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var cmsUnsignedAttrsNew = new OrderedAttributeTable(
                    siCmsNew.ToSignerInfo().UnauthenticatedAttributes);
            var tsAttributeNew = cmsUnsignedAttrsNew[PkcsObjectIdentifiers.IdAAEtsEscTimeStamp]!.First();
            var etsNew = new CmsSignedData(tsAttributeNew.AttrValues[0].GetDerEncoded());
            var siEtsNew = etsNew.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var siEtsNewUnsignedAttrs = new OrderedAttributeTable(
                    siEtsNew.ToSignerInfo().UnauthenticatedAttributes);

            Assert.IsTrue(siEtsNewUnsignedAttrs[PkcsObjectIdentifiers.IdAAEtsCertificateRefs]?.Any(), "There is no IdAAEtsCertificateRefs");
            Assert.IsTrue(siEtsNewUnsignedAttrs[PkcsObjectIdentifiers.IdAAEtsRevocationRefs]?.Any(), "There is no IdAAEtsRevocationRefs");
            Assert.IsTrue(siEtsNewUnsignedAttrs[PkcsObjectIdentifiers.IdAAEtsCertValues]?.Any(), "There is no IdAAEtsCertValues");
            Assert.IsTrue(siEtsNewUnsignedAttrs[PkcsObjectIdentifiers.IdAAEtsRevocationValues]?.Any(), "There is no IdAAEtsRevocationValues");
        }

        [Test]
        public void when_extend_T_to_XLT1_timestamp_should_be_enriched_with_refs_and_vals()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var signatureProfile = SignatureProfile.T;
            var ocspProducedAt = DateTime.UtcNow;
            var ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
            var ocspNextUpdate = ocspProducedAt.AddMinutes(60);
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile: signatureProfile,
                ocspProducedAt: ocspProducedAt,
                ocspNextUpdate: ocspNextUpdate,
                ocspThisUpdate: ocspThisUpdate);

            // check validation
            var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(FileSignatureState.Checked, state);
            Assert.AreEqual(signatureProfile, levelReached);

            // then extend
            IDocument extendedSignedDocument;
            var newSignatureProfile = SignatureProfile.XLType1;
            (extendedSignedDocument, validationReport) = cadesService.ExtendDocument(
                    signedDocument,
                    null,
                    parameters: new SignatureParameters
                    {
                        SignatureProfile = newSignatureProfile,
                        // CreateNewAttributeIfExist = false // false is default, but for explicity
                    });
            signatureInformation = validationReport.SignatureInformationList.First()!;
            state = Extensions.GetSignatureState(signatureInformation, newSignatureProfile);
            levelReached = Extensions.GetLevelReached(signatureInformation);
            var valInfos = GetValidationInfos(SignatureType.CAdES, newSignatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(extendedSignedDocument.OpenStream())));

            Assert.AreEqual(FileSignatureState.Checked, state);
            Assert.AreEqual(newSignatureProfile, levelReached);

            var cmsNew = new CmsSignedData(extendedSignedDocument.OpenStream());
            var siCmsNew = cmsNew.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var cmsUnsignedAttrsNew = new OrderedAttributeTable(
                    siCmsNew.ToSignerInfo().UnauthenticatedAttributes);
            var tsAttributeNew = cmsUnsignedAttrsNew[PkcsObjectIdentifiers.IdAASignatureTimeStampToken]!.First();
            var etsNew = new CmsSignedData(tsAttributeNew.AttrValues[0].GetDerEncoded());
            var siEtsNew = etsNew.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var siEtsNewUnsignedAttrs = new OrderedAttributeTable(
                    siEtsNew.ToSignerInfo().UnauthenticatedAttributes);

            Assert.IsTrue(siEtsNewUnsignedAttrs[PkcsObjectIdentifiers.IdAAEtsCertificateRefs]?.Any(), "There is no IdAAEtsCertificateRefs");
            Assert.IsTrue(siEtsNewUnsignedAttrs[PkcsObjectIdentifiers.IdAAEtsRevocationRefs]?.Any(), "There is no IdAAEtsRevocationRefs");
            Assert.IsTrue(siEtsNewUnsignedAttrs[PkcsObjectIdentifiers.IdAAEtsCertValues]?.Any(), "There is no IdAAEtsCertValues");
            Assert.IsTrue(siEtsNewUnsignedAttrs[PkcsObjectIdentifiers.IdAAEtsRevocationValues]?.Any(), "There is no IdAAEtsRevocationValues");
        }

        [Test]
        public void should_be_no_doubles_in_revocations_values()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile: SignatureProfile.XLType1);

            var cms = new CmsSignedData(Streams.ReadAll(signedDocument.OpenStream()));
            var si = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var cmsUnsigneds = new OrderedAttributeTable(si.ToSignerInfo().UnauthenticatedAttributes);

            var revocationValues = cmsUnsigneds[PkcsObjectIdentifiers.IdAAEtsRevocationValues]!
                        .First().AttrValues[0];
            var crlVals = RevocationValues.GetInstance(revocationValues).GetCrlVals();

            Assert.AreEqual(crlVals.Distinct().Count(), crlVals.Count(), "There is non unique crl values");
        }
        [Test]
        public void XL_without_second_ts()
        {
            SignatureProfile signatureProfile = SignatureProfile.XL;
            FileSignatureState expectedState = FileSignatureState.Checked;
            SignatureProfile expectedLevel = signatureProfile;
            var (container, fakeHttpDataLoader) = Setup();
            var (signedDocument, inputDocument, cadesService, validationReport) = SomeSetupSigning(
                container,
                signatureProfile);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);

            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
            var cms = new CmsSignedData(Streams.ReadAll(signedDocument.OpenStream()));
            var si = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var cmsUnsigneds = new OrderedAttributeTable(si.ToSignerInfo().UnauthenticatedAttributes);

            var secondTSAttrs = cmsUnsigneds[PkcsObjectIdentifiers.IdAAEtsEscTimeStamp];

            Assert.AreEqual(0, secondTSAttrs?.Count ?? 0);
        }

        // TODO: there is a problem with the test setup: when we have xl with revocation data that is outdated and we want to timestamp it second time we should get new revocation data, so there is no problem for test but maybe for other one where you should delete old revocation data and store a new one
        // [Test]
        // public void extend_XL_to_XLT1_with_same_tsp_without_new_T_with_ocsp_outdated()
        // {
        //     var (container, _) = Setup();
        //     // est: 2
        //     // Create xl signature
        //     // Wait time to after ocsp tsp responce
        //     // extend to xlt1
        //     // There should be new ocsp response for second timestamp
        //     // There should be no new T
        //
        //     // 1. create signature with timestamp it the past. check
        //     var signatureProfile = SignatureProfile.XL;
        //     var timestampTime = DateTime.UtcNow.AddDays(-1);
        //     var ocspProducedAt = timestampTime;
        //     var ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
        //     var ocspNextUpdate = ocspProducedAt.AddMinutes(60);
        //     var (signedDocument, inputDocument, cadesService, validationReport) = SomeSetupSigning(
        //         container,
        //         signatureProfile: signatureProfile,
        //         signingDate: timestampTime,
        //         timestampTime: timestampTime,
        //         ocspProducedAt: ocspProducedAt,
        //         ocspNextUpdate: ocspNextUpdate,
        //         ocspThisUpdate: ocspThisUpdate,
        //         crlThisUpdate: ocspThisUpdate,
        //         crlNextUpdate: ocspNextUpdate);
        //
        //     var signatureInformation = validationReport.SignatureInformationList.First()!;
        //     var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
        //     var levelReached = Extensions.GetLevelReached(signatureInformation);
        //     var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport);
        //     logger.Trace(JsonConvert.SerializeObject(valInfos));
        //     logger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));
        //
        //     Assert.AreEqual(FileSignatureState.Checked, state);
        //     Assert.AreEqual(signatureProfile, levelReached);
        //     logger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));
        //
        //     // 2. extend to xlt1. check 
        //
        //     logger.Trace("");
        //     logger.Trace("-----setup times------");
        //     logger.Trace("");
        //
        //     timestampTime = DateTime.UtcNow;
        //     ocspProducedAt = timestampTime;
        //     ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
        //     ocspNextUpdate = ocspProducedAt.AddMinutes(60);
        //     // setup times
        //     var fakeHttpDataLoader = SetupFakeHttpDataLoader(
        //        container,
        //        timestampTime: timestampTime,
        //        ocspProducedAt: ocspProducedAt,
        //        ocspNextUpdate: ocspNextUpdate,
        //        ocspThisUpdate: ocspThisUpdate,
        //        crlThisUpdate: ocspThisUpdate,
        //        crlNextUpdate: ocspNextUpdate);
        //
        //     logger.Trace("");
        //     logger.Trace("-----extend------");
        //     logger.Trace("");
        //
        //     IDocument extendedSignedDocument;
        //     var newSignatureProfile = SignatureProfile.XLType1;
        //     (extendedSignedDocument, validationReport) = cadesService.ExtendDocument(
        //             signedDocument,
        //             null,
        //             parameters: new SignatureParameters
        //             {
        //                 SignatureProfile = newSignatureProfile,
        //                 // CreateNewAttributeIfExist = false, // false is default, but for explicity
        //             });
        //
        //     // 1 - tsp, 1 - ocsp
        //     var postCount = 2;
        //     fakeHttpDataLoader.Verify(x => x.Post(It.IsAny<string>(), It.IsAny<Stream>()), Times.Exactly(postCount));
        //     // 1 - crl for ocsp, 1 - crl for inter
        //     var getCount = 2;
        //     fakeHttpDataLoader.Verify(x => x.Get(It.IsAny<string>()), Times.Exactly(getCount));
        //
        //     logger.Trace("");
        //     logger.Trace("-----validate------");
        //     logger.Trace("");
        //     validationReport = cadesService.ValidateDocument(extendedSignedDocument, false, inputDocument, strictValidation: true);
        //     signatureInformation = validationReport.SignatureInformationList.First()!;
        //     state = Extensions.GetSignatureState(signatureInformation, newSignatureProfile);
        //     levelReached = Extensions.GetLevelReached(signatureInformation);
        //
        //     valInfos = GetValidationInfos(SignatureType.CAdES, newSignatureProfile, validationReport);
        //     logger.Trace(JsonConvert.SerializeObject(valInfos));
        //     logger.Trace(Convert.ToBase64String(Streams.ReadAll(extendedSignedDocument.OpenStream())));
        //
        //     Assert.AreEqual(FileSignatureState.Checked, state);
        //     Assert.AreEqual(newSignatureProfile, levelReached);
        //
        //     // Same counts
        //     fakeHttpDataLoader.Verify(x => x.Post(It.IsAny<string>(), It.IsAny<Stream>()), Times.Exactly(postCount));
        //     fakeHttpDataLoader.Verify(x => x.Get(It.IsAny<string>()), Times.Exactly(getCount));
        // }

        // TODO: same here as above
        // [Test]
        // public void extend_XL_to_XLT1_with_same_tsp_without_new_T_with_ocsp_not_outdated()
        // {
        //     // est: 1
        //     // Create xl signature
        //     // do not Wait time to after ocsp tsp responce
        //     // extend to xlt1
        //     // There should be new ocsp response for second timestamp
        //     // There should be no new T
        //     var (container, _) = Setup();
        //
        //     // 1. create signature with timestamp it the past. check
        //     var signatureProfile = SignatureProfile.XL;
        //     var timestampTime = DateTime.UtcNow;
        //     var ocspProducedAt = timestampTime;
        //     var ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
        //     var ocspNextUpdate = ocspProducedAt.AddMinutes(60);
        //     var (signedDocument, inputDocument, cadesService, validationReport) = SomeSetupSigning(
        //         container,
        //         signatureProfile: signatureProfile,
        //         signingDate: timestampTime,
        //         timestampTime: timestampTime,
        //         ocspProducedAt: ocspProducedAt,
        //         ocspNextUpdate: ocspNextUpdate,
        //         ocspThisUpdate: ocspThisUpdate,
        //         crlThisUpdate: ocspThisUpdate,
        //         crlNextUpdate: ocspNextUpdate);
        //
        //     var signatureInformation = validationReport.SignatureInformationList.First()!;
        //     var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
        //     var levelReached = Extensions.GetLevelReached(signatureInformation);
        //
        //     Assert.AreEqual(FileSignatureState.Checked, state);
        //     Assert.AreEqual(signatureProfile, levelReached);
        //     logger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));
        //
        //     // 2. extend to xlt1. check 
        //
        //     logger.Trace("");
        //     logger.Trace("-----setup times------");
        //     logger.Trace("");
        //
        //     timestampTime = timestampTime.AddMinutes(1);
        //     ocspProducedAt = timestampTime;
        //     ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
        //     ocspNextUpdate = ocspProducedAt.AddMinutes(60);
        //     // setup times
        //     var fakeHttpDataLoader = SetupFakeHttpDataLoader(
        //        container,
        //        timestampTime: timestampTime,
        //        ocspProducedAt: ocspProducedAt,
        //        ocspNextUpdate: ocspNextUpdate,
        //        ocspThisUpdate: ocspThisUpdate,
        //        crlThisUpdate: ocspThisUpdate,
        //        crlNextUpdate: ocspNextUpdate);
        //
        //     logger.Trace("");
        //     logger.Trace("-----extend------");
        //     logger.Trace("");
        //
        //     IDocument extendedSignedDocument;
        //     var newSignatureProfile = SignatureProfile.XLType1;
        //     (extendedSignedDocument, validationReport) = cadesService.ExtendDocument(
        //             signedDocument,
        //             null,
        //             parameters: new SignatureParameters
        //             {
        //                 SignatureProfile = newSignatureProfile,
        //                 // CreateNewAttributeIfExist = false, // false is default, but for explicity
        //             });
        //
        //     // 1 - tsp, 0 - ocsp
        //     var postCount = 1;
        //     fakeHttpDataLoader.Verify(x => x.Post(It.IsAny<string>(), It.IsAny<Stream>()), Times.Exactly(postCount));
        //     // 0 - crl for ocsp, 0 - crl for inter
        //     var getCount = 0;
        //     fakeHttpDataLoader.Verify(x => x.Get(It.IsAny<string>()), Times.Exactly(getCount));
        //
        //     logger.Trace("");
        //     logger.Trace("-----validate------");
        //     logger.Trace("");
        //     validationReport = cadesService.ValidateDocument(extendedSignedDocument, false, inputDocument, strictValidation: true);
        //     signatureInformation = validationReport.SignatureInformationList.First()!;
        //     state = Extensions.GetSignatureState(signatureInformation, newSignatureProfile);
        //     levelReached = Extensions.GetLevelReached(signatureInformation);
        //
        //     var valInfos = GetValidationInfos(SignatureType.CAdES, newSignatureProfile, validationReport);
        //     logger.Trace(JsonConvert.SerializeObject(valInfos));
        //     logger.Trace(Convert.ToBase64String(Streams.ReadAll(extendedSignedDocument.OpenStream())));
        //
        //     Assert.AreEqual(FileSignatureState.Checked, state);
        //     Assert.AreEqual(newSignatureProfile, levelReached);
        //
        //     // Same counts
        //     fakeHttpDataLoader.Verify(x => x.Post(It.IsAny<string>(), It.IsAny<Stream>()), Times.Exactly(postCount));
        //     fakeHttpDataLoader.Verify(x => x.Get(It.IsAny<string>()), Times.Exactly(getCount));
        // }

        // TODO when you create C profile you don't store rev values, so signature become outdated very soon if you do not  provideoriginal validation data. SO. maybe we should add this feature
        [Test]
        public void you_cannot_validate_C_if_you_dont_store_revocation_values()
        {
            var (container, _) = Setup();

            var signatureProfile = SignatureProfile.C;
            var timestampTime = DateTime.UtcNow;
            var ocspProducedAt = timestampTime;
            var ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
            var ocspNextUpdate = ocspProducedAt.AddMinutes(60);
            var (signedDocument, inputDocument, cadesService, validationReport) = SomeSetupSigning(
                container,
                signatureProfile: signatureProfile,
                signingDate: timestampTime,
                timestampTime: timestampTime,
                ocspProducedAt: ocspProducedAt,
                ocspNextUpdate: ocspNextUpdate,
                ocspThisUpdate: ocspThisUpdate,
                crlThisUpdate: ocspThisUpdate,
                crlNextUpdate: ocspNextUpdate);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));

            // Failed because there is no original ocsp
            Assert.AreEqual(FileSignatureState.Failed, state);
            Assert.AreEqual(SignatureProfile.T, levelReached);
        }

        [Test]
        public void extend_C_to_XLT1()
        {
            // Cannot 
        }

        [Test]
        public void extend_XT1_to_XLT1()
        {
            // Cannot 
        }

        [Test]
        public void extend_XT2_to_XLT1()
        {
            // Cannot 
        }

        // TODO: xlt2 support dropped for now. cause: there is no support in a target sig checking system
        // [Test]
        // public void extend_XLT2_to_XLT1()
        // {
        //     var signatureProfile = SignatureProfile.XLType2;
        //     var (container, fakeHttpDataLoader) = Setup();
        //     var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
        //         container,
        //         signatureProfile);
        //
        //     var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
        //     var signatureInformation = validationReport.SignatureInformationList.First()!;
        //     var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
        //     var levelReached = Extensions.GetLevelReached(signatureInformation);
        //
        //     Assert.AreEqual(FileSignatureState.Checked, state);
        //     Assert.AreEqual(signatureProfile, levelReached);
        //     var newSignatureProfile = SignatureProfile.XLType1;
        //     (signedDocument, _) = cadesService.ExtendDocument(
        //             signedDocument,
        //             null,
        //             parameters: new SignatureParameters
        //             {
        //                 SignatureProfile = newSignatureProfile,
        //                 // CreateNewAttributeIfExist = false // false is default, but for explicity
        //             });
        //     validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
        //     Assert.AreEqual(1, validationReport.SignatureInformationList.Count);
        //     signatureInformation = validationReport.SignatureInformationList.First()!;
        //     state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
        //     levelReached = Extensions.GetLevelReached(signatureInformation);
        //     var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport);
        //     nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
        //     nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));
        //
        //     Assert.AreEqual(FileSignatureState.Checked, state);
        //     Assert.AreEqual(newSignatureProfile, levelReached);
        //
        //     Assert.IsTrue(signatureInformation.LevelXLType2Reached);
        //     Assert.IsTrue(signatureInformation.LevelXLType1Reached);
        // }

        [Test]
        public void extension_of_an_extended_should_failed_if_not_valid()
        {
            var signatureProfile = SignatureProfile.T;
            var (container, fakeHttpDataLoader) = Setup();
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile,
                intermediateRevokedAfterSigning: true);

            var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            // var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(FileSignatureState.Failed, state);

            var newSignatureProfile = SignatureProfile.XLType1;
            (signedDocument, _) = cadesService.ExtendDocument(
                    signedDocument,
                    null,
                    parameters: new SignatureParameters
                    {
                        SignatureProfile = newSignatureProfile,
                        // CreateNewAttributeIfExist = false // false is default, but for explicity
                    });
            validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
            signatureInformation = validationReport.SignatureInformationList.First()!;
            state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            var valInfos = GetValidationInfos(SignatureType.CAdES, signatureProfile, validationReport, container.Resolve<ICurrentTimeGetter>());
            nloglogger.Trace(JsonConvert.SerializeObject(valInfos));
            nloglogger.Trace(Convert.ToBase64String(Streams.ReadAll(signedDocument.OpenStream())));

            Assert.AreEqual(FileSignatureState.Failed, state);
        }

        [Test]
        public void extend_XLT1_to_A()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var ocspProducedAt = DateTime.UtcNow;
            var ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
            var ocspNextUpdate = ocspProducedAt.AddMinutes(60);
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile: SignatureProfile.XLType1,
                ocspProducedAt: ocspProducedAt,
                ocspNextUpdate: ocspNextUpdate,
                ocspThisUpdate: ocspThisUpdate);


            var settings = container.Resolve<CAdESServiceSettings>();
            var signatureProfile = SignatureProfile.A;
            var parameters = new SignatureParameters
            {
                SignaturePackaging = settings.SignaturePackaging,
                SignatureProfile = signatureProfile,
                DigestAlgorithmOID = settings.TspDigestAlgorithmOID
            };

            var (signedDocumentA, _) = cadesService.ExtendDocument(signedDocument, inputDocument, parameters);

            // check validation
            var validationReport = cadesService.ValidateDocument(signedDocumentA, false, inputDocument);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(FileSignatureState.Checked, state);
            Assert.AreEqual(signatureProfile, levelReached);
        }

        [Test]
        public void extend_T_to_A()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var ocspProducedAt = DateTime.UtcNow;
            var ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
            var ocspNextUpdate = ocspProducedAt.AddMinutes(60);
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile: SignatureProfile.T,
                ocspProducedAt: ocspProducedAt,
                ocspNextUpdate: ocspNextUpdate,
                ocspThisUpdate: ocspThisUpdate);

            var settings = container.Resolve<CAdESServiceSettings>();
            var signatureProfile = SignatureProfile.A;
            var parameters = new SignatureParameters
            {
                SignaturePackaging = settings.SignaturePackaging,
                SignatureProfile = signatureProfile,
                DigestAlgorithmOID = settings.TspDigestAlgorithmOID
            };

            var (signedDocumentA, _) = cadesService.ExtendDocument(signedDocument, inputDocument, parameters);

            // check validation
            var validationReport = cadesService.ValidateDocument(signedDocumentA, false, inputDocument);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(FileSignatureState.Checked, state);
            Assert.AreEqual(signatureProfile, levelReached);
        }

        [Test]
        public void extend_A_to_new_A()
        {
            var (container, fakeHttpDataLoader) = Setup();

            var currentTime = DateTime.UtcNow.AddMinutes(-2);
            var fakeCurrentTimeGetter = new FakeCurrentTimeGetter(currentTime);
            container.RegisterInstance<ICurrentTimeGetter>(fakeCurrentTimeGetter);

            var timestampTime = currentTime;
            var ocspProducedAt = currentTime;
            var ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
            var ocspNextUpdate = ocspProducedAt.AddMinutes(60);
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile: SignatureProfile.T,
                timestampTime: timestampTime,
                ocspProducedAt: ocspProducedAt,
                ocspNextUpdate: ocspNextUpdate,
                ocspThisUpdate: ocspThisUpdate);

            var settings = container.Resolve<CAdESServiceSettings>();
            var signatureProfile = SignatureProfile.A;
            var parameters = new SignatureParameters
            {
                SignaturePackaging = settings.SignaturePackaging,
                SignatureProfile = signatureProfile,
                DigestAlgorithmOID = settings.TspDigestAlgorithmOID
            };

            var (signedDocumentA, _) = cadesService.ExtendDocument(signedDocument, inputDocument, parameters);

            currentTime = currentTime.AddMinutes(1);
            fakeCurrentTimeGetter.CurrentUtcTime = currentTime;
            timestampTime = currentTime;
            ocspProducedAt = currentTime;
            ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
            ocspNextUpdate = ocspProducedAt.AddMinutes(60);
            SomeSetupSigning(
                container,
                signatureProfile: SignatureProfile.T,
                timestampTime: timestampTime,
                ocspProducedAt: ocspProducedAt,
                ocspNextUpdate: ocspNextUpdate,
                ocspThisUpdate: ocspThisUpdate);

            (signedDocumentA, _) = cadesService.ExtendDocument(signedDocumentA, inputDocument, parameters);

            // check validation
            var validationReport = cadesService.ValidateDocument(signedDocumentA, false, inputDocument);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(FileSignatureState.Checked, state);
            Assert.AreEqual(signatureProfile, levelReached);

            var cms = new CmsSignedData(Streams.ReadAll(signedDocumentA.OpenStream()));
            var si = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var cmsUnsigneds = new OrderedAttributeTable(si.ToSignerInfo().UnauthenticatedAttributes);

            var archiveAttributes = cmsUnsigneds[CAdESProfileA.id_aa_ets_archiveTimestamp_v3]!
                .Select(x => new CmsSignedData(x.AttrValues[0].GetDerEncoded()));

            Assert.AreEqual(2, archiveAttributes.Count());

            {
                var a1si = archiveAttributes.ElementAt(0).GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
                var a1cmsUnsigneds = new OrderedAttributeTable(a1si.ToSignerInfo().UnauthenticatedAttributes);
                var a1index = a1cmsUnsigneds[CAdESProfileA.id_aa_ATSHashIndex_v3]!.First();
                var hashIndexValue1 = (DerSequence)a1index.AttrValues[0]!;
                var unsignedAttributesDerSequence1 = hashIndexValue1[3] as DerSequence;
                Assert.AreEqual(6, unsignedAttributesDerSequence1!.Count);
            }

            {
                var a2si = archiveAttributes.ElementAt(1).GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
                var a2cmsUnsigneds = new OrderedAttributeTable(a2si.ToSignerInfo().UnauthenticatedAttributes);
                var a2index = a2cmsUnsigneds[CAdESProfileA.id_aa_ATSHashIndex_v3]!.First();
                var hashIndexValue2 = (DerSequence)a2index.AttrValues[0]!;
                var unsignedAttributesDerSequence2 = hashIndexValue2[3] as DerSequence;
                Assert.AreEqual(7, unsignedAttributesDerSequence2!.Count);
            }
        }

        [Test]
        public void when_extend_XLT1_to_A_should_update_outdated_revocs()
        {
            var (container, fakeHttpDataLoader) = Setup();
            var currentTime = DateTime.UtcNow.AddDays(-1);
            var fakeCurrentTimeGetter = new FakeCurrentTimeGetter(currentTime);
            container.RegisterInstance<ICurrentTimeGetter>(fakeCurrentTimeGetter);

            var offset = 2;
            var timestampTime = DateTime.Parse(currentTime.ToString());
            var ocspProducedAt = timestampTime;
            var ocspThisUpdate = timestampTime.AddSeconds(-1 * offset);
            var ocspNextUpdate = timestampTime.AddSeconds(offset);
            var crlThisUpdate = timestampTime.AddSeconds(-1 * offset);
            var crlNextUpdate = timestampTime.AddSeconds(offset);
            var signingDate = timestampTime;

            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile: SignatureProfile.XLType1,
                timestampTime: timestampTime,
                ocspProducedAt: ocspProducedAt,
                ocspThisUpdate: ocspThisUpdate,
                ocspNextUpdate: ocspNextUpdate,
                crlThisUpdate: crlThisUpdate,
                crlNextUpdate: crlNextUpdate,
                signingDate: signingDate,
                enrichXTimestamp: true);


            // check that a time for esc timestamps is as set above
            {
                var cms = new CmsSignedData(Streams.ReadAll(signedDocument.OpenStream()));
                // nloglogger.Trace(Convert.ToBase64String(cms.GetEncoded()));
                var si = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
                var cmsUnsigneds = new OrderedAttributeTable(si.ToSignerInfo().UnauthenticatedAttributes);
                var tCms = new CmsSignedData(
                        cmsUnsigneds[PkcsObjectIdentifiers.IdAAEtsEscTimeStamp]!
                            .First().AttrValues[0].GetDerEncoded());
                var tSi = tCms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();

                var ocspRep = tSi.UnsignedAttributes.GetOcspReps().First();
                Assert.AreEqual(ocspThisUpdate, ocspRep.Responses[0].ThisUpdate);
            }

            // setup current time
            currentTime = DateTime.UtcNow;
            fakeCurrentTimeGetter.CurrentUtcTime = currentTime;
            timestampTime = DateTime.Parse(currentTime.ToString());
            ocspProducedAt = timestampTime;
            ocspThisUpdate = timestampTime.AddSeconds(-1 * offset);
            ocspNextUpdate = timestampTime.AddSeconds(offset);
            crlThisUpdate = timestampTime.AddSeconds(-1 * offset);
            crlNextUpdate = timestampTime.AddSeconds(offset);
            signingDate = timestampTime;
            SomeSetupSigning(
                container,
                signatureProfile: SignatureProfile.XLType1,
                timestampTime: timestampTime,
                ocspProducedAt: ocspProducedAt,
                ocspThisUpdate: ocspThisUpdate,
                ocspNextUpdate: ocspNextUpdate,
                crlThisUpdate: crlThisUpdate,
                crlNextUpdate: crlNextUpdate,
                signingDate: signingDate);


            // an A generating 
            var settings = container.Resolve<CAdESServiceSettings>();
            var signatureProfile = SignatureProfile.A;
            var parameters = new SignatureParameters
            {
                SignaturePackaging = settings.SignaturePackaging,
                SignatureProfile = signatureProfile,
                DigestAlgorithmOID = settings.TspDigestAlgorithmOID
            };

            var (signedDocumentA, _) = cadesService.ExtendDocument(signedDocument, inputDocument, parameters);

            // check validation
            var validationReport = cadesService.ValidateDocument(signedDocumentA, false, inputDocument);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(FileSignatureState.Checked, state);
            Assert.AreEqual(signatureProfile, levelReached);

            // check that a time for esc timestamps are new ones
            {
                var cms = new CmsSignedData(Streams.ReadAll(signedDocumentA.OpenStream()));
                var si = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
                var cmsUnsigneds = new OrderedAttributeTable(si.ToSignerInfo().UnauthenticatedAttributes);
                var tCms = new CmsSignedData(
                        cmsUnsigneds[PkcsObjectIdentifiers.IdAAEtsEscTimeStamp]!
                            .First().AttrValues[0].GetDerEncoded());
                var tSi = tCms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();

                var tCmsUnsigneds = new OrderedAttributeTable(tSi.ToSignerInfo().UnauthenticatedAttributes);
                var ocspRep = tSi.UnsignedAttributes.GetOcspReps().First();
                Assert.AreEqual(ocspThisUpdate, ocspRep.Responses[0].ThisUpdate);
            }
        }

        [Test]
        public void when_extend_A_to_A_should_update_outdated_revocs()
        {
            var (container, fakeHttpDataLoader) = Setup();

            var currentTime = DateTime.Parse(DateTime.UtcNow.AddMinutes(-30).ToString());
            var fakeCurrentTimeGetter = new FakeCurrentTimeGetter(currentTime);
            container.RegisterInstance<ICurrentTimeGetter>(fakeCurrentTimeGetter);

            var timestampTime = currentTime;
            var ocspProducedAt = currentTime;
            var ocspThisUpdate = currentTime;
            var crlThisUpdate = currentTime.AddMinutes(-60);
            var crlNextUpdate = currentTime.AddMinutes(60);
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                container,
                signatureProfile: SignatureProfile.T,
                timestampTime: timestampTime,
                ocspProducedAt: ocspProducedAt,
                ocspThisUpdate: ocspThisUpdate,
                crlThisUpdate: crlThisUpdate,
                crlNextUpdate: crlNextUpdate);

            var settings = container.Resolve<CAdESServiceSettings>();
            var signatureProfile = SignatureProfile.A;
            var parameters = new SignatureParameters
            {
                SignaturePackaging = settings.SignaturePackaging,
                SignatureProfile = signatureProfile,
                DigestAlgorithmOID = settings.TspDigestAlgorithmOID
            };

            var (signedDocumentA, _) = cadesService.ExtendDocument(signedDocument, inputDocument, parameters);

            currentTime = DateTime.Parse(DateTime.UtcNow.ToString());
            fakeCurrentTimeGetter.CurrentUtcTime = currentTime;
            ocspProducedAt = currentTime;
            ocspThisUpdate = currentTime;
            crlThisUpdate = currentTime.AddMinutes(-60);
            crlNextUpdate = currentTime.AddMinutes(60);
            SomeSetupSigning(
                container,
                signatureProfile: SignatureProfile.T,
                timestampTime: timestampTime,
                ocspProducedAt: ocspProducedAt,
                ocspThisUpdate: ocspThisUpdate,
                crlThisUpdate: crlThisUpdate,
                crlNextUpdate: crlNextUpdate);

            (signedDocumentA, _) = cadesService.ExtendDocument(signedDocumentA, inputDocument, parameters);

            // check validation
            var validationReport = cadesService.ValidateDocument(signedDocumentA, false, inputDocument);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = Extensions.GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = Extensions.GetLevelReached(signatureInformation);

            Assert.AreEqual(FileSignatureState.Checked, state);
            Assert.AreEqual(signatureProfile, levelReached);

            var cms = new CmsSignedData(Streams.ReadAll(signedDocumentA.OpenStream()));
            var si = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
            var cmsUnsigneds = new OrderedAttributeTable(si.ToSignerInfo().UnauthenticatedAttributes);

            var archiveAttributes = cmsUnsigneds[CAdESProfileA.id_aa_ets_archiveTimestamp_v3]!
                .Select(x => new CmsSignedData(x.AttrValues[0].GetDerEncoded()));

            {
                var a1si = archiveAttributes.ElementAt(0).GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
                var a1cmsUnsigneds = new OrderedAttributeTable(a1si.ToSignerInfo().UnauthenticatedAttributes);
                var ocspRep = a1si.UnsignedAttributes.GetOcspReps().First();
                Assert.AreEqual(ocspThisUpdate, ocspRep.Responses[0].ThisUpdate);
            }
        }

        // [Test]
        // public void test_abstract_cryptoprovider()
        // {
        //      // est: 8
        //      // TODO: refactor code to consistent use
        // }

        // --FEATURES

        // [Test]
        // public void extend_T_to_XLT1_with_new_T()
        // {
        //      // feature TODO: there should be parameters to setup desirable behaviour: use new T for XLT1 or XLT1 for everyone
        // }

        // CreateNewAttributeIfExist is a private set - TODO: need to change maybe structure of validation data and defently ui for validation info
        // [TestCase(true, Description = "createNewAttributeIfExist")]
        // [TestCase(false, Description = "don't createNewAttributeIfExist")]
        // public void check_affinity_when_extend_T_createNewAttributeIfExist(bool createNewAttributeIfExist)
        // {
        //     var (container, fakeHttpDataLoader) = Setup();
        //     // can be many t timestamps
        //     var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
        //         container,
        //         signatureProfile: SignatureProfile.T);
        //
        //     var parameters = new SignatureParameters
        //     {
        //         SignatureProfile = SignatureProfile.T,
        //         // CreateNewAttributeIfExist = createNewAttributeIfExist
        //     };
        //
        //     var (extendedDocument, validationReport) = cadesService.ExtendDocument(signedDocument, null, parameters);
        //     var signatureInformation = validationReport.SignatureInformationList.First()!;
        //     var state = Extensions.GetSignatureState(signatureInformation, parameters.SignatureProfile);
        //     var levelReached = Extensions.GetLevelReached(signatureInformation);
        //     Assert.AreEqual(FileSignatureState.Checked, state);
        //     Assert.AreEqual(parameters.SignatureProfile, levelReached);
        //
        //     var cmsSignedData = new CmsSignedData(Streams.ReadAll(extendedDocument.OpenStream()));
        //     var si = cmsSignedData.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        //     var vector = si.UnsignedAttributes.GetAll(PkcsObjectIdentifiers.IdAASignatureTimeStampToken);
        //     if (createNewAttributeIfExist)
        //     {
        //         Assert.AreEqual(2, vector.Count);
        //     }
        //     else
        //     {
        //         Assert.AreEqual(1, vector.Count);
        //     }
        // }

        //
        // [Test]
        // public void extend_to_A_when_there_are_two_timestamps()
        // {
        //      // TODO:
        //      // est: 16
        //      // TODO: refactor code to consistent use
        //      // check with cryptopro plugin
        // }
        //


        // [OneTimeSetUp]
        public UnityContainer SetupFixture()
        {
            // Signer certificate issued by Intermediate, Intermediate by CA.
            // Signer verified by OCSP, which issued by an ocsp provider
            // An ocsp provider was issued by Intermediate
            // An ocsp provider does not have revocation info
            // Intermediate verified by crl 
            // TSP issued by Intermediate
            // TSP verified by OCSP, which issued by an ocsp provider

            // check that refs and values of Signer is present in a main section
            // check that refs and values of TSP is present in a timestamp section
            // check that refs and values are matched

            // TODO additional test cases: a settings crl should only be used, when crl records are present; same with ocsp; flag noocsp should be respected

            #region Certificates creation

            #endregion

            #region Container init
            var container = new UnityContainer();
            container
                .DefaultCAdESLibSetup();

            #endregion
            return container;
        }

        // [SetUp]
        public (IUnityContainer, Mock<IHTTPDataLoader>) Setup()
        {
            var container = SetupFixture();
            var paramsResolver = new ParamsResolver();
            container.RegisterInstance(new ParamsResolver());
            // TODO: set urls and it must be resetable. maybe i need not to set hexString? it will be easy to reset urls without it but a i need to set different urls for tsp, and if i need another certs from different ca?
            var (_, signerCertsParams) = GetSignerCert(container);
            var (tspUrl, tspCertsParams) = GetSignerCert(container, tsp: true);
            container.RegisterInstance(new CAdESServiceSettings
            {
                TspSource = tspUrl,
                TrustedCerts = new List<X509Certificate> { signerCertsParams.CaCert, tspCertsParams.CaCert },
                TspDigestAlgorithmOID = DigestAlgorithm.SHA256.OID
            });
            var ocspProducedAt = DateTime.UtcNow;
            var ocspThisUpdate = ocspProducedAt.AddMinutes(-60);
            var ocspNextUpdate = ocspProducedAt.AddMinutes(60);
            return (container, SetupFakeHttpDataLoader(
                    container,
                    ocspProducedAt: ocspProducedAt,
                    ocspThisUpdate: ocspThisUpdate,
                    ocspNextUpdate: ocspNextUpdate));
        }

        private (
                IDocument signedDocument,
                IDocument inputDocument,
                IDocumentSignatureService cadesService,
                ValidationReport validationReport)
            SomeSetupSigning(
                IUnityContainer container,
                SignatureProfile signatureProfile,

                bool noNetworkBeforeSigning = false,
                bool noNetworkAfterSigning = false,

                bool signerRevokedBeforeSigning = false,
                bool signerRevokedAfterSigning = false,

                bool ocspRevokedBeforeSigning = false,
                bool ocspRevokedAfterSigning = false,

                bool intermediateRevokedBeforeSigning = false,
                bool intermediateRevokedAfterSigning = false,

                bool tspRevokedBeforeSigning = false,
                bool tspRevokedAfterSigning = false,

                bool noNetworkForTspBeforeSigning = false,
                bool noNetworkForTspAfterSigning = false,

                bool noNetworkForInterBeforeSigning = false,
                bool noNetworkForInterAfterSigning = false,

                bool noNetworkForOcspBeforeSigning = false,
                bool noNetworkForOcspAfterSigning = false,

                bool noNetworkForCrlBeforeSigning = false,
                bool noNetworkForCrlAfterSigning = false,

                bool ocspWithoutCrl = false,

                bool ocspRespIDPublicKey = false,

                DateTime? timestampTime = null,

                DateTime? ocspProducedAt = null,
                DateTime? ocspThisUpdate = null,
                DateTime? ocspNextUpdate = null,

                DateTime? crlThisUpdate = null,
                DateTime? crlNextUpdate = null,

                bool crlOutdated = false,

                CertsParams? certsParams = null,

                DateTime? signingDate = null,

                bool enrichXTimestamp = false
            )
        {
            var cadesSettings = container.Resolve<CAdESServiceSettings>();
            var cadesService = container.Resolve<Func<ICAdESServiceSettings, IDocumentSignatureService>>()(cadesSettings);
            // to be signed
            var inputData = Encoding.UTF8.GetBytes("anydataanydataanydataanydataanydataanydataanydataanydata");
            var inputDocument = new InMemoryDocument(inputData);
            var signingTime = signingDate ?? DateTime.UtcNow;
            certsParams ??= container.Resolve<ParamsResolver>().Resolve(UrlType.Signer, UrlType.Signer).First().Item2.Item2;

            var parameters = new SignatureParameters
            {
                SigningCertificate = certsParams.SignerCert,
                CertificateChain = new X509Certificate[] { certsParams.SignerCert },
                SignaturePackaging = SignaturePackaging.DETACHED,
                SignatureProfile = signatureProfile,
                SigningDate = signingTime,
                DigestAlgorithmOID = DigestAlgorithm.SHA256.OID,
                EncriptionAlgorithmOID = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption.Id,
                EnrichXTimestamp = enrichXTimestamp
            };
            var toBeSignedStream = cadesService.ToBeSigned(inputDocument, parameters);
            // sign
            ISigner signer = SignerUtilities.InitSigner(parameters.DigestWithEncriptionOID, true, certsParams.SignerKeyPair.Private, null);
            toBeSignedStream.Position = 0;
            toBeSignedStream.Seek(0, SeekOrigin.Begin);
            var b = Streams.ReadAll(toBeSignedStream);
            signer.BlockUpdate(b, 0, b.Length);
            var signatureValue = signer.GenerateSignature();

            SetupFakeHttpDataLoader(
                container,
                noNetwork: noNetworkBeforeSigning,
                signerRevoked: signerRevokedBeforeSigning,
                ocspRevoked: ocspRevokedBeforeSigning,
                signerIntermediateRevoked: intermediateRevokedBeforeSigning,
                tspRevoked: tspRevokedBeforeSigning,
                noNetworkForTsp: noNetworkForTspBeforeSigning,
                noNetworkForInter: noNetworkForInterBeforeSigning,
                noNetworkForOcsp: noNetworkForOcspBeforeSigning,
                noNetworkForCrl: noNetworkForCrlBeforeSigning,
                ocspRespIDPublicKey: ocspRespIDPublicKey,
                timestampTime: timestampTime,
                ocspProducedAt: ocspProducedAt,
                ocspThisUpdate: ocspThisUpdate,
                ocspNextUpdate: ocspNextUpdate,
                crlThisUpdate: crlThisUpdate,
                crlNextUpdate: crlNextUpdate,
                crlOutdated: crlOutdated);

            // make pkcs7
            var (signedDocument, validationReport) = cadesService.GetSignedDocument(inputDocument, parameters, signatureValue);

            SetupFakeHttpDataLoader(
                container,
                noNetwork: noNetworkAfterSigning,
                signerRevoked: signerRevokedAfterSigning,
                ocspRevoked: ocspRevokedAfterSigning,
                signerIntermediateRevoked: intermediateRevokedAfterSigning,
                tspRevoked: tspRevokedAfterSigning,
                noNetworkForTsp: noNetworkForTspAfterSigning,
                noNetworkForInter: noNetworkForInterAfterSigning,
                noNetworkForOcsp: noNetworkForOcspAfterSigning,
                noNetworkForCrl: noNetworkForCrlAfterSigning,
                ocspRespIDPublicKey: ocspRespIDPublicKey,
                timestampTime: timestampTime,
                ocspProducedAt: ocspProducedAt,
                ocspThisUpdate: ocspThisUpdate,
                ocspNextUpdate: ocspNextUpdate,
                crlThisUpdate: crlThisUpdate,
                crlNextUpdate: crlNextUpdate,
                crlOutdated: crlOutdated);

            return (signedDocument, inputDocument, cadesService, validationReport);
        }

        private Mock<IHTTPDataLoader> SetupFakeHttpDataLoader(
            IUnityContainer container,
            bool noNetwork = false,
            bool signerRevoked = false,
            bool ocspRevoked = false,
            bool signerIntermediateRevoked = false,
            bool tspRevoked = false,
            bool noNetworkForTsp = false,
            bool noNetworkForInter = false,
            bool noNetworkForOcsp = false,
            bool noNetworkForCrl = false,
            // use ocsp public key for reference issuer
            bool ocspRespIDPublicKey = false,
            DateTime? timestampTime = null,
            DateTime? ocspProducedAt = null,
            DateTime? ocspThisUpdate = null,
            DateTime? ocspNextUpdate = null,
            DateTime? crlThisUpdate = null,
            DateTime? crlNextUpdate = null,
            bool crlOutdated = false)
        {
            var fakeHttpDataLoader = new Mock<IHTTPDataLoader>();

            container.RegisterFactory<Func<IRuntimeValidatingParams, IHTTPDataLoader>>(
                    c => new Func<IRuntimeValidatingParams, IHTTPDataLoader>(
                        (runtimeValidatingParams) =>
                        {
                            var paramsResolver = c.Resolve<ParamsResolver>();
                            fakeHttpDataLoader.Setup(x => x.Post(It.IsAny<string>(), It.IsAny<Stream>())).Returns<string, Stream>((url, stream) =>
                            {
                                if (noNetwork)
                                {
                                    return null;
                                }

                                var ((rootType, urlTypeNew), certsParams) = paramsResolver.Resolve(url);

                                nloglogger.Trace($"rootType={rootType}, urlTypeNew={urlTypeNew}");

                                if (rootType == UrlType.Tsp && urlTypeNew == UrlType.Signer)
                                {
                                    if (noNetworkForTsp)
                                    {
                                        return null;
                                    }

                                    var tspCert = certsParams.SignerCert;
                                    var tspKeyPair = certsParams.SignerKeyPair;

                                    var bytes = Streams.ReadAll(stream);
                                    var request = new TimeStampRequest(bytes);

                                    TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(tspKeyPair.Private, tspCert, TspAlgorithms.Sha256, "1.2");
                                    var certs = new ArrayList { tspCert };
                                    var certStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(certs));
                                    tsTokenGen.SetCertificates(certStore);

                                    TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

                                    TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.Arbitrary(8), timestampTime ?? DateTime.UtcNow);

                                    return new MemoryStream(tsResp.GetEncoded());
                                }
                                else if (urlTypeNew == UrlType.Ocsp)
                                {
                                    if (noNetworkForOcsp)
                                    {
                                        return null;
                                    }

                                    var signerCert = certsParams.SignerCert;
                                    var intermediateCert = certsParams.IntermediateCert;
                                    var ocspCert = certsParams.OcspCert;
                                    var ocspKeyPair = certsParams.OcspKeyPair;
                                    var caCert = certsParams.CaCert;

                                    var bytes = Streams.ReadAll(stream);
                                    var request = new OcspReq(bytes);

                                    BasicOcspRespGenerator generator = new BasicOcspRespGenerator(
                                        ocspRespIDPublicKey ? new RespID(ocspCert.GetPublicKey()) : new RespID(ocspCert.SubjectDN));

                                    var certIDList = request.GetRequestList().Select(x => x.GetCertID());
                                    var status = GetRevokedStatus(
                                        certIDList,
                                        signerRevoked && rootType == UrlType.Signer || tspRevoked && rootType == UrlType.Tsp ?
                                            signerCert :
                                            signerIntermediateRevoked && rootType == UrlType.Signer ?
                                                 intermediateCert : null);

                                    var noncevalue = request.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce) as DerOctetString;
                                    if (noncevalue != null)
                                    {
                                        var oids = new List<DerObjectIdentifier> { OcspObjectIdentifiers.PkixOcspNonce };
                                        var values = new List<X509Extension> { new X509Extension(DerBoolean.False, noncevalue) };
                                        generator.SetResponseExtensions(new Org.BouncyCastle.Asn1.X509.X509Extensions(oids, values));
                                    }

                                    var producedAt = ocspProducedAt ?? DateTime.UtcNow;
                                    var thisUpdate = ocspThisUpdate ?? producedAt.AddMinutes(-1);
                                    var nextUpdate = ocspNextUpdate ?? producedAt.AddMinutes(1);

                                    nloglogger.Trace($"fakeOcsp, url={url}, producedAt={producedAt}, thisUpdate={thisUpdate}, nextUpdate={nextUpdate}");

                                    foreach (var req in certIDList)
                                    {
                                        generator.AddResponse(req, status, thisUpdate, nextUpdate, null);
                                    }

                                    BasicOcspResp basicOcspResp = generator.Generate(
                                            ocspCert.SigAlgOid,
                                            ocspKeyPair.Private,
                                            new X509Certificate[] { ocspCert,
                                            intermediateCert,
                                            caCert }, producedAt, null);
                                    var ocspResponseGenerator = new OCSPRespGenerator();
                                    var ocspResponse = ocspResponseGenerator.Generate(OCSPRespGenerator.Successful, basicOcspResp);

                                    return new MemoryStream(ocspResponse.GetEncoded());
                                }

                                return null;
                            });
                            fakeHttpDataLoader.Setup(x => x.Get(It.IsAny<string>())).Returns<string>((url) =>
                            {
                                nloglogger.Trace($"get {url}");
                                if (noNetwork)
                                {
                                    nloglogger.Trace("no network");
                                    return null;
                                }
                                var ((rootType, urlTypeNew), certsParams) = paramsResolver.Resolve(url);
                                nloglogger.Trace($"rootType={rootType}, urlTypeNew={urlTypeNew}");

                                if (runtimeValidatingParams.OfflineValidating)
                                {
                                    nloglogger.Trace("offlinevalidating");
                                    return null;
                                }
                                if (urlTypeNew == UrlType.Intermediate)
                                {
                                    if (noNetworkForInter)
                                    {
                                        nloglogger.Trace("noNetworkForInter");
                                        return null;
                                    }

                                    return new MemoryStream(certsParams.IntermediateCert.GetEncoded());
                                }
                                else if (urlTypeNew == UrlType.Ca)
                                {
                                    return new MemoryStream(certsParams.CaCert.GetEncoded());
                                }
                                else if (urlTypeNew == UrlType.CrlCa || urlTypeNew == UrlType.CrlInter)
                                {
                                    if (noNetworkForCrl)
                                    {
                                        return null;
                                    }

                                    var revokedSerialNumbers = new List<BigInteger>();
                                    if (signerRevoked && rootType == UrlType.Signer || tspRevoked && rootType == UrlType.Tsp)
                                    {
                                        revokedSerialNumbers.Add(certsParams.SignerCert.SerialNumber);
                                    }

                                    if (signerIntermediateRevoked && rootType == UrlType.Signer)
                                    {
                                        revokedSerialNumbers.Add(certsParams.IntermediateCert.SerialNumber);
                                    }

                                    if (ocspRevoked)
                                    {
                                        revokedSerialNumbers.Add(certsParams.OcspCert.SerialNumber);
                                    }

                                    if (urlTypeNew == UrlType.CrlCa)
                                    {
                                        return new MemoryStream(
                                                GetX509Crl(
                                                    certsParams.CaCert,
                                                    certsParams.CaKeyPair,
                                                    certsParams.CaCert.SigAlgOid,
                                                    crlThisUpdate,
                                                    crlNextUpdate,
                                                    crlOutdated,
                                                    revokedSerialNumbers.ToArray()).GetEncoded());
                                    }
                                    else if (urlTypeNew == UrlType.CrlInter)
                                    {
                                        return new MemoryStream(GetX509Crl(
                                                    certsParams.IntermediateCert,
                                                    certsParams.IntermediateKeyPair,
                                                    certsParams.CaCert.SigAlgOid,
                                                    crlThisUpdate,
                                                    crlNextUpdate,
                                                    crlOutdated,
                                                    revokedSerialNumbers.ToArray()).GetEncoded());
                                    }
                                }

                                return null;
                            });
                            return fakeHttpDataLoader.Object;
                        }));
            return fakeHttpDataLoader;
        }

        private Org.BouncyCastle.Ocsp.CertificateStatus GetRevokedStatus(
            IEnumerable<CertificateID> certIDList,
            X509Certificate? revokedCert) => revokedCert != null && certIDList.Any(x => x.SerialNumber.Equals(revokedCert.SerialNumber)) ?
                                         new RevokedStatus(new RevokedInfo(new DerGeneralizedTime(DateTime.UtcNow.AddDays(-1).ToZuluString()), new CrlReason(CrlReason.KeyCompromise)))
                                         : Org.BouncyCastle.Ocsp.CertificateStatus.Good;

        private X509Crl GetX509Crl(
                X509Certificate issuer,
                AsymmetricCipherKeyPair keyPair,
                string sigAlgOid,
                DateTime? crlThisUpdate = null,
                DateTime? crlNextUpdate = null,
                bool crlOutdated = false,
                params BigInteger[] revokedSerialNumbers)
        {
            var lastCRLNumber = BigInteger.One;
            var crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(issuer.SubjectDN);
            DateTime skewedNow = crlOutdated ? DateTime.UtcNow.AddMonths(-1) : DateTime.UtcNow.AddHours(-1);
            var thisUpdate = crlThisUpdate ?? skewedNow;
            var nextUpdate = crlNextUpdate ?? skewedNow.AddHours(12);
            crlGen.SetThisUpdate(thisUpdate);
            crlGen.SetNextUpdate(nextUpdate);
            crlGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuer));
            crlGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.CrlNumber, false, new CrlNumber(lastCRLNumber));
            //crlGen.addCRL(previousCRL);
            foreach (var sn in revokedSerialNumbers)
            {
                crlGen.AddCrlEntry(sn, DateTime.UtcNow.AddDays(-1), CrlReason.KeyCompromise);
            }

            return crlGen.Generate(new Asn1SignatureFactory(sigAlgOid, keyPair.Private, null));
        }

        private (string, CertsParams) GetSignerCert(
                IUnityContainer container,
                bool signerOverdue = false,
                bool useCrl = true,
                bool ocspWOCrl = false,
                bool tsp = false,
                (bool useOcsp, bool noCheck)? ocsp = null)
        {
            ocsp ??= (true, false);
            var random = new Random();
            var num = random.Next();
            var hexString = num.ToString("X");
            var notBefore = DateTime.UtcNow.AddDays(-30);
            var signerNotBefore = notBefore;
            var notAfter = DateTime.UtcNow.AddDays(30);
            var signerNotAfter = signerOverdue ? DateTime.UtcNow.AddDays(-1) : notAfter;

            var signerUrl = tsp ? "http://tsp_" + hexString : "http://signer_" + hexString;

            // CA
            var ca = new X509Name("CN=ca_" + hexString);
            var caKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            var caCert = CryptoHelpers.GenerateCertificate(
                    ca,
                    ca,
                    caKeyPair.Private,
                    caKeyPair.Public,
                    notBefore: notBefore,
                    notAfter: notAfter
                    );
            var caUrl = "http://ca_" + hexString;
            var crlCaUrl = "http://crlCa_" + hexString;

            // Intermediate
            var intermediateUrl = "http://intermediate_" + hexString;
            var crlInterUrl = "http://crlIntermediate_" + hexString;
            var intermediateCertName = new X509Name("CN=intermediate_" + hexString);
            var intermediateKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            var intermediateCert = CryptoHelpers.GenerateCertificate(
                    ca,
                    intermediateCertName,
                    caKeyPair.Private,
                    intermediateKeyPair.Public,
                    notBefore: notBefore,
                    notAfter: notAfter,
                    issuerUrls: new string[] { caUrl },
                    crlUrls: new string[] { crlCaUrl });

            // OCSP
            var ocspUrl = "http://ocsp_" + hexString;
            var ocspCertName = new X509Name("CN=ocsp_cert_" + hexString);
            var ocspKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            var ocspCert = CryptoHelpers.GenerateCertificate(
                intermediateCertName,
                ocspCertName,
                intermediateKeyPair.Private,
                ocspKeyPair.Public,
                notBefore: notBefore,
                notAfter: notAfter,
                issuerUrls: new string[] { intermediateUrl },
                crlUrls: ocspWOCrl ? null : new string[] { crlInterUrl },
                ocspParam: ocsp);

            // Signer
            var signerCertName = new X509Name("CN=" + (tsp ? "tsp" : "signer_cert_") + hexString);
            var signerKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            var signerCert = CryptoHelpers.GenerateCertificate(
                intermediateCertName,
                signerCertName,
                intermediateKeyPair.Private,
                signerKeyPair.Public,
                notBefore: signerNotBefore,
                notAfter: signerNotAfter,
                tsp: tsp,
                issuerUrls: new string[] { intermediateUrl },
                crlUrls: useCrl ? new string[] { crlInterUrl } : null,
                ocspUrls: ocsp?.useOcsp ?? false ? new string[] { ocspUrl } : null);

            var certParams = new CertsParams(
                signerCert: signerCert,
                signerKeyPair: signerKeyPair,
                intermediateCert: intermediateCert,
                intermediateKeyPair: intermediateKeyPair,
                ocspCert: ocspCert,
                ocspKeyPair: ocspKeyPair,
                caCert: caCert,
                caKeyPair: caKeyPair);

            var paramsResolver = container.Resolve<ParamsResolver>();

            UrlType rootType = tsp ? UrlType.Tsp : UrlType.Signer;

            paramsResolver.Add(
               signerUrl,
                ((rootType, UrlType.Signer), certParams));

            paramsResolver.Add(
                caUrl,
                ((rootType, UrlType.Ca), certParams));
            paramsResolver.Add(
                intermediateUrl,
                ((rootType, UrlType.Intermediate), certParams));
            paramsResolver.Add(
                ocspUrl,
                ((rootType, UrlType.Ocsp), certParams));
            paramsResolver.Add(
                crlCaUrl,
                ((rootType, UrlType.CrlCa), certParams));
            paramsResolver.Add(
                crlInterUrl,
                ((rootType, UrlType.CrlInter), certParams));

            return (signerUrl, certParams);
        }
    }

    enum UrlType
    {
        Signer,
        Tsp,
        Ocsp,
        Intermediate,
        Ca,
        CrlInter,
        CrlCa
    }

    class CertsParams
    {
        public X509Certificate SignerCert { get; private set; }
        public AsymmetricCipherKeyPair SignerKeyPair { get; private set; }
        public X509Certificate IntermediateCert { get; internal set; }
        public AsymmetricCipherKeyPair IntermediateKeyPair { get; private set; }
        public X509Certificate OcspCert { get; internal set; }
        public AsymmetricCipherKeyPair OcspKeyPair { get; internal set; }
        public X509Certificate CaCert { get; internal set; }
        public AsymmetricCipherKeyPair CaKeyPair { get; internal set; }

        public CertsParams(
                X509Certificate signerCert,
                AsymmetricCipherKeyPair signerKeyPair,
                X509Certificate intermediateCert,
                AsymmetricCipherKeyPair intermediateKeyPair,
                X509Certificate ocspCert,
                AsymmetricCipherKeyPair ocspKeyPair,
                X509Certificate caCert,
                AsymmetricCipherKeyPair caKeyPair
                )
        {
            this.SignerCert = signerCert;
            this.SignerKeyPair = signerKeyPair;
            this.IntermediateCert = intermediateCert;
            this.IntermediateKeyPair = intermediateKeyPair;
            this.OcspCert = ocspCert;
            this.OcspKeyPair = ocspKeyPair;
            this.CaCert = caCert;
            this.CaKeyPair = caKeyPair;
        }
    }

    class ParamsResolver
    {
        private Dictionary<string, ((UrlType, UrlType), CertsParams)> prms = new Dictionary<string, ((UrlType, UrlType), CertsParams)>();

        public ((UrlType, UrlType), CertsParams) Resolve(string url)
        {
            return prms[url];
        }

        public IEnumerable<(string, ((UrlType, UrlType), CertsParams))> Resolve(UrlType rootType, UrlType urlType)
        {
            return prms.Where(x => x.Value.Item1.Item1 == rootType && x.Value.Item1.Item2 == urlType).Select(x => (x.Key, x.Value));
        }

        public void Add(string url, ((UrlType, UrlType), CertsParams) value)
        {
            prms.Add(url, value);
        }

        public void Remove(string url)
        {
            prms.Remove(url);
        }
        public void Remove(UrlType rootType)
        {
            var urls = prms.Where(x => x.Value.Item1.Item1 == rootType).Select(x => x.Key).Distinct();
            foreach (var url in urls)
            {
                prms.Remove(url);
            }
        }
    }

    class FakeCurrentTimeGetter : ICurrentTimeGetter
    {
        public FakeCurrentTimeGetter(DateTime value)
        {
            this.CurrentUtcTime = value;
        }

        public DateTime CurrentUtcTime { get; set; }
    }
}
