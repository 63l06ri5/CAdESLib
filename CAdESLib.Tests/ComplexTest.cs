using CAdESLib.Document;
using CAdESLib.Document.Signature;
using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using CAdESLib.Service;
using Moq;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Unity;
using Unity.Lifetime;
using System.Linq;
using Org.BouncyCastle.Cms;

namespace CAdESLib.Tests
{
    [TestFixture]
    public class ComplexTests
    {

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        private Mock<IHTTPDataLoader> fakeHttpDataLoader;
        private UnityContainer container;
        // private X509Crl crl;
        private CAdESServiceSettings cadesSettings;
        private AsymmetricCipherKeyPair caKeyPair;
        private X509Certificate caCert;
        private string crlCaUrl = "http://crlca";
        private string crlInterUrl = "http://crlinter";
        private string caUrl = "http://ca";
        private X509Certificate intermediateCert;
        private X509Name intermediateCertName = new X509Name("CN=intermediate_cert");
        private AsymmetricCipherKeyPair intermediateKeyPair;
        private X509Name tspCertName = new X509Name("CN=tsp_cert");
        private string ocspUrl = "http://ocsp";
        private string intermediateUrl = "http://intermediate";

        private AsymmetricCipherKeyPair signerKeyPair;
        private X509Certificate signerCert;
        private AsymmetricCipherKeyPair ocspKeyPair;
        private X509Certificate ocspCert;
        private string tspUrl;
        private AsymmetricCipherKeyPair tspKeyPair;
        private X509Certificate tspCert;
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

        [TestCase(true, Description = "crlOnline")]
        [TestCase(false, Description = "crlOffline")]
        public void XLT1_with_same_issuers_chain(bool crlOnline)
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

            if (!crlOnline)
            {
                if (cadesSettings.Crls == null)
                {
                    cadesSettings.Crls = new List<X509Crl>();
                }

                cadesSettings.Crls.Add(GetX509Crl(intermediateCert, intermediateKeyPair));
                cadesSettings.Crls.Add(GetX509Crl(caCert, caKeyPair));
            }

            var cadesService = container.Resolve<Func<ICAdESServiceSettings, IDocumentSignatureService>>()(cadesSettings);
            // to be signed
            var inputData = Encoding.UTF8.GetBytes("anydataanydataanydataanydataanydataanydataanydataanydata");
            var inputDocument = new InMemoryDocument(inputData);
            var signingTime = DateTime.Now;
            var parameters = new SignatureParameters
            {
                SigningCertificate = signerCert,
                CertificateChain = new X509Certificate[] { signerCert },
                SignaturePackaging = SignaturePackaging.DETACHED,
                //SignatureProfile = SignatureProfile.XLType1,
                SigningDate = signingTime,
                DigestAlgorithmOID = DigestAlgorithm.SHA256.OID,
                EncriptionAlgorithmOID = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption.Id
            };
            var toBeSignedStream = cadesService.ToBeSigned(inputDocument, parameters);
            // sign
            ISigner signer = SignerUtilities.InitSigner(parameters.DigestWithEncriptionOID, true, signerKeyPair.Private, null);
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
                // sign: ocsp -1  extend: tsp - 2, ocsp - 2
                fakeHttpDataLoader.Verify(x => x.Post(It.IsAny<string>(), It.IsAny<Stream>()), Times.Exactly(1 + 4));
                // sign: intermediate - 1, crl - 2 (1 - inter, 1 - ocsp) if crlOnline else 0, extend: intermediate - 1, crl - 2 (1 - inter, 1 - ocsp) if crlOnline else 0, ca - 0 (it is present because of a trusted list)
                fakeHttpDataLoader.Verify(x => x.Get(It.IsAny<string>()), Times.Exactly(crlOnline ? 6 : 2));
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
            Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.All(x => x.SameDigest?.IsValid ?? false), "XType1 timestamps are not valid");
            Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.All(x => x.CertPathVerification.IsValid), "XType1 cert paths are not valid");

            var cms = new CmsSignedData(Streams.ReadAll(signedDocument.OpenStream()));
            var signers = cms.GetSignerInfos().GetSigners().GetEnumerator();
            signers.MoveNext();
            var signerInformation = (signers.Current as SignerInformation)!;

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
                    byte[] hash = DigestUtilities.CalculateDigest(referencedCert.DigestAlgorithm, valueCert.GetEncoded());
                    Assert.IsTrue(hash.SequenceEqual(referencedCert.DigestValue), $"{label} cert ref index={i} is not matched");
                }
            };

            // main refs and vals should match 
            refsValsChecker("main", signerCert, signerInformation.UnsignedAttributes);

            // tsp refs and vals should match 
            var timestamp = signerInformation.GetSignatureTimestamps().First()!;
            var tspUnsignedAttributes = timestamp.GetTimeStamp().UnsignedAttributes;
            refsValsChecker("tsp", timestamp.GetSigner()!, tspUnsignedAttributes);
        }

        [Test]
        public void T_with_same_issuers_chain()
        {
            var cadesService = container.Resolve<Func<ICAdESServiceSettings, IDocumentSignatureService>>()(cadesSettings);
            // to be signed
            var inputData = Encoding.UTF8.GetBytes("anydataanydataanydataanydataanydataanydataanydataanydata");
            var inputDocument = new InMemoryDocument(inputData);
            var signingTime = DateTime.Now;
            var parameters = new SignatureParameters
            {
                SigningCertificate = signerCert,
                CertificateChain = new X509Certificate[] { signerCert },
                SignaturePackaging = SignaturePackaging.DETACHED,
                SignatureProfile = SignatureProfile.T,
                SigningDate = signingTime,
                DigestAlgorithmOID = DigestAlgorithm.SHA256.OID,
                EncriptionAlgorithmOID = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption.Id
            };
            var toBeSignedStream = cadesService.ToBeSigned(inputDocument, parameters);
            // sign
            ISigner signer = SignerUtilities.InitSigner(parameters.DigestWithEncriptionOID, true, signerKeyPair.Private, null);
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
                // intermediate - 1, crl - 2 
                fakeHttpDataLoader.Verify(x => x.Get(It.IsAny<string>()), Times.Exactly(3));
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
            var cadesService = container.Resolve<Func<ICAdESServiceSettings, IDocumentSignatureService>>()(cadesSettings);
            // to be signed
            var inputData = Encoding.UTF8.GetBytes("anydataanydataanydataanydataanydataanydataanydataanydata");
            var inputDocument = new InMemoryDocument(inputData);
            var signingTime = DateTime.Now;
            var parameters = new SignatureParameters
            {
                SigningCertificate = signerCert,
                CertificateChain = new X509Certificate[] { signerCert },
                SignaturePackaging = SignaturePackaging.DETACHED,
                SignatureProfile = SignatureProfile.BES,
                SigningDate = signingTime,
                DigestAlgorithmOID = DigestAlgorithm.SHA256.OID,
                EncriptionAlgorithmOID = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption.Id
            };
            var toBeSignedStream = cadesService.ToBeSigned(inputDocument, parameters);
            // sign
            ISigner signer = SignerUtilities.InitSigner(parameters.DigestWithEncriptionOID, true, signerKeyPair.Private, null);
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
            var signers = cms.GetSignerInfos().GetSigners().GetEnumerator();
            signers.MoveNext();
            var signerInformation = (signers.Current as SignerInformation)!;

            Assert.IsNull(signerInformation.UnsignedAttributes);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.CheckedWithWarning, SignatureProfile.T)]
        [TestCase(SignatureProfile.C, FileSignatureState.CheckedWithWarning, SignatureProfile.C)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.CheckedWithWarning, SignatureProfile.XType1)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.CheckedWithWarning, SignatureProfile.XType2)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Checked, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Checked, SignatureProfile.XLType2)]
        public void check_no_net(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                signatureProfile,
                noNetworkAfterSigning: true);

            var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.C, FileSignatureState.Failed, SignatureProfile.C)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.Failed, SignatureProfile.XType1)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.Failed, SignatureProfile.XType2)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Checked, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Checked, SignatureProfile.XLType2)]
        public void check_signer_revoked(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                signatureProfile,
                signerRevokedAfterSigning: true);

            var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.C, FileSignatureState.Failed, SignatureProfile.C)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.Failed, SignatureProfile.XType1)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.Failed, SignatureProfile.XType2)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Checked, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Checked, SignatureProfile.XLType2)]
        public void check_intermediate_revoked(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                signatureProfile,
                intermediateRevokedAfterSigning: true);

            var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.C, FileSignatureState.Failed, SignatureProfile.C)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.Failed, SignatureProfile.XType1)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.Failed, SignatureProfile.XType2)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.XLType2)]
        public void check_signer_after_NotAfter(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            SetupSignerCert(overdue: true);

            var (signedDocument, inputDocument, cadesService, _) = SomeSetupSigning(
                signatureProfile);

            var validationReport = cadesService.ValidateDocument(signedDocument, false, inputDocument);
            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);

        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.C, FileSignatureState.Failed, SignatureProfile.C)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.Failed, SignatureProfile.XType1)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.Failed, SignatureProfile.XType2)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.XLType2)]
        public void signer_signer_after_NotAfter(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            SetupSignerCert(overdue: true);

            var (_, _, _, validationReport) = SomeSetupSigning(
                signatureProfile);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);

        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.C, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.BES)]
        public void sign_no_net(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (_, _, _, validationReport) = SomeSetupSigning(
                signatureProfile,
                noNetworkBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.C, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.BES)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.BES)]
        public void sign_no_net_for_tsp(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (_, _, _, validationReport) = SomeSetupSigning(
                signatureProfile,
                noNetworkForTspBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.CheckedWithWarning, SignatureProfile.T)]
        [TestCase(SignatureProfile.C, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.T)]
        public void sign_no_net_for_inter(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (_, _, _, validationReport) = SomeSetupSigning(
                signatureProfile,
                noNetworkForInterBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.CheckedWithWarning, SignatureProfile.T)]
        [TestCase(SignatureProfile.C, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.T)]
        public void sign_no_net_for_revocation(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (_, _, _, validationReport) = SomeSetupSigning(
                signatureProfile,
                noNetworkForOcspBeforeSigning: true,
                noNetworkForCrlBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.C, FileSignatureState.Failed, SignatureProfile.C)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.Failed, SignatureProfile.XType1)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.Failed, SignatureProfile.XType2)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.XLType2)]
        public void sign_signer_revoked(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (_, _, _, validationReport) = SomeSetupSigning(
                signatureProfile,
                signerRevokedBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.C, FileSignatureState.Failed, SignatureProfile.C)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.Failed, SignatureProfile.XType1)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.Failed, SignatureProfile.XType2)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.XLType2)]
        public void sign_ocsp_revoked(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (_, _, _, validationReport) = SomeSetupSigning(
                signatureProfile,
                ocspRevokedBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.C, FileSignatureState.Failed, SignatureProfile.C)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.Failed, SignatureProfile.XType1)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.Failed, SignatureProfile.XType2)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.XLType2)]
        public void sign_inter_revoked(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (_, _, _, validationReport) = SomeSetupSigning(
                signatureProfile,
                intermediateRevokedBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }

        [TestCase(SignatureProfile.T, FileSignatureState.Failed, SignatureProfile.T)]
        [TestCase(SignatureProfile.C, FileSignatureState.Failed, SignatureProfile.C)]
        [TestCase(SignatureProfile.XType1, FileSignatureState.Failed, SignatureProfile.XType1)]
        [TestCase(SignatureProfile.XType2, FileSignatureState.Failed, SignatureProfile.XType2)]
        [TestCase(SignatureProfile.XLType1, FileSignatureState.Failed, SignatureProfile.XLType1)]
        [TestCase(SignatureProfile.XLType2, FileSignatureState.Failed, SignatureProfile.XLType2)]
        public void sign_tsp_revoked(SignatureProfile signatureProfile, FileSignatureState expectedState, SignatureProfile expectedLevel)
        {
            var (_, _, _, validationReport) = SomeSetupSigning(
                signatureProfile,
                tspRevokedBeforeSigning: true);

            var signatureInformation = validationReport.SignatureInformationList.First()!;
            var state = GetSignatureState(signatureInformation, signatureProfile);
            var levelReached = GetLevelReached(signatureInformation);

            Assert.AreEqual(expectedState, state);
            Assert.AreEqual(expectedLevel, levelReached);
        }


        [OneTimeSetUp]
        public void SetupFixture()
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

            // CA
            var ca = new X509Name("CN=ca");
            caKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            caCert = CryptoHelpers.GenerateCertificate(ca, ca, caKeyPair.Private, caKeyPair.Public);

            // Intermediate

            intermediateKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            intermediateCert = CryptoHelpers.GenerateCertificate(ca, intermediateCertName, caKeyPair.Private, intermediateKeyPair.Public, issuerUrls: new string[] { caUrl }, crlUrls: new string[] { crlCaUrl });

            // OCSP
            var ocspCertName = new X509Name("CN=ocsp_cert");
            ocspKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            ocspCert = CryptoHelpers.GenerateCertificate(intermediateCertName, ocspCertName, intermediateKeyPair.Private, ocspKeyPair.Public, issuerUrls: new string[] { intermediateUrl }, crlUrls: new string[] { crlInterUrl }, ocsp: true);

            // TSP
            tspUrl = "http://tsp";
            tspKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            tspCert = CryptoHelpers.GenerateCertificate(intermediateCertName, tspCertName, intermediateKeyPair.Private, tspKeyPair.Public, issuerUrls: new string[] { intermediateUrl }, crlUrls: new string[] { crlInterUrl }, ocspUrls: new string[] { ocspUrl }, tsp: true);

            #endregion

            cadesSettings = new CAdESServiceSettings
            {
                TspSource = tspUrl,
                TrustedCerts = new List<X509Certificate> { caCert }
            };


            #region Container init
            container = new UnityContainer();
            container

                // CAdESLib usage

                .RegisterFactory<Func<ICAdESServiceSettings, IDocumentSignatureService>>(c => new Func<ICAdESServiceSettings, IDocumentSignatureService>(
                    (settings) => new CAdESService(
                        (runtimeValidatingParams) => c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ITspSource>>()(runtimeValidatingParams, settings),
                        (runtimeValidatingParams) => c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICertificateVerifier>>()(runtimeValidatingParams, settings),
                        (runtimeValidatingParams) => c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ISignedDocumentValidator>>()(runtimeValidatingParams, settings))
                    ))


                .RegisterFactory<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICertificateVerifier>>(c => new Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICertificateVerifier>((runtimeValidationSettings, settings) =>
                    new TrustedListCertificateVerifier(
                        c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, Func<X509Certificate, DateTime, ICAdESLogger?, IValidationContext>>>()(runtimeValidationSettings, settings))))

                .RegisterFactory<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ISignedDocumentValidator>>(c => new Func<IRuntimeValidatingParams, ICAdESServiceSettings, ISignedDocumentValidator>((runtimeValidationSettings, settings) =>
                    new SignedDocumentValidator(
                        c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICertificateVerifier>>()(runtimeValidationSettings, settings),
                        c.Resolve<Func<ICAdESLogger>>(),
                        c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings,
                        Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext>>>()(runtimeValidationSettings, settings))))

                .RegisterType<ICAdESLogger, CAdESLogger>(new TransientLifetimeManager())

                .RegisterFactory<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ITspSource>>(
                    c =>
                    new Func<IRuntimeValidatingParams, ICAdESServiceSettings, ITspSource>(
                        (runtimeValidatingParams, settings) =>
                            new OnlineTspSource(
                                settings,
                                () => c.Resolve<Func<IRuntimeValidatingParams, IHTTPDataLoader>>()(runtimeValidatingParams))))

                .RegisterFactory<Func<IRuntimeValidatingParams, ICAdESServiceSettings, IOcspSource>>(
                    c =>
                    new Func<IRuntimeValidatingParams, ICAdESServiceSettings, IOcspSource>(
                        (runtimeValidatingParams, settings) =>
                        new OnlineOcspSource(
                            settings,
                            () => c.Resolve<Func<IRuntimeValidatingParams, IHTTPDataLoader>>()(runtimeValidatingParams))))

                .RegisterFactory<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICrlSource>>(
                    c =>
                    new Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICrlSource>(
                        (runtimeValidatingParams, settings) =>
                        new OnlineCrlSource(
                            settings,
                            () => c.Resolve<Func<IRuntimeValidatingParams, IHTTPDataLoader>>()(runtimeValidatingParams))))

                .RegisterFactory<Func<ICAdESServiceSettings, ICertificateSource>>(c => new Func<ICAdESServiceSettings, ICertificateSource>((settings) => new ListCertificateSourceWithSetttings(settings)))

                .RegisterFactory<Func<IRuntimeValidatingParams, ICertificateSourceFactory>>(
                    c =>
                    new Func<IRuntimeValidatingParams, ICertificateSourceFactory>(
                        (runtimeValidatingParams) =>
                            new AIACertificateFactoryImpl(
                                () => c.Resolve<Func<IRuntimeValidatingParams, IHTTPDataLoader>>()(runtimeValidatingParams))))

                .RegisterFactory<Func<IRuntimeValidatingParams, ICAdESServiceSettings, Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext>>>(
                    c =>
                    new Func<IRuntimeValidatingParams, ICAdESServiceSettings, Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext>>(
                        (runtimeValidatingParams, settings) => (cert, date, logger) =>
                        new ValidationContext(
                              cert,
                              date,
                              logger,
                              c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, IOcspSource>>()(runtimeValidatingParams, settings),
                              c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICrlSource>>()(runtimeValidatingParams, settings),
                              c.Resolve<Func<ICAdESServiceSettings, ICertificateSource>>()(settings),
                              c.Resolve<Func<IOcspSource?, ICrlSource?, ICertificateStatusVerifier>>(),
                              (context) => c.Resolve<Func<IRuntimeValidatingParams, CertificateAndContext, CertificateToken>>()(runtimeValidatingParams, context))
                        ))
                .RegisterFactory<Func<IOcspSource, ICrlSource, ICertificateStatusVerifier>>(c =>
                    new Func<IOcspSource, ICrlSource, ICertificateStatusVerifier>((ocspVerifier, crlVerifier) => new OCSPAndCRLCertificateVerifier(new OCSPCertificateVerifier(ocspVerifier), new CRLCertificateVerifier(crlVerifier)))
                )
                .RegisterFactory<Func<IRuntimeValidatingParams, CertificateAndContext, CertificateToken>>(
                    c =>
                    new Func<IRuntimeValidatingParams, CertificateAndContext, CertificateToken>(
                        (runtimeValidatingParams, context) =>
                            new CertificateToken(context, c.Resolve<Func<IRuntimeValidatingParams, ICertificateSourceFactory>>()(runtimeValidatingParams))))

                ;
            #endregion
        }

        [SetUp]
        public void Setup()
        {
            fakeHttpDataLoader = new Mock<IHTTPDataLoader>();
            SetupSignerCert();
            SetupFakeHttpDataLoader();
        }

        private static FileSignatureState GetSignatureState(SignatureInformation info, SignatureProfile targetSignatureProfile)
        {
            if (info.CertPathRevocationAnalysis.Summary.IsInvalid)
            {
                return FileSignatureState.Failed;
            }

            switch (targetSignatureProfile)
            {
                case SignatureProfile.T:
                    if (!info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid)
                    {
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
                    if (!info.SignatureLevelAnalysis.LevelX.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelC.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid
                        || !(info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?.Any() ?? false))
                    {
                        return FileSignatureState.Failed;
                    }
                    break;

                case SignatureProfile.XType2:
                    if (!info.SignatureLevelAnalysis.LevelX.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelC.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid
                        || !(info.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification?.Any() ?? false))
                    {
                        return FileSignatureState.Failed;
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
                    if (!info.SignatureLevelAnalysis.LevelX.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelC.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid
                        || !(info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?.Any() ?? false))
                    {
                        return FileSignatureState.Failed;
                    }
                    break;

                case SignatureProfile.XLType2:
                    if (!info.SignatureLevelAnalysis.LevelX.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelC.LevelReached.IsValid
                        || !info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid
                        || !(info.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification?.Any() ?? false))
                    {
                        return FileSignatureState.Failed;
                    }
                    break;

                case SignatureProfile.A:
                    if (!info.SignatureLevelAnalysis.LevelA.LevelReached.IsValid)
                    {
                        return FileSignatureState.Failed;
                    }
                    var archiveTimestampsVerification = info.SignatureLevelAnalysis.LevelA.ArchiveTimestampsVerification;

                    if (archiveTimestampsVerification.Any(x => x.CertPathVerification.IsInvalid))
                    {
                        return FileSignatureState.Failed;
                    }
                    else if (archiveTimestampsVerification.Any(x => !x.CertPathVerification.IsValid))
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
                else if (signatureTimestampsVerification.Any(x => !x.CertPathVerification.IsValid))
                {
                    return FileSignatureState.CheckedWithWarning;
                }
            }

            return info.CertPathRevocationAnalysis.Summary.IsValid
                ? FileSignatureState.Checked
                : FileSignatureState.CheckedWithWarning;
        }

        private static SignatureProfile GetLevelReached(SignatureInformation info)
        {
            if (info is null)
            {
                return SignatureProfile.None;
            }

            if (info.SignatureLevelAnalysis.LevelA.LevelReached.IsValid)
            {
                return SignatureProfile.A;
            }

            if (info.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid)
            {
                if (info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?.Any() ?? false)
                {
                    return SignatureProfile.XLType1;
                }

                if (info.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification?.Any() ?? false)
                {
                    return SignatureProfile.XLType2;
                }

                return SignatureProfile.XL;
            }

            if (info.SignatureLevelAnalysis.LevelX.LevelReached.IsValid)
            {
                if (info.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification?.Any() ?? false)
                {
                    return SignatureProfile.XType1;
                }

                if (info.SignatureLevelAnalysis.LevelX.ReferencesTimestampsVerification?.Any() ?? false)
                {
                    return SignatureProfile.XType2;
                }
            }
            else if (info.SignatureLevelAnalysis.LevelC.LevelReached.IsValid)
            {
                return SignatureProfile.C;
            }
            else if (info.SignatureLevelAnalysis.LevelT.LevelReached.IsValid)
            {
                return SignatureProfile.T;
            }
            else if (info.SignatureLevelAnalysis.LevelEPES.LevelReached.IsValid)
            {
                return SignatureProfile.EPES;
            }
            else if (info.SignatureLevelAnalysis.LevelBES.LevelReached.IsValid)
            {
                return SignatureProfile.BES;
            }

            return SignatureProfile.None;
        }

        private (
                IDocument signedDocument,
                IDocument inputDocument,
                IDocumentSignatureService cadesService,
                ValidationReport validationReport)
            SomeSetupSigning(
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
            bool noNetworkForCrlAfterSigning = false


            )
        {
            var cadesService = container.Resolve<Func<ICAdESServiceSettings, IDocumentSignatureService>>()(cadesSettings);
            // to be signed
            var inputData = Encoding.UTF8.GetBytes("anydataanydataanydataanydataanydataanydataanydataanydata");
            var inputDocument = new InMemoryDocument(inputData);
            var signingTime = DateTime.Now;

            var parameters = new SignatureParameters
            {
                SigningCertificate = signerCert,
                CertificateChain = new X509Certificate[] { signerCert },
                SignaturePackaging = SignaturePackaging.DETACHED,
                SignatureProfile = signatureProfile,
                SigningDate = signingTime,
                DigestAlgorithmOID = DigestAlgorithm.SHA256.OID,
                EncriptionAlgorithmOID = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption.Id
            };
            var toBeSignedStream = cadesService.ToBeSigned(inputDocument, parameters);
            // sign
            ISigner signer = SignerUtilities.InitSigner(parameters.DigestWithEncriptionOID, true, signerKeyPair.Private, null);
            toBeSignedStream.Position = 0;
            toBeSignedStream.Seek(0, SeekOrigin.Begin);
            var b = Streams.ReadAll(toBeSignedStream);
            signer.BlockUpdate(b, 0, b.Length);
            var signatureValue = signer.GenerateSignature();

            SetupFakeHttpDataLoader(
                noNetwork: noNetworkBeforeSigning,
                signerRevoked: signerRevokedBeforeSigning,
                ocspRevoked: ocspRevokedBeforeSigning,
                intermediateRevoked: intermediateRevokedBeforeSigning,
                tspRevoked: tspRevokedBeforeSigning,
                noNetworkForTsp: noNetworkForTspBeforeSigning,
                noNetworkForInter: noNetworkForInterBeforeSigning,
                noNetworkForOcsp: noNetworkForOcspBeforeSigning,
                noNetworkForCrl: noNetworkForCrlBeforeSigning);

            // make pkcs7
            var (signedDocument, validationReport) = cadesService.GetSignedDocument(inputDocument, parameters, signatureValue);

            SetupFakeHttpDataLoader(
                noNetwork: noNetworkAfterSigning,
                signerRevoked: signerRevokedAfterSigning,
                ocspRevoked: ocspRevokedAfterSigning,
                intermediateRevoked: intermediateRevokedAfterSigning,
                tspRevoked: tspRevokedAfterSigning,
                noNetworkForTsp: noNetworkForTspAfterSigning,
                noNetworkForInter: noNetworkForInterAfterSigning,
                noNetworkForOcsp: noNetworkForOcspAfterSigning,
                noNetworkForCrl: noNetworkForCrlAfterSigning);

            return (signedDocument, inputDocument, cadesService, validationReport);
        }

        private void SetupFakeHttpDataLoader(
            bool noNetwork = false,
            bool signerRevoked = false,
            bool ocspRevoked = false,
            bool intermediateRevoked = false,
            bool tspRevoked = false,
            bool noNetworkForTsp = false,
            bool noNetworkForInter = false,
            bool noNetworkForOcsp = false,
            bool noNetworkForCrl = false)
        {

            container.RegisterFactory<Func<IRuntimeValidatingParams, IHTTPDataLoader>>(
                    c => new Func<IRuntimeValidatingParams, IHTTPDataLoader>(
                        (runtimeValidatingParams) =>
                        {
                            fakeHttpDataLoader.Setup(x => x.Post(It.IsAny<string>(), It.IsAny<Stream>())).Returns<string, Stream>((url, stream) =>
                            {
                                if (noNetwork)
                                {
                                    return null;
                                }

                                if (url == tspUrl)
                                {
                                    if (noNetworkForTsp)
                                    {
                                        return null;
                                    }

                                    var bytes = Streams.ReadAll(stream);
                                    var request = new TimeStampRequest(bytes);

                                    TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(tspKeyPair.Private, tspCert, TspAlgorithms.Sha256, "1.2");
                                    var certs = new ArrayList { tspCert };
                                    var certStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(certs));
                                    tsTokenGen.SetCertificates(certStore);

                                    TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

                                    TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

                                    return new MemoryStream(tsResp.GetEncoded());
                                }
                                else if (url == ocspUrl)
                                {
                                    if (noNetworkForOcsp)
                                    {
                                        return null;
                                    }

                                    var bytes = Streams.ReadAll(stream);
                                    var request = new OcspReq(bytes);

                                    BasicOcspRespGenerator generator = new BasicOcspRespGenerator(new RespID(ocspCert.SubjectDN));

                                    var certIDList = request.GetRequestList().Select(x => x.GetCertID());
                                    var status = GetRevokedStatus(
                                        certIDList,
                                        signerRevoked ?
                                            signerCert :
                                            intermediateRevoked ?
                                                 intermediateCert : tspRevoked ?
                                                    tspCert : null);

                                    var noncevalue = request.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce) as DerOctetString;
                                    if (noncevalue != null)
                                    {
                                        var oids = new List<DerObjectIdentifier> { OcspObjectIdentifiers.PkixOcspNonce };
                                        var values = new List<X509Extension> { new X509Extension(DerBoolean.False, noncevalue) };
                                        generator.SetResponseExtensions(new Org.BouncyCastle.Asn1.X509.X509Extensions(oids, values));
                                    }

                                    foreach (var req in certIDList)
                                    {
                                        generator.AddResponse(req, status);
                                    }

                                    BasicOcspResp basicOcspResp = generator.Generate(ocspCert.SigAlgOid, ocspKeyPair.Private, new X509Certificate[] { ocspCert, intermediateCert, caCert }, DateTime.UtcNow, null);
                                    var ocspResponseGenerator = new OCSPRespGenerator();
                                    var ocspResponse = ocspResponseGenerator.Generate(OCSPRespGenerator.Successful, basicOcspResp);

                                    return new MemoryStream(ocspResponse.GetEncoded());
                                }

                                return null;
                            });
                            fakeHttpDataLoader.Setup(x => x.Get(It.IsAny<string>())).Returns<string>((url) =>
                            {
                                if (noNetwork)
                                {
                                    return null;
                                }

                                if (runtimeValidatingParams.OfflineValidating)
                                {
                                    return null;
                                }
                                if (url == intermediateUrl)
                                {
                                    if (noNetworkForInter)
                                    {
                                        return null;
                                    }

                                    return new MemoryStream(intermediateCert.GetEncoded());
                                }
                                else if (url == caUrl)
                                {
                                    return new MemoryStream(caCert.GetEncoded());
                                }
                                else if (url == crlCaUrl || url == crlInterUrl)
                                {
                                    if (noNetworkForCrl)
                                    {
                                        return null;
                                    }

                                    var revokedSerialNumbers = new List<BigInteger>();
                                    if (signerRevoked)
                                    {
                                        revokedSerialNumbers.Add(signerCert.SerialNumber);
                                    }

                                    if (intermediateRevoked)
                                    {
                                        revokedSerialNumbers.Add(intermediateCert.SerialNumber);
                                    }

                                    if (ocspRevoked)
                                    {
                                        revokedSerialNumbers.Add(ocspCert.SerialNumber);
                                    }

                                    if (tspRevoked)
                                    {
                                        revokedSerialNumbers.Add(tspCert.SerialNumber);
                                    }

                                    if (url == crlCaUrl)
                                    {
                                        return new MemoryStream(GetX509Crl(caCert, caKeyPair, revokedSerialNumbers.ToArray()).GetEncoded());
                                    }
                                    else if (url == crlInterUrl)
                                    {
                                        return new MemoryStream(GetX509Crl(intermediateCert, intermediateKeyPair, revokedSerialNumbers.ToArray()).GetEncoded());
                                    }
                                }

                                return null;
                            });
                            return fakeHttpDataLoader.Object;
                        }));
        }

        private Org.BouncyCastle.Ocsp.CertificateStatus GetRevokedStatus(
            IEnumerable<CertificateID> certIDList,
            X509Certificate? cert) => cert != null && certIDList.Any(x => x.SerialNumber.Equals(cert.SerialNumber)) ?
                                         new RevokedStatus(new RevokedInfo(new DerGeneralizedTime(DateTime.UtcNow.AddDays(-1).ToZuluString()), new CrlReason(CrlReason.KeyCompromise)))
                                         : Org.BouncyCastle.Ocsp.CertificateStatus.Good;

        private X509Crl GetX509Crl(X509Certificate issuer, AsymmetricCipherKeyPair keyPair, params BigInteger[] revokedSerialNumbers)
        {
            var lastCRLNumber = BigInteger.One;
            var crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(issuer.SubjectDN);
            DateTime skewedNow = DateTime.UtcNow.AddHours(-1);
            crlGen.SetThisUpdate(skewedNow);
            crlGen.SetNextUpdate(skewedNow.AddHours(12));
            crlGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuer));
            crlGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.CrlNumber, false, new CrlNumber(lastCRLNumber));
            //crlGen.addCRL(previousCRL);
            foreach (var sn in revokedSerialNumbers)
            {
                crlGen.AddCrlEntry(sn, DateTime.Now.AddDays(-1), CrlReason.KeyCompromise);
            }

            return crlGen.Generate(new Asn1SignatureFactory(caCert.SigAlgOid, keyPair.Private, null));
        }

        private void SetupSignerCert(bool overdue = false)
        {
            var signerCertName = new X509Name("CN=signer_cert");
            signerKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            signerCert = CryptoHelpers.GenerateCertificate(
                intermediateCertName,
                signerCertName,
                intermediateKeyPair.Private,
                signerKeyPair.Public,
                notBefore: DateTime.Now.AddDays(-30),
                notAfter: DateTime.Now.AddDays(overdue ? -1 : 30),
                issuerUrls: new string[] { intermediateUrl },
                crlUrls: new string[] { crlInterUrl },
                ocspUrls: new string[] { ocspUrl });
        }
    }
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


}
