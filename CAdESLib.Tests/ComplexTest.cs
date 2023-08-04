using CAdESLib.Document;
using CAdESLib.Document.Signature;
using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using CAdESLib.Service;
using Moq;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Tls;
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
using System.ComponentModel;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Text;
using Unity;
using Unity.Lifetime;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Linq;
using Org.BouncyCastle.Cms;

namespace CAdESLib.Tests
{
    [TestFixture]
    public class ComplexTests
    {
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

            #region Certificates creation

            // CA
            var ca = new X509Name("CN=ca");
            var caKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            var caCert = CryptoHelpers.GenerateCertificate(ca, ca, caKeyPair.Private, caKeyPair.Public);

            // Intermediate
            var crlUrl = "http://crl";
            var caUrl = "http://ca";
            var intermediateCertName = new X509Name("CN=intermediate_cert");
            var intermediateKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            var intermediateCert = CryptoHelpers.GenerateCertificate(ca, intermediateCertName, caKeyPair.Private, intermediateKeyPair.Public, issuerUrls: new string[] { caUrl }, crlUrls: new string[] { crlUrl });

            // Signer
            var ocspUrl = "http://ocsp";
            var intermediateUrl = "http://intermediate";
            var signerCertName = new X509Name("CN=signer_cert");
            var signerKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            var signerCert = CryptoHelpers.GenerateCertificate(intermediateCertName, signerCertName, intermediateKeyPair.Private, signerKeyPair.Public, issuerUrls: new string[] { intermediateUrl }, crlUrls: new string[] { crlUrl }, ocspUrls: new string[] { ocspUrl });

            // OCSP
            var ocspCertName = new X509Name("CN=ocsp_cert");
            var ocspKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            var ocspCert = CryptoHelpers.GenerateCertificate(intermediateCertName, ocspCertName, intermediateKeyPair.Private, ocspKeyPair.Public, issuerUrls: new string[] { intermediateUrl }, crlUrls: new string[] { crlUrl }, ocsp: true);

            // TSP
            var tspUrl = "http://tsp";
            var tspCertName = new X509Name("CN=tsp_cert");
            var tspKeyPair = CryptoHelpers.GenerateRsaKeyPair(2048);
            var tspCert = CryptoHelpers.GenerateCertificate(intermediateCertName, tspCertName, intermediateKeyPair.Private, tspKeyPair.Public, issuerUrls: new string[] { intermediateUrl }, crlUrls: new string[] { crlUrl }, ocspUrls: new string[] { ocspUrl }, tsp: true);

            // CRL
            var lastCRLNumber = BigInteger.One;
            var crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(caCert.SubjectDN);
            DateTime skewedNow = DateTime.UtcNow.AddHours(-1);
            crlGen.SetThisUpdate(skewedNow);
            crlGen.SetNextUpdate(skewedNow.AddHours(12));
            //crlGen.SetSignatureAlgorithm(SignatureAlgorithm.SHA256withRSA.jcaString());
            crlGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
            crlGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.CrlNumber, false, new CrlNumber(lastCRLNumber));
            //crlGen.addCRL(previousCRL);
            //crlGen.addCRLEntry(revokedCertificate.getSerialNumber(), skewedNow.toDate(), reason.reason());
            var crl = crlGen.Generate(new Asn1SignatureFactory(caCert.SigAlgOid, caKeyPair.Private, null));

            #endregion

            var fakeHttpDataLoader = new Mock<IHTTPDataLoader>();
            fakeHttpDataLoader.Setup(x => x.Post(It.IsAny<string>(), It.IsAny<Stream>())).Returns<string, Stream>((url, stream) =>
            {
                if (url == tspUrl)
                {
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
                    var bytes = Streams.ReadAll(stream);
                    var request = new OcspReq(bytes);

                    BasicOcspRespGenerator generator = new BasicOcspRespGenerator(new RespID(ocspCert.SubjectDN));



                    //Org.BouncyCastle.Ocsp.CertificateStatus status = new UnknownStatus();
                    var status = Org.BouncyCastle.Ocsp.CertificateStatus.Good;
                    // 0 - Unspecified
                    //status = new Org.BouncyCastle.Ocsp.RevokedStatus(DateTime.UtcNow, 0);
                    var noncevalue = request.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce) as DerOctetString;
                    if (noncevalue != null)
                    {
                        var oids = new List<DerObjectIdentifier> { OcspObjectIdentifiers.PkixOcspNonce };
                        var values = new List<Org.BouncyCastle.Asn1.X509.X509Extension> { new Org.BouncyCastle.Asn1.X509.X509Extension(DerBoolean.False, noncevalue) };
                        generator.SetResponseExtensions(new Org.BouncyCastle.Asn1.X509.X509Extensions(oids, values));
                    }

                    foreach (var req in request.GetRequestList())
                    {
                        generator.AddResponse(req.GetCertID(), status);
                    }

                    BasicOcspResp basicOcspResp = generator.Generate(ocspCert.SigAlgOid, ocspKeyPair.Private, new X509Certificate[] { ocspCert }, DateTime.UtcNow, null);
                    var ocspResponseGenerator = new OCSPRespGenerator();
                    var ocspResponse = ocspResponseGenerator.Generate(OCSPRespGenerator.Successful, basicOcspResp);

                    return new MemoryStream(ocspResponse.GetEncoded());
                }

                return null;
            });
            fakeHttpDataLoader.Setup(x => x.Get(It.IsAny<string>())).Returns<string>((url) =>
            {
                if (url == intermediateUrl)
                {
                    return new MemoryStream(intermediateCert.GetEncoded());
                }
                else if (url == caUrl)
                {
                    return new MemoryStream(caCert.GetEncoded());
                }
                else if (crlOnline && url == crlUrl)
                {
                    return new MemoryStream(crl.GetEncoded());
                }

                return null;
            });

            #region Container init
            var container = new UnityContainer();
            container

                // CAdESLib usage

                .RegisterFactory<Func<ICAdESServiceSettings, IDocumentSignatureService>>(c => new Func<ICAdESServiceSettings, IDocumentSignatureService>(
                    (settings) => new CAdESService(
                        c.Resolve<Func<ICAdESServiceSettings, ITspSource>>()(settings),
                        c.Resolve<Func<ICAdESServiceSettings, ICertificateVerifier>>()(settings),
                        c.Resolve<Func<ICAdESServiceSettings, ISignedDocumentValidator>>()(settings))
                    ))


                .RegisterFactory<Func<ICAdESServiceSettings, ICertificateVerifier>>(c => new Func<ICAdESServiceSettings, ICertificateVerifier>((settings) =>
                    new TrustedListCertificateVerifier(
                        c.Resolve<Func<ICAdESServiceSettings, Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext>>>()(settings))))

                .RegisterFactory<Func<ICAdESServiceSettings, ISignedDocumentValidator>>(c => new Func<ICAdESServiceSettings, ISignedDocumentValidator>((settings) =>
                    new SignedDocumentValidator(
                        c.Resolve<Func<ICAdESServiceSettings, ICertificateVerifier>>()(settings),
                        c.Resolve<Func<ICAdESLogger>>(),
                        c.Resolve<Func<ICAdESServiceSettings,
                        Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext>>>()(settings))))


                .RegisterType<ICAdESLogger, CAdESLogger>(new TransientLifetimeManager())

                .RegisterFactory<Func<ICAdESServiceSettings, ITspSource>>(c => new Func<ICAdESServiceSettings, ITspSource>((settings) => new OnlineTspSource(settings, () => c.Resolve<IHTTPDataLoader>())))

                .RegisterFactory<Func<ICAdESServiceSettings, IOcspSource>>(c => new Func<ICAdESServiceSettings, IOcspSource>((settings) => new OnlineOcspSource(settings, () => c.Resolve<IHTTPDataLoader>())))

                .RegisterFactory<Func<ICAdESServiceSettings, ICrlSource>>(c => new Func<ICAdESServiceSettings, ICrlSource>((settings) => new OnlineCrlSource(settings, () => c.Resolve<IHTTPDataLoader>())))

                .RegisterFactory<Func<ICAdESServiceSettings, ICertificateSource>>(c => new Func<ICAdESServiceSettings, ICertificateSource>((settings) => new ListCertificateSourceWithSetttings(settings)))

                .RegisterInstance<IHTTPDataLoader>(fakeHttpDataLoader.Object)

                .RegisterType<ICertificateSourceFactory, AIACertificateFactoryImpl>(new TransientLifetimeManager())

                .RegisterFactory<Func<ICAdESServiceSettings, Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext>>>(c => new Func<ICAdESServiceSettings, Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext>>(
                  (settings) => (cert, date, logger) => new ValidationContext(
                      cert,
                      date,
                      logger,
                      c.Resolve<Func<ICAdESServiceSettings, IOcspSource>>()(settings),
                      c.Resolve<Func<ICAdESServiceSettings, ICrlSource>>()(settings),
                      c.Resolve<Func<ICAdESServiceSettings, ICertificateSource>>()(settings),
                      c.Resolve<Func<IOcspSource, ICrlSource, ICertificateStatusVerifier>>(), c.Resolve<Func<CertificateAndContext, CertificateToken>>()))
                )
                .RegisterFactory<Func<IOcspSource, ICrlSource, ICertificateStatusVerifier>>(c =>
                    new Func<IOcspSource, ICrlSource, ICertificateStatusVerifier>((ocspVerifier, crlVerifier) => new OCSPAndCRLCertificateVerifier(new OCSPCertificateVerifier(ocspVerifier), new CRLCertificateVerifier(crlVerifier)))
                )
                .RegisterFactory<Func<CertificateAndContext, CertificateToken>>(c =>
                    new Func<CertificateAndContext, CertificateToken>((context) => new CertificateToken(context, c.Resolve<ICertificateSourceFactory>()))
                )

                ;
            #endregion

            var cadesSettings = new CAdESServiceSettings
            {
                TspSource = tspUrl,
                TrustedCerts = new List<X509Certificate> { caCert }
            };

            if (!crlOnline)
            {
                if (cadesSettings.Crls == null)
                {
                    cadesSettings.Crls = new List<X509Crl>();
                }

                cadesSettings.Crls.Add(crl);
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
                SignatureProfile = SignatureProfile.XLType1,
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
            var signedDocument = cadesService.GetSignedDocument(inputDocument, parameters, signatureValue);

            Action callsChecker = () =>
            {
                // tsp - 2, ocsp - 2
                fakeHttpDataLoader.Verify(x => x.Post(It.IsAny<string>(), It.IsAny<Stream>()), Times.Exactly(4));
                // intermediate - 1, crl - 1 if crlOnline else 0, ca - 0 (it is present because of a trusted list)
                fakeHttpDataLoader.Verify(x => x.Get(It.IsAny<string>()), Times.Exactly(crlOnline ? 2 : 1));
            };

            callsChecker();

            // validate
            cadesService = container.Resolve<Func<ICAdESServiceSettings, IDocumentSignatureService>>()(cadesSettings);
            var report = cadesService.ValidateDocument(signedDocument, true, inputDocument);
            var sigInfo = report.SignatureInformationList[0];

            // No new calls, so there was a validation without network access
            callsChecker();

            // XLT1 level is reached and it is a solid one
            Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelXL.LevelReached.IsValid);
            Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.All(x => x.SameDigest.IsValid), "XType1 timestamps are not valid");
            Assert.IsTrue(sigInfo.SignatureLevelAnalysis.LevelX.SignatureAndRefsTimestampsVerification.All(x => x.CertPathVerification.IsValid), "XType1 cert paths are not valid");

            var cms = new CmsSignedData(Streams.ReadAll(signedDocument.OpenStream()));
            var signers = cms.GetSignerInfos().GetSigners().GetEnumerator();
            signers.MoveNext();
            var signerInformation = (SignerInformation) signers.Current;

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
            var timestamp = signerInformation.GetSignatureTimestamps().First();
            var tspUnsignedAttributes = timestamp.GetTimeStamp().UnsignedAttributes;
            refsValsChecker("tsp", timestamp.GetSigner(), tspUnsignedAttributes);
        }
    }
}
