using CAdESLib.Document.Signature.Extensions;
using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using CAdESLib.Service;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using AttributeTable = Org.BouncyCastle.Asn1.Cms.AttributeTable;
using ContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;
using IssuerAndSerialNumber = Org.BouncyCastle.Asn1.Cms.IssuerAndSerialNumber;
using SignedData = Org.BouncyCastle.Asn1.Cms.SignedData;
using SignerInfo = Org.BouncyCastle.Asn1.Cms.SignerInfo;

namespace CAdESLib.Document.Signature
{
    public class CAdESService : IDocumentSignatureService
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();
        private readonly RuntimeValidatingParams runtimeValidatingParams;
        private readonly ITspSource tspSource;
        private readonly ICertificateVerifier verifier;
        private readonly ISignedDocumentValidator validator;
        private readonly ICryptographicProvider cryptographicProvider;
        private readonly ICurrentTimeGetter currentTimeGetter;

        private void PrintMetaInfo()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            FileVersionInfo fileVersionInfo = FileVersionInfo.GetVersionInfo(assembly.Location);
            FileInfo fInfo = new System.IO.FileInfo(assembly.Location);

            nloglogger.Trace($"FileVersion: {fileVersionInfo.FileVersion}, LastWriteTimeUtc: {fInfo.LastWriteTimeUtc}");
        }

        public CAdESService(
            Func<IRuntimeValidatingParams, ITspSource> tspSourceFunc,
            Func<IRuntimeValidatingParams, ICertificateVerifier> verifierFunc,
            Func<IRuntimeValidatingParams, ISignedDocumentValidator> validatorFunc,
            ICryptographicProvider cryptographicProvider,
            ICurrentTimeGetter currentTimeGetter)
        {
            this.runtimeValidatingParams = new RuntimeValidatingParams();
            this.tspSource = tspSourceFunc(this.runtimeValidatingParams);
            this.verifier = verifierFunc(this.runtimeValidatingParams);
            this.validator = validatorFunc(this.runtimeValidatingParams);
            this.cryptographicProvider = cryptographicProvider;
            this.currentTimeGetter = currentTimeGetter;
        }

        private CAdESSignatureExtension? GetExtensionProfile(SignatureParameters parameters)
        {
            SignatureProfile signFormat = parameters.SignatureProfile;
            if (signFormat == SignatureProfile.BES || signFormat == SignatureProfile.EPES)
            {
                return null;
            }
            else if (signFormat == SignatureProfile.T)
            {
                CAdESProfileT extensionT = new CAdESProfileT(tspSource, this.cryptographicProvider, this.currentTimeGetter);
                return extensionT;
            }
            else if (signFormat == SignatureProfile.C)
            {
                CAdESProfileC extensionC = new CAdESProfileC(tspSource, verifier, this.cryptographicProvider, this.currentTimeGetter);
                return extensionC;
            }
            else if (signFormat == SignatureProfile.XType1 || signFormat == SignatureProfile.XType2)
            {
                CAdESProfileX extensionX = new CAdESProfileX(tspSource, verifier, this.cryptographicProvider, this.currentTimeGetter);
                extensionX.SetExtendedValidationType(signFormat == SignatureProfile.XType1 ? 1 : 2);
                return extensionX;
            }

            if (signFormat == SignatureProfile.XL || signFormat == SignatureProfile.XLType1 || signFormat == SignatureProfile.XLType2)
            {
                return GetXLExtension(signFormat);
            }
            else if (signFormat == SignatureProfile.A)
            {
                CAdESProfileA extensionA = new CAdESProfileA(tspSource, validator, GetXLExtension(SignatureProfile.XLType1), this.cryptographicProvider, this.currentTimeGetter);
                return extensionA;
            }

            throw new ArgumentException("Unsupported signature format " + parameters.SignatureProfile);
        }

        private CAdESProfileXL GetXLExtension(SignatureProfile signFormat)
        {
            CAdESProfileXL extensionXL = new CAdESProfileXL(tspSource, verifier, this.cryptographicProvider, this.currentTimeGetter);
            extensionXL.SetExtendedValidationType(signFormat == SignatureProfile.XL ? 0 : signFormat == SignatureProfile.XLType1 ? 1 : 2);
            return extensionXL;
        }



        public virtual (IDocument, ValidationReport) ExtendDocument(
            IDocument signedDocument,
            IDocument? originalDocument,
            SignatureParameters parameters)
        {
            PrintMetaInfo();
            nloglogger.Info($"");
            nloglogger.Info($"---ExtendDocument---");
            nloglogger.Info($"");
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            CAdESSignatureExtension? extension = GetExtensionProfile(parameters);
            ValidationReport? validationReport = null;
            IDocument result = signedDocument;
            ICollection<IValidationContext?>? validationContexts;

            (result, validationContexts) = extension?.ExtendSignatures(signedDocument, this.currentTimeGetter.CurrentUtcTime, originalDocument, parameters) ?? (signedDocument, null);

            if (validationContexts != null && !validationContexts.All(x => x is null))
            {
                runtimeValidatingParams.OfflineValidating = true;
            }
            try
            {
                nloglogger.Trace("ExtendDocument validation");
                validationReport = this.ValidateDocument(result, false, externalContent: originalDocument, validationContexts: validationContexts);
            }
            finally
            {
                runtimeValidatingParams.OfflineValidating = false;
            }

            return (result, validationReport);
        }

        /// <inheritdoc/>
        public ValidationReport ValidateDocument(
                IDocument document,
                bool checkIntegrity,
                IDocument? externalContent = null,
                ICollection<IValidationContext?>? validationContexts = null,
                bool strictValidation = false)
        {
            PrintMetaInfo();
            nloglogger.Info($"");
            nloglogger.Info($"---ValidateDocument---");
            nloglogger.Info($"");
            if (strictValidation)
            {
                runtimeValidatingParams.OfflineValidating = true;
            }

            try
            {
                return validator.ValidateDocument(document, checkIntegrity, externalContent, validationContexts, runtimeValidatingParams);
            }
            finally
            {
                runtimeValidatingParams.OfflineValidating = false;
            }
        }

        public Stream ToBeSigned(IDocument document, SignatureParameters parameters)
        {
            PrintMetaInfo();
            nloglogger.Info($"");
            nloglogger.Info($"---ToBeSigned---");
            nloglogger.Info($"");
            if (document is null)
            {
                throw new ArgumentNullException(nameof(document));
            }
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (parameters.SignaturePackaging != SignaturePackaging.ENVELOPING && parameters.SignaturePackaging != SignaturePackaging.DETACHED)
            {
                throw new ArgumentException("Unsupported signature packaging " + parameters.SignaturePackaging);
            }

            byte[] toBeSigned = Streams.ReadAll(document.OpenStream());
            CmsProcessableByteArray content = new CmsProcessableByteArray(toBeSigned);
            bool includeContent = true;
            if (parameters.SignaturePackaging == SignaturePackaging.DETACHED)
            {
                includeContent = false;
            }
            CmsSignedData signed = CreateCMSSignedDataGenerator(parameters, GetSigningProfile(parameters), false, null).Generate(content, includeContent);

            var si = signed.GetSignerInfos().GetSigners().OfType<SignerInformation>().FirstOrDefault();
            if (si is null)
            {
                throw new ArgumentException("Failed signing");
            }

            return new MemoryStream(si.GetEncodedSignedAttributes());
        }

        public Stream ToBeSignedWithHash(IDocument hash, SignatureParameters parameters)
        {
            PrintMetaInfo();
            nloglogger.Info($"");
            nloglogger.Info($"---ToBeSignedWithHash---");
            nloglogger.Info($"");
            if (hash is null)
            {
                throw new ArgumentNullException(nameof(hash));
            }
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (parameters.SignaturePackaging != SignaturePackaging.ENVELOPING && parameters.SignaturePackaging != SignaturePackaging.DETACHED)
            {
                throw new ArgumentException("Unsupported signature packaging " + parameters.SignaturePackaging);
            }

            byte[] digest = Streams.ReadAll(hash.OpenStream());
            var cadesProfile = GetSigningProfile(parameters);
            CmsAttributeTableGenerator signedAttrGen = new DefaultSignedAttributeTableGenerator(
                    new AttributeTable(cadesProfile.GetSignedAttributes(parameters) as System.Collections.IDictionary));
            var dict = (cadesProfile.GetSignedAttributes(parameters) as System.Collections.IDictionary)!;
            dict[CmsAttributeTableParameter.ContentType] = PkcsObjectIdentifiers.Data;
            dict[CmsAttributeTableParameter.Digest] = digest;

            return new MemoryStream(new Org.BouncyCastle.Asn1.DerSet(signedAttrGen.GetAttributes(dict).ToAsn1EncodableVector()).GetDerEncoded());
        }

        public (IDocument, ValidationReport) GetSignedDocument(IDocument document, SignatureParameters parameters, byte[] signatureValue)
        {
            PrintMetaInfo();
            nloglogger.Info($"");
            nloglogger.Info($"---GetSignedDocument---");
            nloglogger.Info($"");
            if (document is null)
            {
                throw new ArgumentNullException(nameof(document));
            }
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (parameters.SignaturePackaging
                != SignaturePackaging.ENVELOPING && parameters.SignaturePackaging != SignaturePackaging.DETACHED)
            {
                throw new ArgumentException("Unsupported signature packaging " + parameters.SignaturePackaging);
            }
            byte[] toBeSigned = Streams.ReadAll(document.OpenStream());
            CmsProcessableByteArray content = new CmsProcessableByteArray(toBeSigned);
            bool includeContent = parameters.SignaturePackaging != SignaturePackaging.DETACHED;
            CmsSignedData data = CreateCMSSignedDataGenerator(
                    parameters,
                    GetSigningProfile(parameters),
                    parameters.SignatureProfile != SignatureProfile.BES,
                    null,
                    signatureValue).Generate(content, includeContent);
            IDocument signedDocument = new CMSSignedDocument(data);

            var (result, validationReport) = this.ExtendDocument(signedDocument, document, parameters);

            return (result, validationReport);
        }

        public (IDocument, ValidationReport) GetSignedDocumentWithSignedAttributes(
                IDocument signedAttributes,
                SignatureParameters parameters,
                byte[] signatureValue)
        {
            nloglogger.Info($"");
            nloglogger.Info($"---GetSignedDocumentWithSignedAttributes---");
            nloglogger.Info($"");
            PrintMetaInfo();
            if (signedAttributes is null)
            {
                throw new ArgumentNullException(nameof(signedAttributes));
            }
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (parameters.SignaturePackaging
                != SignaturePackaging.ENVELOPING && parameters.SignaturePackaging != SignaturePackaging.DETACHED)
            {
                throw new ArgumentException("Unsupported signature packaging " + parameters.SignaturePackaging);
            }

            var contentTypeOid = new DerObjectIdentifier(CmsObjectIdentifiers.Data.Id);
            Asn1OctetString? octs = null;
            Asn1Set? certrevlist = null;
            Asn1Set? unsignedAttr = null;
            ContentInfo encInfo = new ContentInfo(contentTypeOid, octs);
            Asn1EncodableVector digestAlgs = new Asn1EncodableVector();
            var digestAlgorithmId = new AlgorithmIdentifier(new DerObjectIdentifier(parameters.DigestAlgorithmOID), DerNull.Instance);
            digestAlgs.Add(digestAlgorithmId);
            Asn1Set? certificates = null;
            var signingCertificate = parameters.SigningCertificate!;

            var certs = new List<X509Certificate> { signingCertificate };
            if (parameters.CertificateChain != null)
            {
                foreach (X509Certificate c in parameters.CertificateChain)
                {
                    if (!c.SubjectDN.Equals(signingCertificate.SubjectDN))
                    {
                        certs.Add(c);
                    }
                }
            }

            if (certs.Count != 0)
            {
                Asn1EncodableVector v = new Asn1EncodableVector();
                foreach (X509Certificate c in certs)
                {
                    v.Add(X509CertificateStructure.GetInstance(
                        Asn1Object.FromByteArray(c.GetEncoded())));
                }
                certificates = new DerSet(v);
            }

            Asn1EncodableVector signerInfos = new Asn1EncodableVector();
            SignerIdentifier signerIdentifier = new SignerIdentifier(
                    new IssuerAndSerialNumber(signingCertificate.IssuerDN, new DerInteger(signingCertificate.SerialNumber)));
            var signatureName = parameters.SignatureName;
            var encAlgId = new DefaultSignatureAlgorithmIdentifierFinder().Find(signatureName).Algorithm;

            Asn1Set signedAttr = Asn1Set.GetInstance(Streams.ReadAll(signedAttributes.OpenStream()));

            signerInfos.Add(new SignerInfo(
                        signerIdentifier,
                        new AlgorithmIdentifier(new DerObjectIdentifier(parameters.DigestAlgorithmOID), DerNull.Instance),
                         signedAttr,
                         new AlgorithmIdentifier(encAlgId, DerNull.Instance),
                         new DerOctetString(signatureValue),
                         unsignedAttr
                        ));

            SignedData sd = new SignedData(
                 new DerSet(digestAlgs),
                 encInfo,
                 certificates,
                 certrevlist,
                 new DerSet(signerInfos));

            ContentInfo contentInfo = new ContentInfo(CmsObjectIdentifiers.SignedData, sd);

            CmsProcessable? content = null;
            var data = new CmsSignedData(content, contentInfo);

            IDocument signedDocument = new CMSSignedDocument(data);

            var (result, validationReport) = this.ExtendDocument(signedDocument, null, parameters);

            return (result, validationReport);
        }

        /// <summary>
        /// Because some information are stored in the profile, a profile is not Thread-safe.
        /// </summary>
        /// <remarks>
        /// Because some information are stored in the profile, a profile is not Thread-safe. The software must create one
        /// for each request.
        /// </remarks>
        /// <returns>A new instance of signatureProfile corresponding to the parameters.</returns>
        private CAdESProfileBES GetSigningProfile(SignatureParameters parameters)
        {
            var signFormat = parameters.SignatureProfile;
            if (signFormat.Equals(SignatureProfile.BES))
            {
                return new CAdESProfileBES(this.cryptographicProvider);
            }

            return new CAdESProfileEPES(this.cryptographicProvider);
        }

        private CmsSignedDataGenerator CreateCMSSignedDataGenerator(
                SignatureParameters parameters,
                CAdESProfileBES cadesProfile,
                bool includeUnsignedAttributes = true,
                CmsSignedData? originalSignedData = null,
                byte[]? signature = null)
        {
            var signerCertificate = parameters.SigningCertificate;
            if (signerCertificate is null)
            {
                throw new ArgumentException(nameof(signerCertificate));
            }

            var generator = new CmsSignedDataGenerator();

            var signedAttrGen = new DefaultSignedAttributeTableGenerator(
                    new AttributeTable(cadesProfile.GetSignedAttributes(parameters) as System.Collections.IDictionary));
            var unsignedAttrGen = new SimpleAttributeTableGenerator(
                    includeUnsignedAttributes ? new AttributeTable(cadesProfile.GetUnsignedAttributes(parameters) as System.Collections.IDictionary) : null);

            var builder = new SignerInfoGeneratorBuilder().WithSignedAttributeGenerator(signedAttrGen).WithUnsignedAttributeGenerator(unsignedAttrGen);
            generator.AddSignerInfoGenerator(
                    builder.Build(
                        new ReadySignatureFactory(
                            new PreComputedSigner(signature ?? Array.Empty<byte>()),
                            parameters.DigestWithEncriptionOID),
                        signerCertificate));

            if (originalSignedData != null)
            {
                generator.AddSigners(originalSignedData.GetSignerInfos());
            }
            var certs = new List<X509Certificate>
                {
                    signerCertificate
                };
            if (parameters.CertificateChain != null)
            {
                foreach (X509Certificate c in parameters.CertificateChain)
                {
                    if (!c.SubjectDN.Equals(signerCertificate.SubjectDN))
                    {
                        certs.Add(c);
                    }
                }
            }
            IX509Store certStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(certs));
            generator.AddCertificates(certStore);
            if (originalSignedData != null)
            {
                generator.AddCertificates(originalSignedData.GetCertificates("Collection"));
            }
            return generator;

        }
    }

    public class PreComputedSigner : ISigner
    {
        private byte[] preComputedSignature { get; set; }
        private readonly IDigest digest;
        private byte[]? currentSignature;

        /// <param name="preComputedSignature">the preComputedSignature to set</param>
        public PreComputedSigner(byte[] preComputedSignature)
        {
            this.preComputedSignature = preComputedSignature;
            digest = new NullDigest();
        }

        /// <summary>The default constructor for PreComputedSigner.</summary>
        /// <remarks>The default constructor for PreComputedSigner.</remarks>
        /// <param name="algorithmName"></param>
        public PreComputedSigner()
            : this(Array.Empty<byte>())
        {
        }

        public string AlgorithmName => "NONE";

        public void Init(bool forSigning, ICipherParameters parameters)
        {
            Reset();
        }

        public void Update(byte input)
        {
            digest.Update(input);
        }

        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            digest.BlockUpdate(input, inOff, length);
        }

        public byte[] GenerateSignature()
        {
            if (preComputedSignature?.Length > 0)
            {
                currentSignature = preComputedSignature;
                return preComputedSignature;
            }
            else
            {
                byte[] hash = new byte[digest.GetDigestSize()];
                digest.DoFinal(hash, 0);
                currentSignature = hash;
                return currentSignature;
            }
        }

        public byte[]? CurrentSignature()
        {
            return currentSignature;
        }

        public bool VerifySignature(byte[] signature)
        {
            throw new System.NotImplementedException();
        }

        public void Reset()
        {
            currentSignature = null;
            digest.Reset();
        }
    }

    class ReadySignatureFactory : ISignatureFactory
    {
        private readonly ISigner signer;
        private readonly Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier algID;

        public Object AlgorithmDetails
        {
            get { return this.algID; }
        }

        public ReadySignatureFactory(ISigner signer, string digestOID)
        {
            this.signer = signer;
            this.algID = new AlgorithmIdentifier(new DerObjectIdentifier(digestOID), DerNull.Instance);
        }

        public IStreamCalculator CreateCalculator()
        {
            return new StreamCalculator(signer);
        }
    }

    class StreamCalculator : IStreamCalculator, IDisposable
    {
        private readonly SignerSink mSignerSink;

        public StreamCalculator(ISigner signer)
        {
            this.mSignerSink = new SignerSink(signer);
        }

        public Stream Stream
        {
            get { return mSignerSink; }
        }

        public object GetResult()
        {
            return new DefaultSignatureResult(mSignerSink.Signer);
        }

        public void Dispose()
        {
            this.mSignerSink?.Dispose();
        }


    }
}
