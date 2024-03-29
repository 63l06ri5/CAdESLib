﻿using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using CAdESLib.Service;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
#pragma warning disable 618

namespace CAdESLib.Tests
{
    class CryptoHelpers
    {
        private static readonly SecureRandom secureRandom = new SecureRandom();

        public static AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
        {
            KeyGenerationParameters keygenParam = new KeyGenerationParameters(secureRandom, length);

            RsaKeyPairGenerator keyGenerator = new RsaKeyPairGenerator();
            keyGenerator.Init(keygenParam);
            return keyGenerator.GenerateKeyPair();
        }

        public static X509Certificate GenerateCertificate(
            X509Name issuer,
            X509Name subject,
            AsymmetricKeyParameter issuerPrivate,
            AsymmetricKeyParameter subjectPublic,
            DateTime? notBefore = null,
            DateTime? notAfter = null,
            bool ocsp = false,
            bool tsp = false,
            string[]? issuerUrls = null,
            string[]? ocspUrls = null,
            string[]? crlUrls = null)
        {
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(
                    PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(),
                    issuerPrivate);

            X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetIssuerDN(issuer);
            certGenerator.SetSubjectDN(subject);
            certGenerator.SetSerialNumber(BigInteger.ValueOf(Math.Abs(secureRandom.NextInt())));
            certGenerator.SetNotAfter(notAfter ?? DateTime.UtcNow.AddDays(1));
            certGenerator.SetNotBefore(notBefore ?? DateTime.UtcNow.AddDays(-1));
            certGenerator.SetPublicKey(subjectPublic);

            // Authority Information Access
            var aiaAsn = new Asn1EncodableVector();

            Action<string[]?, DerObjectIdentifier> aiaFunc = (string[]? urls, DerObjectIdentifier identifier) =>
            {
                if (urls != null && urls.Length > 0)
                {
                    foreach (var item in urls)
                    {
                        AccessDescription caIssuersAsn = new AccessDescription(
                            identifier, new GeneralName(
                                GeneralName.UniformResourceIdentifier,
                                new DerIA5String(item)
                            )
                        );
                        aiaAsn.Add(caIssuersAsn);
                    }
                }
            };

            aiaFunc(issuerUrls, AccessDescription.IdADCAIssuers);
            aiaFunc(ocspUrls, AccessDescription.IdADOcsp);

            if (aiaAsn.Count > 0)
            {
                certGenerator.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.AuthorityInfoAccess, false, new DerSequence(aiaAsn));
            }

            // CrlDistributionPoints
            if (crlUrls != null && crlUrls.Length > 0)
            {
                var cdps = new List<DistributionPoint>(crlUrls.Length);
                foreach (string crlUrl in crlUrls)
                {
                    var uriGeneralName = new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl);
                    var cdpName = new DistributionPointName(DistributionPointName.FullName, uriGeneralName);
                    var cdp = new DistributionPoint(cdpName, null, null);
                    cdps.Add(cdp);
                }
                certGenerator.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.CrlDistributionPoints, false, new CrlDistPoint(cdps.ToArray()));
            }

            certGenerator.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign));

            var keySupposedIds = new List<KeyPurposeID>();
            if (tsp)
            {
                keySupposedIds.Add(KeyPurposeID.IdKPTimeStamping);
            }

            if (ocsp)
            {
                keySupposedIds.Add(KeyPurposeID.IdKPOcspSigning);
            }
            certGenerator.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(keySupposedIds));
            if (ocsp)
            {
                certGenerator.AddExtension(X509Consts.OCSPNoCheck, false, new DerInteger(BigInteger.ValueOf(0x0500)));
            }
            return certGenerator.Generate(signatureFactory);
        }

        public static bool ValidateSignedCert(X509Certificate cert, ICipherParameters pubKey)
        {
            cert.CheckValidity(DateTime.UtcNow);
            byte[] tbsCert = cert.GetTbsCertificate();
            byte[] sig = cert.GetSignature();

            ISigner signer = SignerUtilities.GetSigner(cert.SigAlgName);
            signer.Init(false, pubKey);
            signer.BlockUpdate(tbsCert, 0, tbsCert.Length);
            return signer.VerifySignature(sig);
        }
    }

    class FakeOnlineTspSource : ITspSource
    {
        private readonly AsymmetricCipherKeyPair keyPair;
        private readonly X509Certificate cert;

        public FakeOnlineTspSource(X509Certificate cert, AsymmetricCipherKeyPair keyPair)
        {
            this.keyPair = keyPair;
            this.cert = cert;
        }

        public string TsaURL => throw new NotImplementedException();

        public string TsaUsername => throw new NotImplementedException();

        public string TsaPassword => throw new NotImplementedException();

        public string TsaDigestAlgorithmOID => DigestAlgorithms.GetAllowedDigests(DEFAULTHASHALGORITHM)!;

        public const string DEFAULTHASHALGORITHM = "SHA-256";

        public IDigest GetMessageDigest()
        {
            return DigestAlgorithms.GetMessageDigest(DEFAULTHASHALGORITHM);
        }

        public TimeStampResponse GetTimeStampResponse(string digestAlgorithmOid, byte[] digest)
        {
            TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
            tsqGenerator.SetCertReq(true);
            // tsqGenerator.setReqPolicy("1.3.6.1.4.1.601.10.3.1");
            BigInteger nonce = BigInteger.ValueOf(DateTime.UtcNow.Ticks + Environment.TickCount);
            TimeStampRequest request = tsqGenerator.Generate(digestAlgorithmOid, digest, nonce);


            TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(keyPair.Private, cert, TspAlgorithms.Sha256, "1.2");
            var certs = new ArrayList
                {
                    cert
                };
            var certStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(certs));
            tsTokenGen.SetCertificates(certStore);

            //TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
            //TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

            TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

            TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

            tsResp = new TimeStampResponse(tsResp.GetEncoded());

            return tsResp;
        }

        public byte[] GetTimeStampToken(byte[] imprint)
        {
            throw new NotImplementedException();
        }

        public int GetTokenSizeEstimate()
        {
            throw new NotImplementedException();
        }
    }

    class FakeOnlineOcspSource : IOcspSource
    {
        private readonly AsymmetricCipherKeyPair keyPair;
        private readonly X509Certificate cert;
        private readonly List<(X509Certificate, X509Certificate)> notRevoked = new List<(X509Certificate, X509Certificate)>();
        private readonly List<(X509Certificate, X509Certificate)> revoked = new List<(X509Certificate, X509Certificate)>();

        public FakeOnlineOcspSource(X509Certificate cert, AsymmetricCipherKeyPair keyPair)
        {
            this.keyPair = keyPair;
            this.cert = cert;
        }

        public BasicOcspResp GetOcspResponse(X509Certificate certificate, X509Certificate issuerCertificate)
        {
            try
            {
                CertificateID certId = new CertificateID(CertificateID.HashSha1, issuerCertificate, certificate.SerialNumber);

                BasicOcspRespGenerator generator = new BasicOcspRespGenerator(new RespID(cert.SubjectDN));

                Org.BouncyCastle.Ocsp.CertificateStatus status = new UnknownStatus();
                if (certificate.SerialNumber.ToString() == cert.SerialNumber.ToString() || notRevoked.Any(x => x.Item1.SerialNumber.ToString() == certificate.SerialNumber.ToString() && x.Item2.SerialNumber.ToString() == issuerCertificate.SerialNumber.ToString()))
                {
                    status = Org.BouncyCastle.Ocsp.CertificateStatus.Good;
                }
                else if (revoked.Any(x => x.Item1.SerialNumber.ToString() == certificate.SerialNumber.ToString() && x.Item2.SerialNumber.ToString() == issuerCertificate.SerialNumber.ToString()))
                {
                    // 0 - Unspecified
                    status = new Org.BouncyCastle.Ocsp.RevokedStatus(DateTime.UtcNow, 0);
                }

                generator.AddResponse(certId, status);

                BasicOcspResp resp = generator.Generate("SHA1withRSA", keyPair.Private, new X509Certificate[] { cert }, DateTime.UtcNow, null);

                return resp;
            }
            catch (Exception e)
            {
                throw new IOException(e.Message, e);
            }
        }

        public void AddNotRevokedCert(X509Certificate certificate, X509Certificate issuerCertificate)
        {
            notRevoked.Add((certificate, issuerCertificate));
        }

        public void AddRevokedCert(X509Certificate certificate, X509Certificate issuerCertificate)
        {
            revoked.Add((certificate, issuerCertificate));
        }

    }

    class FakeOnlineCrlSource : ICrlSource
    {
        private readonly List<(X509Certificate, X509Certificate, AsymmetricCipherKeyPair)> revoked = new List<(X509Certificate, X509Certificate, AsymmetricCipherKeyPair)>();
        private readonly Dictionary<X509Certificate, (X509Certificate, AsymmetricCipherKeyPair)> certIssuerPairs;


        public FakeOnlineCrlSource(Dictionary<X509Certificate, (X509Certificate, AsymmetricCipherKeyPair)> certIssuerPairs)
        {
            this.certIssuerPairs = certIssuerPairs;
        }
        public IEnumerable<X509Crl> FindCrls(X509Certificate certificate, X509Certificate issuerCertificate)
        {
            X509V2CrlGenerator crlGen = new X509V2CrlGenerator();
            DateTime now = DateTime.UtcNow.AddDays(-1);
            //			BigInteger			revokedSerialNumber = BigInteger.Two;

            var pair = certIssuerPairs.ContainsKey(certificate) ? certIssuerPairs[certificate] : (null, null);
            var cert = pair.Item1;
            var privateKey = pair.Item2?.Private;
            var revokedCertObjs = revoked.Where(x => x.Item2.SerialNumber.ToString() == issuerCertificate.SerialNumber.ToString());
            if (revokedCertObjs.Any())
            {
                var revokedCertObj = revokedCertObjs.FirstOrDefault(x => x.Item1?.SerialNumber.ToString() == certificate.SerialNumber.ToString());
                if (revokedCertObj.Item1 != null)
                {
                    crlGen.AddCrlEntry(revokedCertObj.Item1.SerialNumber, now, CrlReason.PrivilegeWithdrawn);
                }

                cert = revokedCertObjs.First().Item2;
                privateKey = revokedCertObjs.First().Item3.Private;
            }

            crlGen.SetIssuerDN(PrincipalUtilities.GetSubjectX509Principal(cert));

            crlGen.SetThisUpdate(now);
            crlGen.SetNextUpdate(now.AddDays(30));
            crlGen.SetSignatureAlgorithm("SHA256WithRSAEncryption");

            crlGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(cert));
            crlGen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.One));

            return new List<X509Crl> { crlGen.Generate(privateKey) };
        }
        public void AddRevokedCert(X509Certificate certificate, X509Certificate issuerCertificate, AsymmetricCipherKeyPair keyPair)
        {
            revoked.Add((certificate, issuerCertificate, keyPair));
        }

        public void AddCertIssuer(X509Certificate certificate, X509Certificate issuerCertificate, AsymmetricCipherKeyPair keyPair)
        {
            certIssuerPairs[certificate] = (issuerCertificate, keyPair);
        }
    }

    class FakeAIACertificateFactoryImpl : ICertificateSourceFactory
    {
        public ICertificateSource CreateAIACertificateSource(X509Certificate certificate)
        {
            return new ListCertificateSource(new[] { certificate });
        }
    }
}
