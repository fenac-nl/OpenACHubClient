using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace OpenACHubClient.Model
{
    public enum JwtSignOption
    {
        Signature, NoSignature, InvalidSignature, InvalidSignAlgorithm
    }
    public class JwtToken
    {
        private readonly object _jwtHeader = null;
        private readonly object _jwtPayload = null;
        private readonly X509Certificate2 _cert = null;
        private readonly JwtSignOption _signOption;
        public JwtToken(object jwtHeader, object jwtPayload, X509Certificate2 cert, JwtSignOption signOption = JwtSignOption.Signature)
        {
            _jwtHeader = jwtHeader;
            _jwtPayload = jwtPayload;
            _cert = cert;
            _signOption = signOption;
        }

        public override string ToString()
        {
            var contractResolver = new DefaultContractResolver
            {
                NamingStrategy = new CamelCaseNamingStrategy()
            };
            var serializerSettings = new JsonSerializerSettings
            {
                ContractResolver = contractResolver,
                Formatting = Formatting.Indented
            };
            var jwtHeader = Base64UrlTextEncoder.Encode(
                Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject(_jwtHeader, serializerSettings)
                )
            );
            var jwtPayload = Base64UrlTextEncoder.Encode(
                Encoding.UTF8.GetBytes(
                    JsonConvert.SerializeObject(_jwtPayload, serializerSettings)
                )
            );
            if (_signOption == JwtSignOption.NoSignature)
            {
                return $"{jwtHeader}.{jwtPayload}.";
            }
            string jwtSignature;
            var rsa = (RSACng)_cert.PrivateKey;
            jwtSignature = Base64UrlTextEncoder.Encode(
                rsa.SignData(
                    Encoding.UTF8.GetBytes(
                        $"{jwtHeader}.{jwtPayload}"), 
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1
                    )
                );
            if (_signOption == JwtSignOption.InvalidSignature)
            {
                // Laat de eerste 10 posities weg voor een ongeldige handtekening.
                jwtSignature = jwtSignature.Substring(10);
            }
            return $"{jwtHeader}.{jwtPayload}.{jwtSignature}";
        }
    }
}
