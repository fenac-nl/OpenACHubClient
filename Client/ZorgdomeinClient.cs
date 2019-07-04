using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using OpenACHubClient.Config;
using OpenACHubClient.Model;
using OpenACHubClient.Model.Zorgdomein;
using Newtonsoft.Json;
using FhirBundle = Hl7.Fhir.Model.Bundle;

namespace OpenACHubClient.Client
{
    public class ZorgdomeinClient
    {
        private readonly IConfigurationRoot _config;
        private readonly ZorgdomeinConfig _zorgdomeinConfig = new ZorgdomeinConfig();
        private HttpClient _client = null;
        private HttpClientHandler _handler = null;
        private readonly X509Certificate2 _certificate = null;

        public ZorgdomeinClient(IConfigurationRoot config)
        {
            _config = config;
            _zorgdomeinConfig = new ZorgdomeinConfig();
            _config.GetSection("Zorgdomein").Bind(_zorgdomeinConfig);
            _certificate = new X509Certificate2(
                _zorgdomeinConfig.ClientCertificate.File, 
                _zorgdomeinConfig.ClientCertificate.Password
            );
            MakeClient();
        }

        ~ZorgdomeinClient()
        {
            if (_client != null)
            {
                _client.Dispose();
            }
        }

        private void MakeClient()
        {
            _handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = Validate
            };
            _client = new HttpClient(_handler);
            _client.DefaultRequestHeaders.ConnectionClose = false;
            _client.DefaultRequestHeaders.Add("Connection", "Keep-Alive");
            _client.DefaultRequestHeaders.Add("Keep-Alive", "timeout=5");
        }

        private bool Validate(HttpRequestMessage reqMessage, X509Certificate2 cert, X509Chain chain, SslPolicyErrors errors)
        {
            return true;
        }

        private bool IsTestGeselecteerd(ScanType scanType)
        {
            switch (scanType)
            {
                case ScanType.ValidCertificateValidJwt:
                    return _zorgdomeinConfig.ScanConfig.ValidCertificateValidJwt;

                case ScanType.NoCertificateValidJwt:
                    return _zorgdomeinConfig.ScanConfig.NoCertificateValidJwt;

                case ScanType.ValidCertificateNoJwt:
                    return _zorgdomeinConfig.ScanConfig.ValidCertificateNoJwt;

                case ScanType.ValidCertificateNoSignatureJwt:
                    return _zorgdomeinConfig.ScanConfig.ValidCertificateNoSignatureJwt;

                case ScanType.ValidCertificateInvalidSignatureJwt:
                    return _zorgdomeinConfig.ScanConfig.ValidCertificateInvalidSignatureJwt;

                case ScanType.ValidCertificateInvalidSigningAlgorithMJwt:
                    return _zorgdomeinConfig.ScanConfig.ValidCertificateInvalidSigningAlgorithMJwt;

                case ScanType.ValidCertificateExpiredJwt:
                    return _zorgdomeinConfig.ScanConfig.ValidCertificateExpiredJwt;

                default:
                    return false;
            }
        }

        public async Task DoSecurityScan()
        {
            // voor de volgorde van de tests
            var scans = new List<SecurityScan>
            {
                new SecurityScan {
                    Type = ScanType.ValidCertificateValidJwt,
                    Description = "Geldig certificaat en geldige JWT",
                    UseCertificate = true,
                    ExpectedResponse = 201
                },
                new SecurityScan {
                    Type = ScanType.NoCertificateValidJwt,
                    Description = "Geen certificaat en geldige JWT",
                    UseCertificate = false,
                    ExpectedResponse = 403
                },
                new SecurityScan {
                    Type = ScanType.ValidCertificateNoJwt,
                    Description = "Geldig certificaat en geen JWT",
                    UseCertificate = true,
                    ExpectedResponse = 401
                },
                new SecurityScan {
                    Type = ScanType.ValidCertificateNoSignatureJwt,
                    Description = "Geldig certificaat en JWT zonder handtekening",
                    UseCertificate = true,
                    ExpectedResponse = 401
                },
                new SecurityScan {
                    Type = ScanType.ValidCertificateInvalidSignatureJwt,
                    Description = "Geldig certificaat en JWT met ongeldige handtekening",
                    UseCertificate = true,
                    ExpectedResponse = 401
                },
                new SecurityScan {
                    Type = ScanType.ValidCertificateInvalidSigningAlgorithMJwt,
                    Description = "Geldig certificaat en JWT met ongeldig teken algoritme",
                    UseCertificate = true,
                    ExpectedResponse = 401
                },
                new SecurityScan {
                    Type = ScanType.ValidCertificateExpiredJwt,
                    Description = "Geldig certificaat en verlopen JWT",
                    UseCertificate = true,
                    ExpectedResponse = 401
                },
            };

            var bundle = new FhirBundle();
            var content = new StringContent(JsonConvert.SerializeObject(bundle), Encoding.UTF8, "application/json");
            var url = $"https://{_zorgdomeinConfig.Host}:{_zorgdomeinConfig.Port}/api/zorgdomein/verwijzing/bundle?";
            string jwt = "";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"Start security scan voor URL: {url}");
            Console.ResetColor();
            Console.WriteLine("----------------------------------------------------------------------------------------------");

            foreach (var scan in scans)
            {
                if (!IsTestGeselecteerd(scan.Type)) continue;

                Console.Write("* Security scan: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(scan.Description);
                Console.ResetColor();

                _client.DefaultRequestHeaders.Authorization = null;
                if (scan.UseCertificate)
                {
                    _handler.ClientCertificates.Clear();
                    _handler.ClientCertificates.Add(_certificate);
                }
                else
                {
                    // Test zonder certificaat: maak een nieuwe client omdat het certificaat
                    // anders aan de verbinding verbonden blijft.
                    MakeClient();
                }

                switch (scan.Type)
                {
                    case ScanType.ValidCertificateValidJwt:
                    case ScanType.NoCertificateValidJwt:
                        jwt = new JwtToken(new JwtHeader(), new JwtPayload(), _certificate).ToString();
                        _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
                        break;

                    case ScanType.ValidCertificateNoJwt:
                        // We hoeven niets te doen: certificaat is hierboven al toegevoegd, JWT wordt hier niet toegevoegd.
                        break;

                    case ScanType.ValidCertificateNoSignatureJwt:
                        jwt = new JwtToken(new JwtHeader(), new JwtPayload(), _certificate, signOption: JwtSignOption.NoSignature).ToString();
                        _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
                        break;

                    case ScanType.ValidCertificateInvalidSignatureJwt:
                        jwt = new JwtToken(new JwtHeader(), new JwtPayload(), _certificate, signOption: JwtSignOption.InvalidSignature).ToString();
                        _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
                        break;

                    case ScanType.ValidCertificateInvalidSigningAlgorithMJwt:
                        //  Zorgdomein verwacht RS256 (RSA + SHA256). Geef HS256 (HMAC + SHA256) om een ongeldig signing algoritme te testen
                        jwt = new JwtToken(new JwtHeader { Alg = "HS256" }, new JwtPayload(), _certificate, signOption: JwtSignOption.InvalidSignAlgorithm).ToString();
                        _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
                        break;

                    case ScanType.ValidCertificateExpiredJwt:
                        jwt = new JwtToken(new JwtHeader(), new JwtPayload { Iat = DateTimeOffset.Now.ToUnixTimeSeconds() - 5000 }, _certificate).ToString();
                        _client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
                        break;
                }
                try
                {
                    var response = await _client.PostAsync(url, content);
                    var statusCode = (int)response.StatusCode;

                    if (statusCode == scan.ExpectedResponse)
                    {
                        var statusMessage = $"Statuscode: {statusCode} - {response.ReasonPhrase}";
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"[OK] {statusMessage}");
                    }
                    else
                    {
                        var statusMessage = $"Expected statuscode: {scan.ExpectedResponse}, received: {statusCode} - {response.ReasonPhrase}";
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[ERROR] {statusMessage}");
                    }
                }
                catch (Exception e)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[ERROR] Kon geen verbinding maken met '{url}'");
                    Console.WriteLine($"Exception: {e.Message}");
                }

                Console.ResetColor();
            }
        }
        
    }
}
