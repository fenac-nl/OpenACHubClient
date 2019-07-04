using System;
using System.Collections.Generic;
using System.Text;

namespace OpenACHubClient.Config
{
    public class ZorgdomeinConfig
    {
        public string Host { get; set; } = "127.0.0.1";
        public int Port { get; set; } = 2700;
        public ClientcertificateConfig ClientCertificate { get; set; }
        public ScanConfig ScanConfig { get; set; }
    }
}
