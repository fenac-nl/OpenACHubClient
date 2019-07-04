using System;
using System.Collections.Generic;
using System.Text;

namespace OpenACHubClient.Model.Zorgdomein
{
    public class JwtPayload
    {
        public string Iss { get; set; } = "Zorgdomein";
        public string Jti { get; set; } = Guid.NewGuid().ToString();
        public long Iat { get; set; } = DateTimeOffset.Now.ToUnixTimeSeconds();
    }
}
