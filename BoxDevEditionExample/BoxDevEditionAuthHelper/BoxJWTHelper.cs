using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using RestSharp;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.IO;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

/* Use Nuget to install the following packages:
 * 
 * Bouncy Castle
 * JSON Web Token Handler for the Microsoft .NET Framework 4.5
 * Json.NET
 * RestSharp
 * 
 * Also, add a reference to System.IdentityModel
 */

namespace BoxDevEditionAuthHelper
{
    public class BoxJWTHelper
    {
        const string AUTH_URL = "https://api.box.com/oauth2/token";
        const string USERS_URL = "https://api.box.com/2.0/users";
        const string JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

        private readonly string enterpriseId;
        private readonly string clientId;
        private readonly string clientSecret;
        private readonly SigningCredentials credentials;

        public BoxJWTHelper(string enterpriseId, string clientId, string clientSecret, string privateKey, string privateKeyPassword)
        {
            this.enterpriseId = enterpriseId;
            this.clientId = clientId;
            this.clientSecret = clientSecret;

            var pwf = new PEMPasswordFinder(privateKeyPassword);
            AsymmetricCipherKeyPair key;
            using (var reader = new StringReader(privateKey))
            {
                key = (AsymmetricCipherKeyPair)new PemReader(reader, pwf).ReadObject();
            }
            var rsa = DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)key.Private);

            this.credentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
        }

        public string GetEnterpriseToken()
        {
            string assertion = ConstructJWTAssertion(this.enterpriseId, "enterprise");

            var result = JWTAuthPost(assertion);
            return result.access_token;
        }

        public string GetUserToken(string userId)
        {
            string assertion = ConstructJWTAssertion(userId, "user");

            var result = JWTAuthPost(assertion);
            return result.access_token;
        }

        public string CreateAppUser(string name, string enterpriseToken)
        {
            var client = new RestClient(USERS_URL);
            var request = new RestRequest(Method.POST);
            request.AddHeader("Authorization", "Bearer " + enterpriseToken);
            request.AddJsonBody(new { name = name, is_platform_access_only = true });

            var response = client.Execute(request);
            var content = response.Content;

            dynamic parsed_content = JObject.Parse(content);
            return parsed_content.id;
        }

        public void DeleteAppUser(string userId, string enterpriseToken, bool force = true)
        {
            var client = new RestClient(USERS_URL + "/" + userId);
            var request = new RestRequest(Method.DELETE);
            request.AddHeader("Authorization", "Bearer " + enterpriseToken);
            request.AddParameter("force", force ? "true" : "false");

            var response = client.Execute(request);
        }

        private string ConstructJWTAssertion(string sub, string boxSubType)
        {
            byte[] randomNumber = new byte[64];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomNumber);
            }

            var claims = new List<Claim>{
                new Claim("sub", sub),
                new Claim("box_sub_type", boxSubType),
                new Claim("jti", Convert.ToBase64String(randomNumber)),
            };

            var token = new JwtSecurityToken(issuer: this.clientId, audience: AUTH_URL, claims: claims, expires: DateTime.UtcNow.AddSeconds(30),
                            signingCredentials: this.credentials);

            var tokenHandler = new JwtSecurityTokenHandler();
            string assertion = tokenHandler.WriteToken(token);
            return assertion;
        }

        private dynamic JWTAuthPost(string assertion)
        {
            var client = new RestClient(AUTH_URL);
            var request = new RestRequest(Method.POST);
            request.AddParameter("grant_type", JWT_GRANT_TYPE);
            request.AddParameter("client_id", this.clientId);
            request.AddParameter("client_secret", this.clientSecret);
            request.AddParameter("assertion", assertion);

            var response = client.Execute(request);
            var content = response.Content;

            dynamic parsed_content = JObject.Parse(content);
            return parsed_content;
        }
    }


    class PEMPasswordFinder : IPasswordFinder
    {
        private string pword;

        public PEMPasswordFinder(string password)
        {
            pword = password;
        }

        public char[] GetPassword()
        {
            return pword.ToCharArray();
        }
    }
}

