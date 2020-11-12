using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace API.Services
{
    public class TokenService : ITokenService
    {
        private readonly SymmetricSecurityKey _key;
        public TokenService(IConfiguration config)
        {
            //expecting byte[] key and passing name of TokenKey which we create later
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["TokenKey"]));
        }

        public string CreateToken(AppUser user)
        {
            //Identifying what claims we need to put inside the Token
            var claims = new List<Claim>
            {
                    //Passing Claim Type and Value - 3rd Overload - only 1 Claim using as of now and is UserName
                new Claim(JwtRegisteredClaimNames.NameId, user.UserName)
            };
            //Security Key & Alogritym
            var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

            //Describing the Token and specify what goes inside a Token as
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(7),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}
