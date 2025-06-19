
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Jwt3
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var secret = new RsaSecurityKey(RSA.Create());

            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();


            builder.Services.AddAuthentication("MyBearer").AddJwtBearer("MyBearer", options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    IssuerSigningKey = secret,
                };

                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        // You can add custom logic here if needed
                        if (context.Request.Query.ContainsKey("token"))
                        {
                            context.Token = context.Request.Query["token"];
                        }
                        return Task.CompletedTask;
                    },
                };
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }
            app.UseAuthentication();
            app.UseAuthorization();


            app.MapGet("other", (string token, HttpContext ctx) =>
            {
                var isAuth = ctx.User.Claims.Any(x => x.Issuer == "zmrbak");
                var a = ctx.User.Claims.ToList();
                return isAuth;
            });

            app.MapGet("jwt", () =>
            {
                var jwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim("iss","zmrbak"),
                        new Claim("sub","learning"),
                    }, "myjwt"),
                    SigningCredentials = new SigningCredentials(secret, SecurityAlgorithms.RsaSha256)
                });
                return jwt;
            });

            app.MapControllers();

            app.Run();
        }
    }
}
