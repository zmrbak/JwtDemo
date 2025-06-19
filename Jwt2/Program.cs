
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace Jwt2
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            builder.Services.AddScoped<MyAuthService>();
            builder.Services.AddHttpContextAccessor();

            builder.Services.AddAuthentication("MyCookie").AddCookie("MyCookie");
            builder.Services.AddAuthorization(builder =>
            {
                builder.AddPolicy("MyPolicy", policy =>
                {
                    policy.RequireClaim("special", "allow");
                });
            });


            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseAuthentication();
            app.UseAuthorization();

            {
                app.MapGet("other4", (HttpContext ctx) =>
                {
                    var isAuthenticated = ctx.User.Identities.Any(x => x.AuthenticationType == "MyCookie");
                    if (isAuthenticated)
                    {
                        return "�ѵ�¼";
                    }
                    else
                    {
                        return "δ��¼";
                    }
                });

                //�˴� (HttpContext ctx) ���ɼ�дΪ ctx
                app.MapGet("login4", async (HttpContext ctx) =>
                {
                    //claim �����Ϣ������������ɫ��Ȩ��
                    //claimidentity �����֤��Ϣ
                    //claimprincipal �������֤��Ϣ����ĳ���û�
                    var claims = new List<Claim>();
                    claims.Add(new Claim("name", "zmrbak"));

                    claims.Add(new Claim("special", "allow"));

                    var identity = new ClaimsIdentity(claims, "MyCookie");
                    await ctx.SignInAsync("MyCookie", new ClaimsPrincipal(identity));
                    return "��¼�ɹ�";
                });

                app.MapGet("special",(HttpContext ctx) =>
                {
                    var isAuthenticated = ctx.User.Identities.Any(x => x.AuthenticationType == "MyCookie");
                    if (isAuthenticated)
                    {
                        return "�ѵ�¼";
                    }
                    else
                    {
                        return "δ��¼";
                    }
                }).RequireAuthorization("MyPolicy");
            }

            {
                app.MapGet("other3", (HttpContext ctx) =>
                {
                   var isAuthenticated = ctx.User.Identities.Any(x => x.AuthenticationType=="MyCookie");
                    if (isAuthenticated)
                    {
                        return "�ѵ�¼";
                    }
                    else
                    {
                        return "δ��¼";
                    }
                });

                //�˴� (HttpContext ctx) ���ɼ�дΪ ctx
                app.MapGet("login3", async (HttpContext ctx) =>
                {
                    //claim �����Ϣ������������ɫ��Ȩ��
                    //claimidentity �����֤��Ϣ
                    //claimprincipal �������֤��Ϣ����ĳ���û�
                    var claims = new List<Claim>();
                    claims.Add(new Claim("name", "zmrbak"));
                    var identity = new ClaimsIdentity(claims, "MyCookie");
                    await ctx.SignInAsync("MyCookie", new ClaimsPrincipal(identity));
                    return "��¼�ɹ�";
                });
            }


            {
                app.MapGet("other2", (HttpContext ctx) =>
                {
                    var cookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
                    return cookie;
                });

                //�˴� (HttpContext ctx) ���ɼ�дΪ ctx
                app.MapGet("login2", (MyAuthService ctx) =>
                {
                    ctx.SignIn();
                    return "��¼�ɹ�";
                });
            }


            {
                app.MapGet("other1", (HttpContext ctx) =>
                {
                    var cookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
                    return cookie;
                });

                //�˴� (HttpContext ctx) ���ɼ�дΪ ctx
                app.MapGet("login1", (HttpContext ctx) =>
                {
                    ctx.Response.Headers["set-cookie"] = "auth=name:zmrbak";
                    return "��¼�ɹ�";
                });
            }

            app.MapControllers();

            app.Run();
        }

        public class MyAuthService
        {
            private readonly IHttpContextAccessor contextAccessor;

            public MyAuthService(IHttpContextAccessor contextAccessor)
            {
                this.contextAccessor = contextAccessor;
            }

            public void SignIn()
            {
                contextAccessor.HttpContext!.Response.Headers["set-cookie"] = "auth=name:zmrbak";
            }
        }
    }
}
