using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TokenAuthenticationWithJWT.Database;

const string adminRole = "admin";
const string adminUserName = "admin";
const string adminEmail = "admin@nader.com";
const string adminPassword = "1q2w3E**";

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseInMemoryDatabase("tokenAuthDB");
});

builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedPhoneNumber = false;
    options.SignIn.RequireConfirmedEmail = false;
    options.SignIn.RequireConfirmedAccount = false;
    options.Password.RequireDigit = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddApiEndpoints();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var secretKey = builder.Configuration["JWT:SecretKey"]!;
        var validIssuer = builder.Configuration["JWT:ValidIssuer"]!;
        var validAudience = builder.Configuration["JWT:ValidAudience"]!;
        options.TokenValidationParameters = new()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = validIssuer,
            ValidAudience = validAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
        };
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("adminPolicy", builder =>
    {
        builder.RequireRole(adminRole);
    });

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.MapIdentityApi<IdentityUser>();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapPost("/create-default-user", async (RoleManager<IdentityRole> roleManager,
                                UserManager<IdentityUser> userManager) =>
{
    var roleCreationResult = await roleManager.CreateAsync(new(adminRole));
    IdentityUser identityUser = new(adminUserName);
    identityUser.Email = adminEmail;
    var userCreationResult = await userManager.CreateAsync(identityUser, adminPassword);
    var userAddToRoleResult = await userManager.AddToRoleAsync(identityUser, adminRole);

    return new { roleCreationResult, userCreationResult, userAddToRoleResult };
});

app.MapPost("/token", async (UserManager<IdentityUser> userManager, IConfiguration configuration) =>
{
    IdentityUser? identityUser = await userManager.FindByNameAsync(adminUserName);
    if (identityUser is null)
    {
        return Results.Ok("User not found!!");
    }

    var result = await userManager.PasswordValidators[0].ValidateAsync(userManager, identityUser, adminPassword);
    if (!result.Succeeded)
    {
        return Results.Ok("Username or password combination is wrong!!");
    }
    var claims = new List<Claim>
                    {
                        new(JwtRegisteredClaimNames.Sub,   identityUser.Id.ToString()),
                        new(JwtRegisteredClaimNames.Email, identityUser.Email!),
                        new(JwtRegisteredClaimNames.Name,  identityUser.UserName!),
                    };

    foreach (var role in await userManager.GetRolesAsync(identityUser))
    {
        claims.Add(new(ClaimTypes.Role, role));
    }

    var secretKey = configuration["JWT:SecretKey"];
    var validIssuer = configuration["JWT:ValidIssuer"];
    var validAudience = configuration["JWT:ValidAudience"];

    SymmetricSecurityKey symmetricSecurityKey = new(Encoding.UTF8.GetBytes(secretKey!));
    SigningCredentials signingCredentials = new(symmetricSecurityKey,
                                                SecurityAlgorithms.HmacSha256);
    JwtSecurityToken jwtSecurityToken = new(validIssuer,
                                            validAudience,
                                            claims,
                                            null,
                                            DateTime.UtcNow.AddHours(1),
                                            signingCredentials);

    JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

    string tokenValue = jwtSecurityTokenHandler.WriteToken(jwtSecurityToken);

    return Results.Ok(tokenValue);
});

app.MapControllers();

app.MapGet("/secure", [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = adminRole)]() =>
{
    return "I'm authorized!!";
});

app.UseAuthentication();
app.UseAuthorization();

app.Run();
