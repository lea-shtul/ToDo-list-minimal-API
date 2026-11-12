using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;                
using Microsoft.AspNetCore.Identity;                               
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;                      
using Microsoft.IdentityModel.Tokens;                              
using TodoApi;


var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("ToDoDB")
                       ?? builder.Configuration["ToDoDB"];

builder.Services.AddDbContext<ToDoDbContext>(options =>
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString)));

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


var jwt = builder.Configuration.GetSection("Jwt");
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt["Key"]!));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt["Issuer"],
            ValidateAudience = true,
            ValidAudience = jwt["Audience"],
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key
        };
    });
builder.Services.AddAuthorization();



var app = builder.Build();


using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ToDoDbContext>();
    db.Database.EnsureCreated();
}

app.UseCors("AllowAll");



app.UseCors("AllowAll");
app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();   //מי אתה
app.UseAuthorization();    //מה מותר לך לעשות

//הרשמה
app.MapPost("/register", async (ToDoDbContext db, AuthRequest req) =>
{
    if (await db.Users.AnyAsync(u => u.Username == req.Username))
        return Results.BadRequest("שם המשתמש כבר קיים");

    var user = new User { Username = req.Username };
    user.Password = new PasswordHasher<User>().HashPassword(user, req.Password);

    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Ok();
});

// התחברות
app.MapPost("/login", async (ToDoDbContext db, AuthRequest req) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == req.Username);
    if (user is null) return Results.Unauthorized();

    var result = new PasswordHasher<User>().VerifyHashedPassword(user, user.Password, req.Password);
    if (result == PasswordVerificationResult.Failed) return Results.Unauthorized();

    var descriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username)
        }),
        Expires = DateTime.UtcNow.AddHours(2),
        Issuer = jwt["Issuer"],
        Audience = jwt["Audience"],
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
    };

    var token = new JsonWebTokenHandler().CreateToken(descriptor);
   return Results.Ok(new { token, username = user.Username });
});

app.MapGet("/items", async (ToDoDbContext db, ClaimsPrincipal user) =>
{
    var userId = GetUserId(user);
    return await db.Items.Where(i => i.UserId == userId).ToListAsync();
}).RequireAuthorization();

app.MapPost("/items", async (ToDoDbContext db, ClaimsPrincipal user, Item newItem) =>
{
    newItem.UserId = GetUserId(user);
    db.Items.Add(newItem);
    await db.SaveChangesAsync();
    return Results.Created($"/items/{newItem.Id}", newItem);
}).RequireAuthorization();

app.MapPut("/items/{id}", async (ToDoDbContext db, ClaimsPrincipal user, int id, Item updatedItem) =>
{
    var userId = GetUserId(user);
    var item = await db.Items.FirstOrDefaultAsync(i => i.Id == id && i.UserId == userId);
    if (item is null) return Results.NotFound();
    if (updatedItem.Name is not null) item.Name = updatedItem.Name;
    item.IsComplete = updatedItem.IsComplete;
    await db.SaveChangesAsync();
    return Results.Ok(item);
}).RequireAuthorization();

app.MapDelete("/items/{id}", async (ToDoDbContext db, ClaimsPrincipal user, int id) =>
{
    var userId = GetUserId(user);
    var item = await db.Items.FirstOrDefaultAsync(i => i.Id == id && i.UserId == userId);
    if (item is null) return Results.NotFound();
    db.Items.Remove(item);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();

app.Run();


static int GetUserId(ClaimsPrincipal user) =>
    int.Parse(user.FindFirst(ClaimTypes.NameIdentifier)!.Value);


record AuthRequest(string Username, string Password);