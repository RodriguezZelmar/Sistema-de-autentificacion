using AuthApi.Common;
using AuthApi.Config;
using AuthApi.Data;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;

// En desarrollo, carga las variables definidas en el archivo .env (si existe).
// NoClobber: una variable de entorno real siempre tiene prioridad sobre el .env.
DotNetEnv.Env.NoClobber().TraversePath().Load();

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddOpenApi(options => options.AddDocumentTransformer<OpenApiBearerTransformer>());
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddSingleton(TimeProvider.System);

// La cadena de conexión se resuelve de forma diferida (cuando se crea el DbContext),
// así los tests pueden reemplazarla por una base temporal.
builder.Services.AddDbContext<AppDbContext>((sp, options) =>
    options.UseSqlite(sp.GetRequiredService<IConfiguration>()["DATABASE_CONNECTION"] ?? "Data Source=auth.db"));

builder.Services.AddAuthModule(builder.Configuration);

var app = builder.Build();

await DatabaseInitializer.InitializeAsync(app.Services);

app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();               // /openapi/v1.json
    app.MapScalarApiReference();    // /scalar (UI para probar la API)
}
else
{
    app.UseHttpsRedirection();
}

app.UseRateLimiter();      // límite de intentos en /auth/*
app.UseAuthentication();   // 1° ¿quién sos?  (lee y valida el JWT)
app.UseAuthorization();    // 2° ¿qué podés hacer? (aplica [Authorize] / permisos)

app.MapControllers();

app.Run();

// Necesario para que los tests de integración (WebApplicationFactory) puedan referenciar Program.
public partial class Program;
