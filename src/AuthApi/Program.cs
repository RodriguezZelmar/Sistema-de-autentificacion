using AuthApi.Common;
using AuthApi.Config;
using Scalar.AspNetCore;

// En desarrollo, carga las variables definidas en el archivo .env (si existe).
// NoClobber: una variable de entorno real siempre tiene prioridad sobre el .env.
DotNetEnv.Env.NoClobber().TraversePath().Load();

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddSingleton(TimeProvider.System);

builder.Services.AddAuthModule(builder.Configuration);

var app = builder.Build();

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

app.MapControllers();

app.Run();

// Necesario para que los tests de integración (WebApplicationFactory) puedan referenciar Program.
public partial class Program;
