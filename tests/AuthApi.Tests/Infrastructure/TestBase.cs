using System.Net.Http.Json;
using AuthApi.Data;
using Microsoft.Extensions.DependencyInjection;

namespace AuthApi.Tests.Infrastructure;

/// <summary>
/// Base de los tests de integración: cada test recibe una API recién levantada
/// (xUnit crea una instancia de la clase por test) y helpers para los pasos repetidos.
/// </summary>
public abstract class TestBase : IDisposable
{
    protected const string ValidPassword = "Password123";

    protected AuthApiFactory Factory { get; } = new();
    protected HttpClient Client { get; }

    protected TestBase() => Client = Factory.CreateClient();

    protected Task<HttpResponseMessage> RegisterAsync(string email, string password = ValidPassword, string? name = null) =>
        Client.PostAsJsonAsync("/auth/register", new { email, password, name });

    /// <summary>Ejecuta código contra la base de datos de la API (para verificar lo que realmente se guardó).</summary>
    protected async Task<T> WithDbAsync<T>(Func<AppDbContext, Task<T>> action)
    {
        using var scope = Factory.Services.CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<AppDbContext>());
    }

    public void Dispose()
    {
        Client.Dispose();
        Factory.Dispose();
        GC.SuppressFinalize(this);
    }
}
