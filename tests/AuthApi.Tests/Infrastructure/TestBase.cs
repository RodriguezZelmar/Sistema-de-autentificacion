using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthApi.Auth;
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

    protected Task<HttpResponseMessage> LoginAsync(string email, string password = ValidPassword) =>
        Client.PostAsJsonAsync("/auth/login", new { email, password });

    /// <summary>Registra (si hace falta) y hace login; devuelve las credenciales.</summary>
    protected async Task<TokenResponse> RegisterAndLoginAsync(string email, string password = ValidPassword)
    {
        await RegisterAsync(email, password);
        return await LoginAsAsync(email, password);
    }

    protected async Task<TokenResponse> LoginAsAsync(string email, string password = ValidPassword)
    {
        var response = await LoginAsync(email, password);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TokenResponse>())!;
    }

    /// <summary>Request con "Authorization: Bearer &lt;token&gt;".</summary>
    protected Task<HttpResponseMessage> SendAsync(HttpMethod method, string url, string? accessToken, object? body = null)
    {
        var request = new HttpRequestMessage(method, url);
        if (accessToken is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        if (body is not null)
            request.Content = JsonContent.Create(body);
        return Client.SendAsync(request);
    }

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
