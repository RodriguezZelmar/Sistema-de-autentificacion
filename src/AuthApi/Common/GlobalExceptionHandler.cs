using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Common;

/// <summary>
/// Punto único donde las excepciones se convierten en respuestas HTTP.
/// - <see cref="ApiException"/>: error esperado → su código y mensaje.
/// - Cualquier otra: error inesperado → 500 genérico, sin stack trace ni detalles internos.
/// </summary>
public sealed class GlobalExceptionHandler(
    IProblemDetailsService problemDetails,
    ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext context, Exception exception, CancellationToken ct)
    {
        ProblemDetails problem;

        if (exception is ApiException api)
        {
            problem = new ProblemDetails { Status = api.StatusCode, Title = api.Title, Detail = api.Message };
        }
        else
        {
            // Se registra el error completo en el log del servidor, pero el cliente solo ve un mensaje genérico.
            logger.LogError(exception, "Unhandled exception on {Method} {Path}", context.Request.Method, context.Request.Path);
            problem = new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "Internal Server Error",
                Detail = "An unexpected error occurred."
            };
        }

        context.Response.StatusCode = problem.Status.Value;
        return await problemDetails.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = context,
            ProblemDetails = problem,
            Exception = exception
        });
    }
}
