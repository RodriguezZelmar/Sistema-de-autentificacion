namespace AuthApi.Common;

/// <summary>
/// Error de negocio con un código HTTP asociado. Los services lo lanzan y
/// <see cref="GlobalExceptionHandler"/> lo convierte en una respuesta ProblemDetails.
/// Así los controllers quedan limpios y los services no conocen detalles de HTTP más allá del código.
/// </summary>
public sealed class ApiException(int statusCode, string title, string detail) : Exception(detail)
{
    public int StatusCode { get; } = statusCode;
    public string Title { get; } = title;

    public static ApiException BadRequest(string detail) => new(StatusCodes.Status400BadRequest, "Bad Request", detail);
    public static ApiException Unauthorized(string detail) => new(StatusCodes.Status401Unauthorized, "Unauthorized", detail);
    public static ApiException Forbidden(string detail) => new(StatusCodes.Status403Forbidden, "Forbidden", detail);
    public static ApiException NotFound(string detail) => new(StatusCodes.Status404NotFound, "Not Found", detail);
    public static ApiException Conflict(string detail) => new(StatusCodes.Status409Conflict, "Conflict", detail);
}
