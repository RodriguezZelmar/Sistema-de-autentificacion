# Auth API — Autenticación y autorización reutilizable

API REST que implementa un sistema de **autenticación y autorización** completo y reutilizable:
registro, login, hashing de contraseñas, JWT, refresh tokens, roles, permisos, logout y
recuperación de contraseña.

No es una aplicación: es un **módulo base** pensado para incorporarse a otros proyectos
(una tienda, un sistema de gestión, el backend de un juego…). El recurso `/users` existe
únicamente para demostrar que la autenticación y la autorización funcionan.

> Stack: **ASP.NET Core 10** · **EF Core 10 + SQLite** · **BCrypt** · **JWT (HMAC-SHA256)** · **xUnit**

---

## Índice

- [Stack y por qué](#stack-y-por-qué)
- [Autenticación vs autorización](#autenticación-vs-autorización)
- [Arquitectura](#arquitectura)
- [Modelo de datos](#modelo-de-datos)
- [Endpoints](#endpoints)
- [Flujo de registro](#flujo-de-registro)
- [Flujo de login](#flujo-de-login)
- [JWT](#jwt)
- [Middleware de autenticación](#middleware-de-autenticación)
- [Refresh tokens](#refresh-tokens)

---

## Stack y por qué

| Pieza | Elección | Motivo |
|---|---|---|
| Framework | ASP.NET Core 10 (controllers) | Muy usado en la industria. Separa de forma nativa *authentication* (handlers → 401) de *authorization* (policies → 403). |
| ORM / DB | EF Core + SQLite | SQLite es un único archivo: cero instalación. EF Core genera consultas parametrizadas (protege contra SQL injection) y migraciones para crear la DB desde cero. Cambiar a PostgreSQL/SQL Server es cambiar el provider. |
| Hash de contraseñas | BCrypt (`BCrypt.Net-Next`) | Algoritmo diseñado para contraseñas: lento a propósito, con *salt* incluido y costo configurable. |
| Tokens | JWT firmado con HMAC-SHA256 (`Microsoft.AspNetCore.Authentication.JwtBearer`) | Estándar de facto para APIs stateless. |
| Tests | xUnit + `WebApplicationFactory` | Tests de integración que levantan la API real en memoria y hacen requests HTTP. |

---

## Autenticación vs autorización

```text
Authentication = ¿Quién sos?              Authorization = ¿Qué tenés permitido hacer?
```

*(se completa con ejemplos concretos a medida que se implementa)*

---

## Arquitectura

```text
Client
  ↓
Auth API (ASP.NET Core)
  ↓
Authentication  ── JwtBearer valida firma, expiración, issuer, audience  → si falla: 401
  ↓
JWT (identidad: sub = userId, role)
  ↓
Authorization   ── [RequirePermission("users:delete")]                  → si falla: 403
  ↓
Roles / Permissions (USER → users:read · ADMIN → users:*)
  ↓
Protected Resources (/users)
```

Capas dentro de cada módulo:

```text
HTTP → Controller (valida entrada, traduce a HTTP) → Service (lógica) → AppDbContext (EF Core) → SQLite
```

Estructura del proyecto:

```text
src/AuthApi/
├── Auth/            Registro, login, refresh, logout, recuperación de contraseña
├── Authorization/   Roles, permisos y el "guard" que verifica permisos
├── Users/           UserService (almacén de identidades, lo usa Auth) + recurso de DEMO /users
├── Data/            DbContext, entidades, migraciones, seed del admin
├── Config/          Opciones leídas de variables de entorno + AddAuthModule()
├── Common/          Errores de negocio y manejador global de excepciones
└── Program.cs       Composición de la aplicación
tests/AuthApi.Tests/ Tests de integración
```

No se agregó una capa de *repositories*: `DbContext` de EF Core ya es una *unit of work* con
repositorios (`DbSet<T>`). Agregar otra capa encima en un proyecto de este tamaño solo sumaría
indirección sin beneficio.

---

## Modelo de datos

```text
User                       RefreshToken                PasswordResetToken
─────────────────          ─────────────────           ─────────────────
Id           (Guid)        Id        (Guid)            Id        (Guid)
Email        (único)       UserId    → User            UserId    → User
Name         (opcional)    TokenHash (SHA-256)         TokenHash (SHA-256)
PasswordHash (BCrypt)      ExpiresAt                   ExpiresAt
Role         (USER/ADMIN)  RevokedAt (null = activo)   UsedAt    (null = sin usar)
IsActive                   CreatedAt                   CreatedAt
CreatedAt
UpdatedAt
```

`IsActive` es el único campo que no estaba en el diseño mínimo: permite que el login
"verifique que el usuario pueda iniciar sesión" (un admin puede desactivar una cuenta).

---

## Endpoints

| Método | Ruta | Requiere | Descripción |
|---|---|---|---|
| POST | `/auth/register` | — | Registrar usuario (siempre con rol USER) |
| POST | `/auth/login` | — | Login → access token + refresh token |
| POST | `/auth/refresh` | refresh token | Nuevo access token (rota el refresh token) |
| POST | `/auth/logout` | refresh token | Revoca el refresh token |
| POST | `/auth/forgot-password` | — | Genera token de recuperación (simulado) |
| POST | `/auth/reset-password` | token de recuperación | Cambia la contraseña |
| GET | `/users/me` | access token | Perfil del usuario autenticado |
| GET | `/users` | `users:read` | Listar usuarios |
| POST | `/users` | `users:create` | Crear usuario (puede elegir rol) |
| PUT | `/users/{id}` | `users:update` | Actualizar usuario |
| DELETE | `/users/{id}` | `users:delete` | Eliminar usuario |

---

## Flujo de registro

```text
POST /auth/register  { "email", "password", "name"? }
  ↓
1. Validar entrada (DataAnnotations + [ApiController])   → 400 si es inválida
     email válido · password 8-72 caracteres con letra y número
  ↓
2. Normalizar email (trim + minúsculas) y comprobar que no exista → 409 si existe
  ↓
3. Hashear la contraseña con BCrypt (salt aleatorio + work factor)
  ↓
4. Guardar el usuario (índice único en Email como garantía final ante registros simultáneos)
  ↓
5. Asignar rol USER — SIEMPRE. El DTO de registro no tiene campo "role":
   si el cliente envía {"role":"ADMIN"}, se ignora.
  ↓
6. 201 Created con UserResponse (id, email, name, role…) — nunca password ni passwordHash
```

Archivos: [`AuthController`](src/AuthApi/Auth/AuthController.cs) →
[`AuthService.RegisterAsync`](src/AuthApi/Auth/AuthService.cs) →
[`UserService.CreateAsync`](src/AuthApi/Users/UserService.cs) →
[`BcryptPasswordHasher`](src/AuthApi/Auth/Passwords/BcryptPasswordHasher.cs).

**¿Por qué BCrypt y no SHA-256?** SHA-256 es rápido: una GPU calcula miles de millones por
segundo, así que un hash SHA-256 de una contraseña filtrado se rompe por fuerza bruta. BCrypt es
lento a propósito (costo `2^BCRYPT_WORK_FACTOR`) y agrega un *salt* aleatorio por usuario, por lo
que dos contraseñas iguales producen hashes distintos y las *rainbow tables* no sirven.
El hash guardado (`$2a$12$<salt><hash>`) ya contiene algoritmo, costo y salt.

**Nota sobre enumeración de usuarios:** responder `409` a un email existente revela que ese email
está registrado. Es el compromiso habitual en un registro (la alternativa es confirmar por email
siempre). En login y recuperación de contraseña, en cambio, las respuestas no revelan si el
usuario existe.

---

## Flujo de login

```text
POST /auth/login  { "email", "password" }
  ↓
1. Buscar el usuario por email normalizado
  ↓
2. BCrypt.Verify(password, passwordHash)
   - Si el usuario NO existe se verifica igual contra un hash ficticio:
     misma demora y mismo mensaje → no se puede averiguar qué emails existen
   - Falla → 401 "Invalid email or password."
  ↓
3. ¿IsActive? No → 403 "This account is disabled."
  ↓
4. Generar access token (JWT, 15 min)
  ↓
5. Generar refresh token (aleatorio, 7 días) y guardar SOLO su hash SHA-256
  ↓
6. 200 { accessToken, tokenType: "Bearer", expiresIn, accessTokenExpiresAt,
         refreshToken, refreshTokenExpiresAt }
```

---

## JWT

### ¿Qué es?

Un **JSON Web Token** es un string con tres partes en Base64Url separadas por puntos:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 . eyJzdWIiOiI4ZjQ...In0 . 3q2-7_Yk1sX...
└──────────── header ────────────┘   └──── payload ────┘   └─ signature ─┘
```

| Parte | Contenido en este proyecto |
|---|---|
| **Header** | `{"alg":"HS256","typ":"JWT"}` — algoritmo de firma |
| **Payload** | `sub` (id del usuario), `role`, `jti` (id único del token), `iat`, `nbf`, `exp` (expiración), `iss` (quién lo emitió), `aud` (para quién) |
| **Signature** | `HMACSHA256(base64url(header) + "." + base64url(payload), JWT_SECRET)` |

### ¿Cómo se valida? ([`JwtTokenService.CreateValidationParameters`](src/AuthApi/Auth/Jwt/JwtTokenService.cs))

1. Tiene formato `header.payload.signature`.
2. El algoritmo es exactamente `HS256` (se rechaza `"alg":"none"` y cualquier otro).
3. La **firma** recalculada con `JWT_SECRET` coincide → nadie modificó el payload.
4. `exp` no pasó (con 30 s de tolerancia por diferencias de reloj) y `nbf` ya llegó.
5. `iss` y `aud` son los esperados.

Si cualquier paso falla → **401**. Hay tests para cada caso: sin token, token malformado,
expirado, firmado con otra clave, payload alterado (`USER` → `ADMIN`) y `alg: none`
([`JwtAuthenticationTests`](tests/AuthApi.Tests/JwtAuthenticationTests.cs)).

### ¿Qué NO debe ir en el payload?

El payload está **codificado, no cifrado**: cualquiera que tenga el token puede leerlo
(pegalo en jwt.io). Por eso nunca debe contener contraseñas, hashes, secretos, datos de pago
ni datos personales innecesarios. Este proyecto solo incluye el id y el rol (ni siquiera el email).

### Firmar ≠ cifrar

- **Firmar** (lo que hace este proyecto, JWS): garantiza **integridad y autenticidad** — el token lo
  emitió quien conoce el secreto y no fue modificado. El contenido sigue siendo visible.
- **Cifrar** (JWE): garantiza **confidencialidad** — el contenido no se puede leer sin la clave.

Un JWT firmado es como una carta con un sello de lacre: todos pueden leerla, pero nadie puede
alterarla sin romper el sello.

### Un JWT no es una contraseña

Es una **credencial temporal derivada** del login: prueba que alguien se autenticó hace poco.
Diferencias clave:
- **Expira** (15 min) y no puede cambiarse ni "resetearse" como una contraseña.
- Quien lo tenga puede usarlo (*bearer* = portador): por eso viaja solo por HTTPS, vive poco y no se loguea.
- No se guarda en el servidor: el servidor solo verifica la firma (es *stateless*). La contraseña,
  en cambio, se guarda (hasheada) y es el secreto de largo plazo del usuario.

### Secretos

`JWT_SECRET` se lee de variables de entorno (o `.env` en desarrollo), nunca está en el código.
La aplicación **no arranca** si falta o tiene menos de 32 caracteres (256 bits, requisito de HS256).

---

## Middleware de autenticación

ASP.NET Core ya trae el middleware: `app.UseAuthentication()` con el handler **JwtBearer**,
configurado en [`JwtBearerSetup`](src/AuthApi/Auth/Jwt/JwtBearerSetup.cs). En cada request:

```text
1. Obtiene el token del header  Authorization: Bearer <token>
2. Lo valida (formato + algoritmo)
3. Verifica la firma con JWT_SECRET
4. Verifica expiración (exp/nbf), issuer y audience
5. Obtiene la identidad → HttpContext.User con los claims (sub, role)
6. Si el endpoint tiene [Authorize] y la identidad es válida → continúa
7. Si no → 401 Unauthorized (ProblemDetails con el motivo: falta, inválido o expirado)
```

Un controller protegido no hace nada especial: solo declara `[Authorize]` y lee el id del usuario
con `User.GetUserId()`:

```csharp
[HttpGet("me")]
[Authorize]   // solo AUTENTICACIÓN: cualquier usuario logueado
public async Task<UserResponse> Me(CancellationToken ct) =>
    UserResponse.From(await users.GetByIdAsync(User.GetUserId(), ct));
```

---

## Refresh tokens

### ¿Por qué existen dos tokens?

```text
Access Token  (JWT)                         Refresh Token  (string aleatorio)
    ↓                                           ↓
vida corta (15 min)                         vida más larga (7 días)
    ↓                                           ↓
se envía en CADA request a recursos         se envía SOLO a POST /auth/refresh
protegidos (Authorization: Bearer)              ↓
    ↓                                       se usa para obtener un nuevo Access Token
stateless: el servidor solo verifica        stateful: está en la base → se puede REVOCAR
la firma → no se puede revocar
```

Es un compromiso entre **seguridad** y **comodidad**:
- Si el access token durara días, uno robado serviría días, y no hay forma de invalidarlo (es stateless).
- Si durara 15 minutos y no hubiera refresh, el usuario tendría que escribir la contraseña cada 15 minutos.
- Con ambos: el token que viaja en todos los requests (el más expuesto) vive poco, y la sesión larga
  depende de un token que viaja poco y que el servidor **sí controla** (puede revocarlo en logout,
  al cambiar la contraseña o si detecta robo).

### Flujo de refresh

```text
POST /auth/refresh  { "refreshToken": "..." }
  ↓
1. Hashear el token recibido (SHA-256) y buscarlo en RefreshTokens
     no existe                       → 401
  ↓
2. ¿RevokedAt != null?  → REUTILIZACIÓN detectada → revocar TODAS las sesiones del usuario → 401
  ↓
3. ¿ExpiresAt <= ahora? → 401
  ↓
4. ¿Usuario activo? No → 403
  ↓
5. ROTACIÓN: marcar el token actual como revocado y emitir uno nuevo
  ↓
6. 200 { accessToken nuevo, refreshToken nuevo, ... }
```

### Decisiones de seguridad ([`RefreshTokenService`](src/AuthApi/Auth/Tokens/RefreshTokenService.cs))

- **Valor opaco y aleatorio**: 512 bits de `RandomNumberGenerator` (CSPRNG). No es un JWT: no
  contiene datos y solo tiene sentido para este servidor.
- **Solo se guarda el hash SHA-256**: si se filtra la base, los hashes no se pueden usar como tokens.
  SHA-256 es suficiente (no hace falta BCrypt) porque el token tiene 512 bits de entropía:
  imposible de adivinar. Y al ser determinístico permite buscarlo por índice.
- **Rotación**: cada refresh token sirve una sola vez. Cada uso devuelve uno nuevo.
- **Detección de reutilización**: si llega un token ya rotado, alguien tiene una copia (¿robo?).
  Como no se puede saber quién es el legítimo, se revocan todas las sesiones del usuario y debe
  volver a hacer login.
- **Mismo mensaje** para token inexistente, expirado o revocado.

Simplificación: el refresh token viaja en el body JSON. En una aplicación web real conviene
enviarlo en una cookie `HttpOnly; Secure; SameSite=Strict` para que JavaScript no pueda leerlo.
