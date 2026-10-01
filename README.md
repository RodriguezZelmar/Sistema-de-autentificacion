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
- [Flujo de logout](#flujo-de-logout)
- [Roles y permisos](#roles-y-permisos)
- [Autorización y 401 vs 403](#autorización-y-401-vs-403)
- [Usuario administrador de demo](#usuario-administrador-de-demo)
- [Recuperación de contraseña](#recuperación-de-contraseña)
- [Seguridad](#seguridad)

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

| | Autenticación | Autorización |
|---|---|---|
| Pregunta | ¿Quién sos? | ¿Qué tenés permitido hacer? |
| En este proyecto | Login con email + contraseña → JWT. En cada request, JwtBearer valida el JWT y establece la identidad (`sub`, `role`). | `PermissionAuthorizationHandler` traduce el rol a permisos y verifica el que pide el endpoint. |
| Cómo se declara | `[Authorize]` | `[RequirePermission(Permissions.UsersDelete)]` |
| Si falla | **401 Unauthorized** | **403 Forbidden** |
| Código | [`Auth/Jwt/`](src/AuthApi/Auth/Jwt) | [`Authorization/`](src/AuthApi/Authorization) |

Ejemplo concreto con dos usuarios autenticados, Ana (USER) y el admin (ADMIN):

```text
GET /users/me           Ana   → 200   autenticación: alcanza con estar logueado
GET /users              Ana   → 200   autorización: USER tiene users:read
DELETE /users/{id}      Ana   → 403   autenticada ✔, pero USER NO tiene users:delete
DELETE /users/{id}      admin → 204   ADMIN tiene users:delete
DELETE /users/{id}      (sin token) → 401   ni siquiera sabemos quién es
```

Las dos piezas están separadas en el código y en el pipeline de ASP.NET Core:

```csharp
app.UseAuthentication();   // 1° ¿quién sos?  → construye HttpContext.User a partir del JWT
app.UseAuthorization();    // 2° ¿qué podés hacer? → evalúa [Authorize] / [RequirePermission]
```

La autorización nunca mira el token ni la firma: trabaja sobre la identidad que la autenticación
ya validó. Y la autenticación no sabe nada de permisos.

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

---

## Flujo de logout

```text
POST /auth/logout  { "refreshToken": "..." }
  ↓
1. Buscar el refresh token por su hash
  ↓
2. Si existe y está activo → RevokedAt = ahora
  ↓
3. 204 No Content  (siempre: es idempotente y no revela si el token existía)
```

- Solo cierra **esa** sesión (ese dispositivo); las otras sesiones del usuario siguen activas.
- No exige access token: tener el refresh token alcanza, y así se puede cerrar sesión aunque el
  access token ya haya expirado.

> ⚠️ **Limitación importante:** el access token JWT ya emitido **sigue siendo válido hasta su
> expiración** (máximo 15 minutos), porque es stateless: el servidor no consulta la base para
> validarlo. Hay un test que documenta este comportamiento
> (`Logout_DoesNotInvalidateAlreadyIssuedAccessToken`). Por eso el access token dura poco.
> Si se necesitara revocación inmediata, las opciones son: una *denylist* de `jti` revocados
> (en Redis, con TTL igual a la vida del token), o guardar una "versión de sesión" por usuario y
> compararla en cada request — ambas reintroducen estado y una consulta por request.

---

## Roles y permisos

```text
Role
 ↓
conjunto de permisos
 ↓
acción que puede realizar
```

| Rol | Permisos |
|---|---|
| `USER` | `users:read` |
| `ADMIN` | `users:read`, `users:create`, `users:update`, `users:delete` |

- **Roles** ([`Roles`](src/AuthApi/Authorization/Roles.cs)): se guardan en `User.Role` y viajan en el claim `role` del JWT.
- **Permisos** ([`Permissions`](src/AuthApi/Authorization/Permissions.cs)): formato `recurso:acción`.
- **Mapa rol → permisos** ([`RolePermissions`](src/AuthApi/Authorization/RolePermissions.cs)): vive en el código.

¿Por qué los endpoints piden **permisos** y no roles? Con `[Authorize(Roles = "ADMIN")]`, agregar un
rol `MODERATOR` que también pueda borrar obligaría a modificar cada endpoint. Con permisos, el
endpoint dice *qué acción* realiza (`users:delete`) y solo cambia el mapa rol → permisos.

¿Por qué el token lleva el **rol** y no la lista de permisos? El token queda chico y el mapa
rol → permisos se resuelve en el servidor en cada request, así un cambio en el mapa aplica de
inmediato sin esperar a que expiren los tokens.

¿Por qué el mapa está en código y no en tablas? Porque los permisos están acoplados al código que
define los endpoints, y no se pidió administrarlos en tiempo de ejecución. Si hiciera falta, se
pasaría a tablas `Role` / `Permission` / `RolePermission` cambiando solo `RolePermissions`.

`GET /users/me` devuelve los permisos del usuario actual, útil para ver el mapa en acción:

```json
{ "user": { "email": "ana@example.com", "role": "USER", ... }, "permissions": ["users:read"] }
```

---

## Autorización y 401 vs 403

El guard de autorización es un atributo:

```csharp
[HttpDelete("{id:guid}")]
[RequirePermission(Permissions.UsersDelete)]
public async Task<IActionResult> Delete(Guid id, ...)
```

[`RequirePermissionAttribute`](src/AuthApi/Authorization/RequirePermissionAttribute.cs) hereda de
`[Authorize]` (así que primero exige autenticación) y agrega un `PermissionRequirement`.
[`PermissionAuthorizationHandler`](src/AuthApi/Authorization/PermissionAuthorizationHandler.cs)
lee el claim `role` de la identidad ya validada y comprueba si ese rol tiene el permiso.

```text
Request
   ↓
¿Tiene token válido?  ── No ──→ 401 Unauthorized
   ↓ Sí                          "No sé quién sos" (token ausente, inválido, alterado o expirado).
   ↓                             Solución: autenticarse (login / refresh).
¿Tiene el permiso?    ── No ──→ 403 Forbidden
   ↓ Sí                          "Sé quién sos, pero no podés hacer esto."
   ↓                             Volver a autenticarse no cambia nada.
Puede acceder (2xx)
```

| Código | Significa | Ejemplo en este proyecto |
|---|---|---|
| **401 Unauthorized** | Falta autenticación o es inválida. (El nombre del estándar es confuso: en realidad significa *unauthenticated*.) Incluye header `WWW-Authenticate: Bearer`. | `GET /users` sin token, con token expirado o con firma inválida |
| **403 Forbidden** | La identidad es válida pero no tiene permiso. | `DELETE /users/{id}` con un token de USER |

Ambos devuelven un cuerpo `application/problem+json` (RFC 9457) con el motivo.

---

## Usuario administrador de demo

El registro público **siempre** crea usuarios `USER`. El DTO de registro ni siquiera tiene una
propiedad `role`, así que enviar `{"role": "ADMIN"}` no tiene efecto (hay un test que lo verifica:
`Register_IgnoresRoleSentByClient`).

¿Cómo se obtiene entonces un ADMIN? De dos formas controladas:

1. **Seed al arrancar** ([`DatabaseInitializer`](src/AuthApi/Data/DatabaseInitializer.cs)): si las
   variables `ADMIN_EMAIL` y `ADMIN_PASSWORD` están definidas y ese usuario no existe, se crea con rol
   ADMIN. La contraseña debe cumplir la misma política que cualquier otra. En producción basta con no
   definirlas (o eliminarlas después del primer arranque).
2. **Un ADMIN existente** crea o promueve usuarios con `POST /users` o `PUT /users/{id}`
   (permisos `users:create` / `users:update`).

Reglas de los endpoints de administración ([`UserService`](src/AuthApi/Users/UserService.cs)):
- Un rol desconocido → 400.
- Un admin no puede cambiar su propio rol, desactivarse ni eliminarse (evita quedarse sin admin) → 400.
- Al cambiar el rol de un usuario o desactivarlo, se **revocan todos sus refresh tokens**: para seguir
  usando la API debe volver a hacer login, y su nuevo token reflejará el rol nuevo. Su access token
  actual sigue vigente hasta expirar (máx. 15 min) — la misma limitación que en logout.
- Al eliminar un usuario, sus refresh tokens y tokens de recuperación se borran en cascada.

---

## Recuperación de contraseña

> ⚠️ **Simulada.** En una aplicación real el token se envía **por email** (como parte de un link,
> p. ej. `https://app.com/reset?token=...`) y nunca aparece en la respuesta HTTP. Devolverlo en la
> respuesta es solo una simplificación de este proyecto educativo para poder probar el flujo sin
> un servidor de correo, y se controla con `PASSWORD_RESET_EXPOSE_TOKEN` (en producción: `false`).

```text
POST /auth/forgot-password  { "email" }
  ↓
1. ¿Existe un usuario activo con ese email?
     No → 200 con el mensaje genérico (no se revela si el email existe)
  ↓ Sí
2. Borrar los tokens anteriores sin usar de ese usuario (solo vale el último pedido)
  ↓
3. Generar token aleatorio (512 bits), guardar SOLO su hash, con ExpiresAt = ahora + 15 min
  ↓
4. [App real: enviar email]   [Demo: incluir resetToken en la respuesta]
  ↓
5. 200 { "message": "If the email is registered, ...", "resetToken"?, "resetTokenExpiresAt"? }


POST /auth/reset-password  { "token", "newPassword" }
  ↓
1. Validar newPassword con la política de contraseñas                → 400
  ↓
2. Buscar el token por su hash. ¿Existe, no expiró y no fue usado?   → 400 si no
  ↓
3. En una transacción:
   a. Marcar UsedAt de forma atómica (UPDATE ... WHERE UsedAt IS NULL):
      si dos requests usan el mismo token a la vez, solo uno gana
   b. Guardar el hash BCrypt de la nueva contraseña
   c. Revocar TODOS los refresh tokens del usuario (cierra sesiones abiertas
      con la contraseña vieja, por si eran de un atacante)
  ↓
4. 204 No Content → el usuario hace login con la contraseña nueva
```

El token de recuperación cumple los requisitos:

| Requisito | Implementación ([`PasswordResetService`](src/AuthApi/Auth/Tokens/PasswordResetService.cs)) |
|---|---|
| Tiene expiración | `ExpiresAt` (15 min, `PASSWORD_RESET_TOKEN_MINUTES`) |
| Es de un solo uso | `UsedAt` se completa al usarlo; un segundo uso → 400 |
| Se invalida después de usarse | Ídem, y además pedir uno nuevo borra los anteriores sin usar |
| Está asociado al usuario | `UserId` (FK con borrado en cascada) |
| No se guarda en texto plano | Solo el hash SHA-256 |

Tests: [`PasswordResetTests`](tests/AuthApi.Tests/PasswordResetTests.cs) (válido, expirado, ya usado,
desconocido, revoca sesiones, modo producción sin token en la respuesta…).

Simplificación conocida: en modo demo, que la respuesta incluya o no el token revela si el email existe.
Con `PASSWORD_RESET_EXPOSE_TOKEN=false` la respuesta es idéntica en ambos casos.

---

## Seguridad

### Medidas implementadas

| Riesgo | Medida | Dónde |
|---|---|---|
| Contraseñas filtradas desde la base | BCrypt con salt por usuario y work factor configurable; nunca texto plano | `BcryptPasswordHasher` |
| Exposición del hash | Las entidades nunca se serializan: solo DTOs (`UserResponse`) sin `PasswordHash` | `Users/UserDtos.cs` |
| Secretos en el código | `JWT_SECRET`, credenciales del admin, etc. vienen de variables de entorno / `.env` (ignorado por git). La app no arranca sin un `JWT_SECRET` de ≥ 32 caracteres | `AuthOptions`, `.env.example` |
| SQL injection | Todo el acceso a datos es vía EF Core/LINQ → consultas parametrizadas. No hay SQL concatenado | `Data/`, services |
| Entrada inválida | DataAnnotations + `[ApiController]` → 400 automático; política de contraseñas; longitudes máximas | DTOs, `PasswordPolicyAttribute` |
| Usuarios duplicados | Email normalizado (trim + minúsculas) + verificación previa + **índice único** en la base | `UserService`, `AppDbContext` |
| Escalada de privilegios en el registro | El DTO de registro no tiene `role`; siempre se asigna USER | `AuthService.RegisterAsync` |
| Tokens alterados / falsificados | Firma HS256 verificada, algoritmo fijo (rechaza `alg: none`), issuer y audience validados | `JwtTokenService` |
| Tokens expirados | `exp` validado (access); `ExpiresAt` validado (refresh y reset) | JwtBearer, services |
| Robo de access token | Vida corta (15 min) y payload sin datos sensibles | `AuthOptions` |
| Robo de refresh token | Guardado como hash, rotación en cada uso, detección de reutilización, revocable | `RefreshTokenService` |
| Refresh tokens revocados | `RevokedAt` comprobado en cada refresh; logout, reset y cambio de rol revocan | `RefreshTokenService` |
| Reutilización de tokens de recuperación | `UsedAt` + `UPDATE` atómico condicional; pedir uno nuevo borra los anteriores | `PasswordResetService` |
| Enumeración de usuarios | Login: mismo mensaje y hash ficticio para emails inexistentes (mismo tiempo). Forgot-password: mismo mensaje siempre | `AuthService` |
| Fuerza bruta | Rate limiting por IP en `/auth/*` (`AUTH_RATE_LIMIT_PER_MINUTE`, por defecto 10/min) → 429 | `AuthModuleExtensions` |
| Contraseñas / tokens en logs | Solo se loguean ids de usuario, nunca contraseñas ni tokens | services |
| Fuga de detalles internos | Errores inesperados → 500 genérico (el detalle queda solo en el log del servidor). Errores esperados → ProblemDetails | `GlobalExceptionHandler` |
| Transporte | `UseHttpsRedirection` fuera de Development | `Program.cs` |

### Simplificaciones de este proyecto (y qué haría en producción)

- **Recuperación de contraseña sin email**: el token se devuelve en la respuesta en modo demo. → Enviar email y `PASSWORD_RESET_EXPOSE_TOKEN=false`.
- **Revocación de access tokens**: un JWT emitido vale hasta expirar (máx. 15 min), aun después de logout o cambio de rol. → Denylist de `jti` en Redis o "versión de sesión" por usuario si se necesita revocación inmediata.
- **Refresh token en el body**: → Cookie `HttpOnly; Secure; SameSite=Strict` en clientes web.
- **HS256 (clave simétrica)**: cualquier servicio que valide tokens necesita el secreto. → Con varios servicios, RS256/ES256 (firma con clave privada, validación con la pública, publicada vía JWKS).
- **Rate limiting en memoria y por IP**: no se comparte entre instancias. → Redis o el API gateway. Se puede complementar con bloqueo temporal de cuenta tras N intentos fallidos.
- **Sin verificación de email** al registrarse, ni MFA.
- **Concurrencia en refresh**: dos refresh simultáneos con el mismo token podrían rotar ambos. Se podría usar el mismo `UPDATE` condicional que en reset-password.
- **Limpieza de tokens**: los refresh/reset tokens expirados quedan en la base. → Job periódico que los borre.
- **Migraciones al arrancar**: cómodo para la demo. → En producción, aplicarlas en el pipeline de despliegue.
- **SQLite**: → PostgreSQL / SQL Server cambiando el provider de EF Core.
