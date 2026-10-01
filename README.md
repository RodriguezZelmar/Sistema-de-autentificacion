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
