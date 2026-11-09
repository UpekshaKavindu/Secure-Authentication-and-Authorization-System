# Secure Authentication and Authorization System

A full-stack web application that securely verifies **who a user is** (authentication) and controls **what they are allowed to do** (authorization).

> **Note:** Items marked `TODO` depend on your actual code. Replace them before publishing.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Tech Stack](#tech-stack)
4. [Architecture](#architecture)
5. [Project Structure](#project-structure)
6. [Getting Started](#getting-started)
7. [Configuration](#configuration)
8. [API Reference](#api-reference)
9. [Security Measures](#security-measures)
10. [Testing](#testing)
11. [Documentation](#documentation)
12. [Contributing](#contributing)
13. [License](#license)

---

## Overview

This project provides a secure login and access-control layer that can protect a web application. It is split into a **backend** (REST API handling identity, credentials, tokens and permissions) and a **frontend** (user interface for registration, login and role-based pages).

The full requirements are described in [`SRS.docx`](./SRS.docx).

## Features

> Confirm each item against your implementation and delete what is not built.

- User registration with input validation
- Secure login and logout
- Password hashing (never stored in plain text)
- Token-based authentication (e.g. JWT) with expiry
- Role-Based Access Control (RBAC), e.g. `ADMIN`, `USER`
- Protected routes on both backend and frontend
- Proper error handling without leaking sensitive details
- `TODO:` password reset, email verification, multi-factor authentication, account lockout, audit logging

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | `TODO` (e.g. Java Spring Boot + Spring Security) |
| Frontend | `TODO` (e.g. React / Angular) |
| Database | `TODO` (e.g. MySQL / PostgreSQL / MongoDB) |
| Auth | `TODO` (e.g. JWT, BCrypt) |
| Testing | `TODO` (e.g. JUnit, Mockito, Postman, Jest) |

## Architecture

```
┌────────────┐   HTTPS    ┌──────────────────┐        ┌──────────┐
│  Frontend  │ ─────────► │  Backend (API)   │ ─────► │ Database │
│  (client)  │ ◄───────── │  Auth + RBAC     │ ◄───── │          │
└────────────┘   JSON     └──────────────────┘        └──────────┘
```

**Login flow**

1. The user submits credentials to the login endpoint.
2. The backend finds the user and compares the password with the stored hash.
3. If valid, the backend issues a signed token containing the user identity and role.
4. The frontend sends the token with every later request.
5. The backend verifies the token and checks the role before allowing access to a resource.

## Project Structure

```
.
├── security-backend/     # Server-side API (authentication, authorization, data access)
├── security-frontend/    # Client-side user interface
├── SRS.docx              # Software Requirements Specification
├── README.md
└── TESTING.md            # Testing guide
```

## Getting Started

### Prerequisites

- `TODO` Runtime for the backend (e.g. JDK 17+, Maven/Gradle)
- `TODO` Node.js 18+ and npm (for the frontend)
- `TODO` Database server installed and running
- Git

### 1. Clone the repository

```bash
git clone https://github.com/UpekshaKavindu/Secure-Authentication-and-Authorization-System.git
cd Secure-Authentication-and-Authorization-System
```

### 2. Run the backend

```bash
cd security-backend
# TODO: replace with your real commands, for example:
# ./mvnw spring-boot:run
```

The API runs on `http://localhost:TODO_PORT`.

### 3. Run the frontend

```bash
cd security-frontend
# TODO: replace with your real commands, for example:
# npm install
# npm start
```

The UI runs on `http://localhost:TODO_PORT`.

## Configuration

Never commit real secrets. Use environment variables or an untracked config file.

| Variable | Description | Example |
|----------|-------------|---------|
| `DB_URL` | Database connection string | `TODO` |
| `DB_USERNAME` | Database user | `TODO` |
| `DB_PASSWORD` | Database password | `TODO` |
| `JWT_SECRET` | Key used to sign tokens (long and random) | `TODO` |
| `JWT_EXPIRATION` | Token lifetime | `TODO` |

## API Reference

> Replace with your real endpoints.

| Method | Endpoint | Access | Description |
|--------|----------|--------|-------------|
| POST | `/api/auth/register` | Public | Create a new account |
| POST | `/api/auth/login` | Public | Authenticate and receive a token |
| GET | `/api/user/profile` | Authenticated | View own profile |
| GET | `/api/admin/users` | Admin only | List all users |

**Example request**

```http
POST /api/auth/login
Content-Type: application/json

{ "username": "user@example.com", "password": "********" }
```

**Example response**

```json
{ "token": "<jwt>", "role": "USER", "expiresIn": 3600 }
```

## Security Measures

- Passwords are stored as salted hashes (e.g. BCrypt)
- Tokens are signed and have an expiry time
- Server-side authorization checks on every protected endpoint
- Input validation and parameterized database queries (SQL injection protection)
- Output encoding and sanitization (XSS protection)
- CORS restricted to trusted origins
- HTTPS recommended for all deployments
- Generic error messages for failed logins (no user enumeration)

## Testing

See **[TESTING.md](./TESTING.md)** for the full step-by-step testing guide covering unit, integration, API, security, frontend, end-to-end and performance testing.

## Documentation

- [Software Requirements Specification](./SRS.docx)

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push the branch: `git push origin feature/your-feature`
5. Open a Pull Request

## License

`TODO:` Add a license (e.g. MIT) and include a `LICENSE` file.

## Author

**Upeksha Kavindu**
