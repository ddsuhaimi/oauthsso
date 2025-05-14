# Poltek SSO OAuth 2.0 Server

A lightweight, in-memory OAuth 2.0 Authorization Server with OpenID Connect features.

## Features

- OAuth 2.0 Authorization Code Flow with PKCE
- JWT-based Access & Refresh Tokens
- Client Registration & Management
- User Management
- Token Introspection & Revocation
- OpenID Connect UserInfo Endpoint

## Project Structure

```
.
├── app
│   ├── config/      - Application configuration
│   ├── handlers/    - HTTP handlers for all endpoints
│   ├── middleware/  - HTTP middleware functions
│   ├── models/      - Data models and store implementation
│   ├── utils/       - Utility functions
│   └── views/       - HTML templates
└── main.go          - Application entry point
```

## Running Locally

### Prerequisites

- Go 1.20+

### Starting the Server

```bash
go run main.go
```

The server will start on port 8080 by default. You can configure the port by setting the `PORT` environment variable.

### Docker

To run the server in Docker:

```bash
docker build -t poltek-sso .
docker run -p 8080:8080 poltek-sso
```

## Configuration

The following environment variables can be used to configure the server:

- `PORT`: The port to run the server on (default: 8080)
- `ADMIN_USERNAME`: The username for admin authentication (default: admin)
- `ADMIN_PASSWORD`: The password for admin authentication (default: admin123)

## Usage

### 1. Register a Client

```bash
curl -X POST http://localhost:8080/clients \
  -u "admin:admin123" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Client App",
    "redirect_uris": ["http://localhost:3000/callback"],
    "scopes": ["openid", "profile", "email"]
  }'
```

The response will contain your `client_id` and `client_secret`. These are needed for OAuth authentication.

### 2. OAuth 2.0 Authorization Flow

#### Step 1: Redirect user to the authorization endpoint

```
GET /authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&scope=openid%20profile%20email&state=random_state_value&code_challenge=CODE_CHALLENGE&code_challenge_method=S256
```

The user will be presented with a login form. After successful authentication, they will be redirected to your redirect URI with an authorization code.

#### Step 2: Exchange code for tokens

```bash
curl -X POST http://localhost:8080/token \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=YOUR_REDIRECT_URI" \
  -d "code_verifier=CODE_VERIFIER"
```

The response will contain an access token, refresh token, token type, expiration time, and scope.

### 3. User Management

#### Register a new user

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword"
  }'
```

#### Confirm email (for development purposes)

```bash
curl -X POST "http://localhost:8080/confirm-email?token=fake_token&email=user@example.com"
```

#### Reset password (request)

```bash
curl -X POST http://localhost:8080/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

#### Reset password (confirmation)

```bash
curl -X PUT "http://localhost:8080/reset-password?user_id=USER_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset_token",
    "new_password": "newpassword123"
  }'
```

### 4. Refresh Tokens

```bash
curl -X POST http://localhost:8080/token \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN"
```

### 5. Revoke Tokens

```bash
curl -X POST http://localhost:8080/revoke \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -d "token=TOKEN_TO_REVOKE" \
  -d "token_type_hint=access_token"
```

### 6. Token Introspection

```bash
curl -X POST http://localhost:8080/introspect \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -d "token=TOKEN_TO_INTROSPECT"
```

### 7. UserInfo Endpoint

```bash
curl -X GET http://localhost:8080/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Important Notes

- This is an in-memory implementation intended for development and testing.
- All data is lost when the server is restarted.
- For production use, you would need to implement a persistent storage layer.
- The server uses RS256 for JWT signing with ephemeral keys generated at startup.

## License

MIT
