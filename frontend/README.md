# Zero-Trust Auth Frontend

Next.js frontend application for testing the Zero-Trust API Gateway.

## Features

- User registration and login
- JWT authentication with refresh tokens
- MFA (Multi-Factor Authentication) support
- Device fingerprinting and trust scores
- Session management
- Real-time security dashboard

## Getting Started

### Install Dependencies

```bash
cd frontend
npm install
```

### Run Development Server

```bash
npm run dev
```

Open [http://localhost:3002](http://localhost:3002) in your browser.

### Build for Production

```bash
npm run build
npm start
```

## API Configuration

The frontend connects to the Zero-Trust API Gateway at `http://localhost:3000`.

To change this, edit `.env.local`:

```
NEXT_PUBLIC_API_URL=http://localhost:3000
```

## Usage

1. **Register**: Create a new account at `/register`
2. **Login**: Sign in at `/login`
3. **Dashboard**: View your user info, devices, and sessions at `/dashboard`

## Testing MFA

To test MFA functionality:

1. Register and login
2. Use the gateway API to enable MFA (`POST /auth/mfa/enroll`)
3. Scan QR code with Google Authenticator or similar app
4. Confirm enrollment with TOTP code
5. Next login will require MFA verification

## Security Features Demonstrated

- **JWT Authentication**: Access and refresh token management
- **Device Fingerprinting**: Unique device identification via SHA-256
- **Trust Scoring**: Real-time device trust assessment (0-100)
- **Risk Assessment**: Multi-factor risk calculation
- **Session Management**: Persistent session tracking
- **MFA Support**: TOTP-based two-factor authentication

## Tech Stack

- Next.js 15
- React 19
- TypeScript
- Tailwind CSS
