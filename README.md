# License Server & Admin Dashboard

Root-free Android App Optimizer Central License Server.

## Features
- **Admin Dashboard**: Web UI at `http://<server-ip>:5000/admin`
- **Secure Activation & Validation**: Cryptographic keys (`RO-XXXX-XXXX-XXXX-XXXX`)
- **Device Binding**: Configurable activations per key with remote unbind capabilities
- **Zero-Dependency SQLite**: Native `node:sqlite` in Node 22+ with automatic schema creation
- **Abuse Protection**: Sliding window IP rate-limiting and audit logging
- **Full Key Lifecycle**: Generate, Revoke, Reactivate, Delete, Set Expiration & Durations

## Quick Start

### 1. Requirements
- Node.js v22+ (tested on Node v24)
- npm

### 2. Install Dependencies
```bash
cd LicenseServer
npm install
```

### 3. Create Admin Account
```bash
node scripts/create-admin.js <username> <password>
# Example:
node scripts/create-admin.js admin myStrongPassword123
```

### 4. Start Server
```bash
# Development / Foreground:
node server.js

# Production with PM2 or systemd:
npm install -g pm2
pm2 start server.js --name "license-server"
```
Default port is `5000`. You can change it via `PORT=8080 node server.js`.

### 5. Access Admin Dashboard
Navigate to `http://<your-server-ip>:5000/admin` in any web browser and log in with your admin credentials.

## API Documentation

### Public Endpoints (Used by Android APK)
- `POST /api/license/activate`
  - Body: `{"license_key": "RO-...", "device_id": "...", "device_model": "..."}`
  - Returns: Session token, license status, and expiration date.
- `POST /api/license/validate`
  - Body: `{"license_key": "RO-...", "device_id": "...", "session_token": "..."}`
- `GET /api/health`

### Admin Endpoints (Require Bearer Token)
- `POST /api/admin/login`
- `GET /api/admin/stats`
- `GET /api/admin/licenses`
- `POST /api/admin/licenses/generate`
- `POST /api/admin/licenses/:id/revoke`
- `POST /api/admin/licenses/:id/activate`
- `DELETE /api/admin/licenses/:id`
- `GET /api/admin/licenses/:id/activations`
- `DELETE /api/admin/activations/:id` (Unbind device)
- `GET /api/admin/logs`
