# Backend - Auth System with Session Management

This is a Node.js backend using Express, MongoDB, JWT, and AWS S3 for a full authentication system with session handling.

## Features

- Register with profile picture (uploads to S3)
- Login with username or email
- JWT-based access and refresh tokens
- Session tracking by IP, location, and user agent
- View and manage sessions
- Token refresh route
- Logout and session termination
- Middleware for authentication

## Setup Instructions

1. **Install dependencies**

```bash
npm install
```

2. **Environment Variables**

Create a `.env` file with the following:

```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
JWT_REFRESH_SECRET=your_jwt_refresh_secret
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
AWS_REGION=your_region
S3_BUCKET_NAME=your_bucket
```

3. **Run the server**

```bash
npm run dev
```

4. **Production build**

```bash
npm start
```

## Folder Structure

- `controllers/`: Route logic
- `routes/`: API endpoints
- `middleware/`: Auth and file upload
- `models/`: Mongoose schemas
- `utils/`: Helper functions (e.g., S3)

## API Routes

### Auth (`/api/auth`)
- `POST /register`: Register a new user
- `POST /login`: Login user
- `GET /refresh-token`: Refresh access token
- `GET /logout`: Logout user
- `GET /me`: Get profile (requires token)

### Sessions (`/api/sessions`)
- `GET /`: List active sessions
- `DELETE /:sessionId`: Logout from a specific session
