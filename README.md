# Gmail OAuth Backend with MongoDB & S3

This project is a Node.js backend that allows users to register/login, authenticate with Gmail, and fetch their emails. Gmail OAuth tokens are stored securely in Amazon S3, and user data is stored in MongoDB.

## Features
- User registration and login (JWT-based)
- Gmail OAuth2 authentication (per user)
- Gmail tokens stored in S3 (per user)
- Emails fetched from Gmail API
- MongoDB for user storage

## Prerequisites
- Node.js (v16+ recommended)
- An AWS account with an S3 bucket
- A MongoDB database (local or Atlas)
- Google Cloud project with OAuth2 credentials (download `credentials.json`)

## Setup

1. **Clone the repository**
2. **Install dependencies:**
   ```sh
   npm install
   ```
3. **Create a `.env` file** (see `.env.example`)
4. **Place your `credentials.json`** (Google OAuth) in the project root
5. **Start the server:**
   ```sh
   npm run dev
   # or
   npm start
   ```

## Environment Variables
See `.env.example` for all required variables:
- `MONGO_URI` - MongoDB connection string
- `JWT_SECRET` - Secret for JWT signing
- `AWS_ACCESS_KEY_ID` - AWS IAM access key
- `AWS_SECRET_ACCESS_KEY` - AWS IAM secret key
- `AWS_REGION` - AWS region for S3
- `S3_BUCKET_NAME` - Your S3 bucket name

## Usage
1. Register a user via `/register`
2. Login via `/login` to get a JWT
3. Use the app UI to authenticate with Gmail and view emails

## Security Notes
- Never commit your `.env` or `credentials.json` to version control.
- Use IAM users with least privilege for AWS credentials.

## License
MIT 