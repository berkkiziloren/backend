# Node.js Backend with Express and MongoDB

This is a boilerplate Node.js backend project using Express.js and MongoDB, optimized for AWS deployment.

## Prerequisites

- Node.js (v14 or higher)
- MongoDB (local or Atlas)
- AWS Account (for deployment)

## Setup Instructions

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file in the root directory with the following variables:
```
PORT=3000
MONGODB_URI=your_mongodb_connection_string
NODE_ENV=development
```

3. Start the development server:
```bash
npm run dev
```

## Project Structure

```
.
├── app.js              # Main application file
├── package.json        # Project dependencies
├── .env               # Environment variables (create this file)
└── README.md          # This file
```

## AWS Deployment

### MongoDB Setup
1. Create a MongoDB Atlas account
2. Create a new cluster
3. Set up database access (user/password)
4. Set up network access (IP whitelist)
5. Get your connection string

### Backend Deployment
1. Create an EC2 instance
2. Install Node.js and npm
3. Clone your repository
4. Set up environment variables
5. Install PM2: `npm install -g pm2`
6. Start the application: `pm2 start app.js`

## Security Considerations

- Always use environment variables for sensitive data
- Enable CORS only for necessary origins
- Use Helmet for security headers
- Implement proper authentication
- Use HTTPS in production

## Available Scripts

- `npm start`: Start the production server
- `npm run dev`: Start the development server with nodemon
- `npm test`: Run tests

## License

MIT 