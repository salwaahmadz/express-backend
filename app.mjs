import express from 'express';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import jsonfile from 'jsonfile'; // Import jsonfile package

// Load environment variables
import dotenv from 'dotenv';
dotenv.config();

// File path for the JSON database
const dbFilePath = './database.json';

// Initialize the Express app
const app = express();

// Define a JWT secret key. This should be isolated by using env variables for security
const jwtSecretKey = process.env.JWT_SECRET || 'your-default-secret-key';

// Set up CORS and JSON middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Basic home route for the API
app.get('/', (_req, res) => {
  res.send('Auth API.\nPlease use POST /auth & POST /verify for authentication');
});

// The auth endpoint that creates a new user record or logs a user based on an existing record
app.post('/auth', async (req, res) => {
  const { email, password } = req.body;

  // Read data from JSON file
  let dbData = {};
  try {
    dbData = await jsonfile.readFile(dbFilePath);
  } catch (error) {
    console.error('Error reading database file:', error);
  }

  // Look up the user entry in the database
  const user = dbData.users.find(user => user.email === email);

  // If found, compare the hashed passwords and generate the JWT token for the user
  if (user) {
    const result = await bcrypt.compare(password, user.password);
    if (!result) {
      return res.status(401).json({ message: 'Invalid password' });
    } else {
      const loginData = {
        email,
        signInTime: Date.now(),
      };

      const token = jwt.sign(loginData, jwtSecretKey);
      res.status(200).json({ message: 'success', token });
    }
  } else {
    const hash = await bcrypt.hash(password, 10);
    dbData.users.push({ email, password: hash });

    // Write data back to JSON file
    try {
      await jsonfile.writeFile(dbFilePath, dbData);
    } catch (error) {
      console.error('Error writing to database file:', error);
    }

    const loginData = {
      email,
      signInTime: Date.now(),
    };

    const token = jwt.sign(loginData, jwtSecretKey);
    res.status(200).json({ message: 'success', token });
  }
});

// The verify endpoint that checks if a given JWT token is valid
app.post('/verify', (req, res) => {
  const tokenHeaderKey = 'jwt-token';
  const authToken = req.headers[tokenHeaderKey];
  try {
    const verified = jwt.verify(authToken, jwtSecretKey);
    if (verified) {
      return res.status(200).json({ status: 'logged in', message: 'success' });
    } else {
      return res.status(401).json({ status: 'invalid auth', message: 'error' });
    }
  } catch (error) {
    return res.status(401).json({ status: 'invalid auth', message: 'error' });
  }
});

// An endpoint to see if there's an existing account for a given email address
app.post('/check-account', async (req, res) => {
  const { email } = req.body;

  // Read data from JSON file
  let dbData = {};
  try {
    dbData = await jsonfile.readFile(dbFilePath);
  } catch (error) {
    console.error('Error reading database file:', error);
  }

  const user = dbData.users.find(user => user.email === email);

  res.status(200).json({
    status: user ? 'User exists' : 'User does not exist',
    userExists: !!user,
  });
});

app.listen(3080, () => {
  console.log('Server is running on port 3080');
});