const express = require("express");
const app = express();
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
require('dotenv').config(); // Load environment variables

// Settings for the server
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const SECRET = "THE SECRET"

// Database connection
async function getDBConnection() {
  return await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "mydb",
  });
}

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Generate JWT token
function generateToken(user) {
  return jwt.sign(user, SECRET, { expiresIn: '2m' });
}

// Documentation
app.get("/", (req, res) => {
  res.send(`<h1>API Documentation</h1>
  <ul>
    <li>GET /users - Get all users</li>
    <li>POST /users - Create a new user</li>
    <li>PUT /users/:id - Update an existing user</li>
    <li>POST /login - Log in user and return a JWT token</li>
  </ul>`);
});

// GET route to fetch all users
app.get("/users", authenticateToken, async function (req, res) {
  try {
    const connection = await getDBConnection();
    const [rows] = await connection.execute('SELECT * FROM users');
    res.json(rows);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "An error occurred while fetching users." });
  }
});

// POST route to create new users
app.post("/users", async function (req, res) {
  try {
    const { username, password } = req.body;

    // Validate request body
    if (!username) {
      return res.status(400).json({ error: "Username is required." });
    }
    if (!password) {
      return res.status(400).json({ error: "Password is required." });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
    const connection = await getDBConnection();
    const [result] = await connection.execute(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)",
      [username, hashedPassword]
    );
    if (result.affectedRows !== 1) {
      return res.status(500).json({ error: "Failed to create user." });
    }

    // Fetch newly created user
    const [newUserRows] = await connection.execute('SELECT * FROM users WHERE id = ?', [result.insertId]);
    const newUser = newUserRows[0];
    res.status(201).json(newUser);
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "An error occurred while creating user." });
  }
});

// PUT route to update a user
app.put("/users/:id", authenticateToken, async function (req, res) {
  try {
    const userId = req.params.id;
    const { username, password } = req.body;

    // Validate request body
    if (!username) {
      return res.status(400).json({ error: "Username is required." });
    }
    if (!password) {
      return res.status(400).json({ error: "Password is required." });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update user information
    const connection = await getDBConnection();
    const [result] = await connection.execute(
      "UPDATE users SET username = ?, password_hash = ? WHERE id = ?",
      [username, hashedPassword, userId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    // Fetch updated user information
    const [updatedUserRows] = await connection.execute('SELECT * FROM users WHERE id = ?', [userId]);
    const updatedUser = updatedUserRows[0];
    res.json(updatedUser);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "An error occurred while updating user." });
  }
});

// POST route for login
app.post("/login", async function (req, res) {
  try {
    const { username, password } = req.body;
    const connection = await getDBConnection();
    const [rows] = await connection.execute('SELECT * FROM users WHERE username = ?', [username]);
    const user = rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid username or password." });
    }
    const token = generateToken({ username: user.username });
    res.json({ token });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ error: "An error occurred while logging in." });
  }
});

// Server port
const port = 3000;
app.listen(port, () => {
  console.log(`Server is listening on http://localhost:${port}`);
});
