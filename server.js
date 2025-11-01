// server.js - Enhanced with XSS vulnerability for demonstration
// Run: npm install express cors cookie-parser && node server.js

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const path = require("path");

const app = express();
app.use(express.json());
app.use(cookieParser());

// Serve static frontend from /public
app.use(express.static(path.join(__dirname, "public")));

// CORS setup
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}));

// Simple "insecure login" that returns a JSON token
app.post("/api/login-insecure", (req, res) => {
  res.json({ token: "fake-jwt-token-LOCAL-abc123" });
});

// Secure login: set HttpOnly cookie
app.post("/api/login-secure", (req, res) => {
  res.cookie("auth_token", "secure-jwt-token-COOKIE-xyz789", {
    httpOnly: true,
    sameSite: "Strict",
    secure: false, // set to true in production with HTTPS
    maxAge: 60 * 60 * 1000 // 1 hour
  });
  res.json({ message: "HttpOnly cookie set" });
});

// Protected endpoints
app.get("/api/protected-insecure", (req, res) => {
  const auth = req.headers.authorization || "";
  if (auth === "Bearer fake-jwt-token-LOCAL-abc123") {
    return res.json({ message: "Protected (insecure) – Access granted" });
  }
  return res.status(401).json({ error: "Unauthorized (insecure)" });
});

app.get("/api/protected-secure", (req, res) => {
  if (req.cookies && req.cookies.auth_token === "secure-jwt-token-COOKIE-xyz789") {
    return res.json({ message: "Protected (secure) – Access granted" });
  }
  return res.status(401).json({ error: "Unauthorized (secure)" });
});

// ⚠️ VULNERABLE ENDPOINT - For educational demonstration only
// This endpoint is intentionally vulnerable to XSS attacks
app.get("/api/search", (req, res) => {
  const query = req.query.q || "";
  // INSECURE: Directly reflecting user input without sanitization
  res.send(`
    <html>
    <head><title>Search Results</title></head>
    <body>
      <h2>Search Results for: ${query}</h2>
      <p>No results found.</p>
      <a href="/">Back to Home</a>
    </body>
    </html>
  `);
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running → http://localhost:${PORT}`));