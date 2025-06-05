// jwt-express-server.js
// Serveur Express démontrant l'authentification par JWT + Refresh + Test API
// Installation : npm i express jsonwebtoken dotenv cors async-mutex
// Lancer avec : node jwt-express-server.js

import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const PORT = process.env.PORT || 3000;
const ACCESS_TOKEN_SECRET =
  process.env.ACCESS_TOKEN_SECRET || "changez_cette_clé_access";
const REFRESH_TOKEN_SECRET =
  process.env.REFRESH_TOKEN_SECRET || "changez_cette_clé_refresh";

// --- Données utilisateur en dur (démo) ---
const USER = {
  id: 1,
  username: "Sacha",
  password: "passwordPokedex123", // ⚠️ jamais en clair en prod
  role: "student",
};

// Stockage en mémoire des refresh tokens (DEMO uniquement)
let refreshTokens = [];

const app = express();
app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["POST", "GET", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
app.use(express.json());

/** Génère un access token (expire en 1h) */
function generateAccessToken(user) {
  const payload = {
    sub: user.id,
    username: user.username,
    role: user.role,
  };
  return jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: "1h" });
}

/** Génère un refresh token (expire en 7j) */
function generateRefreshToken(user) {
  const payload = { sub: user.id };
  return jwt.sign(payload, REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
}

// --- Route POST /login → renvoie { accessToken, refreshToken, expiresIn, refreshExpiresIn } ---
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === USER.username && password === USER.password) {
    const accessToken = generateAccessToken(USER);
    const refreshToken = generateRefreshToken(USER);
    refreshTokens.push(refreshToken);
    return res.json({
      accessToken,
      refreshToken,
      expiresIn: 20, // 1h en secondes
      refreshExpiresIn: 7 * 24 * 3600, // 7 jours en secondes
    });
  }
  return res.status(401).json({ message: "Identifiants invalides" });
});

// --- Middleware d’authentification pour endpoints protégés ---
function authenticateJWT(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "Token manquant" });
  const token = authHeader.split(" ")[1];
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err)
      return res.status(403).json({ message: "Token invalide ou expiré" });
    req.user = decoded;
    next();
  });
}

// --- GET /profile (protégé) renvoie le payload et un message ---
app.get("/profile", authenticateJWT, (req, res) => {
  res.json({
    message: "Bienvenue dans la zone protégée !",
    user: req.user,
  });
});

// --- GET /test-data (protégé) : permet de tester un endpoint “de test” ---
app.get("/test-data", authenticateJWT, (req, res) => {
  res.json({
    data: "Voici des données de test protégées.",
    receivedAt: new Date().toISOString(),
    user: req.user, // montrer que le middleware a bien décodé le JWT
  });
});

// --- POST /refresh → { accessToken, expiresIn } ou 403 si refresh invalide/expiré ---
app.post("/refresh", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(400).json({ message: "Refresh token manquant" });
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json({ message: "Refresh token invalide" });
  }
  jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, decoded) => {
    if (err)
      return res
        .status(403)
        .json({ message: "Refresh token expiré ou invalide" });
    if (decoded.sub !== USER.id) {
      return res.status(403).json({ message: "Utilisateur non reconnu" });
    }
    const newAccessToken = generateAccessToken(USER);
    console.log("returning new access token for user:", USER.username);
    return res.json({
      accessToken: newAccessToken,
      expiresIn: 20,
    });
  });
});

// --- POST /logout → supprime le refresh token côté serveur ---
app.post("/logout", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(400).json({ message: "Refresh token manquant" });
  refreshTokens = refreshTokens.filter((t) => t !== refreshToken);
  return res.json({ message: "Déconnexion réussie" });
});

app.listen(PORT, () => {
  console.log(`JWT demo server running on http://localhost:${PORT}`);
});
