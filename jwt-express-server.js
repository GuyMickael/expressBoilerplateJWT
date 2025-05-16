// jwt-express-server.js
// Petit serveur Express minimaliste démontrant l'authentification par JWT
// Installation : npm i express jsonwebtoken dotenv
// Lancer avec : node jwt-express-server.js
import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key_change_me";

// --- Données utilisateur en dur (démo) ---
const USER = {
  id: 1,
  username: "Sacha",
  password: "passwordPokedex123", // ⚠️ pour la démo uniquement. Jamais en clair en prod !
  role: "student",
};

const app = express();
app.use(
  cors({
    origin: "http://localhost:5174", // ou "*" en dev
    methods: ["POST", "GET", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true, // si tu envoies des cookies
  })
);

app.use(express.json());
// Helper : générer un token pour l'utilisateur
function generateToken(user) {
  const payload = {
    sub: user.id,
    username: user.username,
    role: user.role,
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

// --- Route de connexion ---
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Vérification très basique : compare aux valeurs en dur
  if (username === USER.username && password === USER.password) {
    const token = generateToken(USER);
    return res.json({ token });
  }

  return res.status(401).json({ message: "Identifiants invalides" });
});

// Middleware pour sécuriser les routes protégées
function authenticateJWT(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "Token manquant" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Token invalide" });
    req.user = decoded; // infos du payload dispo dans req.user
    next();
  });
}

// --- Exemple de route protégée ---
app.get("/profile", authenticateJWT, (req, res) => {
  // Renvoie les infos du payload + un petit message
  res.json({
    message: "Bienvenue dans la zone protégée !",
    user: req.user,
  });
});

app.listen(PORT, () => {
  console.log(`JWT demo server running on http://localhost:${PORT}`);
});
