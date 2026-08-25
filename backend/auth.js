const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.warn(
    "WARNING: JWT_SECRET is not configured."
  );
}

async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

async function comparePassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function createToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function createRandomToken() {
  return crypto.randomBytes(48).toString("hex");
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

module.exports = {
  hashPassword,
  comparePassword,
  createToken,
  verifyToken,
  createRandomToken,
  hashToken
};
