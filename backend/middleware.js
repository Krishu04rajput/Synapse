const { verifyToken } = require("./auth");

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  const token = authHeader.substring(7);

  try {
    const payload = verifyToken(token);

    req.user = {
      id: payload.sub,
      username: payload.username
    };

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired authentication token."
    });
  }
}

module.exports = {
  requireAuth
};
