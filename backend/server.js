require("dotenv").config();

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const path = require("path");

const { query, testDatabase } = require("./db");

const {
  hashPassword,
  comparePassword,
  createToken
} = require("./auth");

const { requireAuth } = require("./middleware");

const app = express();

const PORT = process.env.PORT || 3000;

app.use(
  cors({
    origin: process.env.FRONTEND_URL || true,
    credentials: true
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many authentication attempts. Try again later."
  }
});

app.get("/api/health", async (req, res) => {
  try {
    const database = await testDatabase();

    res.json({
      success: true,
      service: "Synapse API",
      status: "online",
      database: "connected",
      time: database.now
    });
  } catch (error) {
    console.error(error);

    res.status(503).json({
      success: false,
      service: "Synapse API",
      status: "online",
      database: "offline"
    });
  }
});

/*
========================================
REGISTER
========================================
*/

app.post("/api/auth/register", authLimiter, async (req, res) => {
  try {
    let {
      username,
      displayName,
      email,
      password
    } = req.body;

    username = String(username || "")
      .trim()
      .toLowerCase();

    displayName = String(displayName || "").trim();

    email = String(email || "")
      .trim()
      .toLowerCase();

    password = String(password || "");

    if (!username || !displayName || !email || !password) {
      return res.status(400).json({
        error: "All fields are required."
      });
    }

    if (!/^[a-z0-9_]{3,32}$/.test(username)) {
      return res.status(400).json({
        error:
          "Username must be 3-32 characters and contain only letters, numbers and underscores."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        error: "Invalid email address."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must contain at least 8 characters."
      });
    }

    const existing = await query(
      `
      SELECT id
      FROM users
      WHERE username = $1
         OR email = $2
      LIMIT 1
      `,
      [username, email]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "Username or email is already registered."
      });
    }

    const passwordHash = await hashPassword(password);

    const result = await query(
      `
      INSERT INTO users
      (
        username,
        display_name,
        email,
        password_hash,
        status
      )
      VALUES ($1, $2, $3, $4, 'online')
      RETURNING
        id,
        username,
        display_name,
        email,
        avatar_url,
        bio,
        status,
        custom_status,
        created_at
      `,
      [
        username,
        displayName,
        email,
        passwordHash
      ]
    );

    const user = result.rows[0];

    const token = createToken(user);

    res.status(201).json({
      success: true,
      message: "Account created successfully.",
      token,
      user
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      error: "Unable to create account."
    });
  }
});

/*
========================================
LOGIN
========================================
*/

app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const identity = String(
      req.body.identity || ""
    )
      .trim()
      .toLowerCase();

    const password = String(
      req.body.password || ""
    );

    if (!identity || !password) {
      return res.status(400).json({
        error: "Login details are required."
      });
    }

    const result = await query(
      `
      SELECT *
      FROM users
      WHERE username = $1
         OR email = $1
      LIMIT 1
      `,
      [identity]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid username/email or password."
      });
    }

    const user = result.rows[0];

    const valid = await comparePassword(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid username/email or password."
      });
    }

    await query(
      `
      UPDATE users
      SET
        status = 'online',
        last_seen = NOW(),
        updated_at = NOW()
      WHERE id = $1
      `,
      [user.id]
    );

    const token = createToken(user);

    delete user.password_hash;

    res.json({
      success: true,
      message: "Login successful.",
      token,
      user
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      error: "Unable to login."
    });
  }
});

/*
========================================
CURRENT USER
========================================
*/

app.get(
  "/api/auth/me",
  requireAuth,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT
          id,
          username,
          display_name,
          email,
          avatar_url,
          bio,
          status,
          custom_status,
          created_at,
          last_seen
        FROM users
        WHERE id = $1
        `,
        [req.user.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "User not found."
        });
      }

      res.json({
        success: true,
        user: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load profile."
      });
    }
  }
);

/*
========================================
LOGOUT
========================================
*/

app.post(
  "/api/auth/logout",
  requireAuth,
  async (req, res) => {
    try {
      await query(
        `
        UPDATE users
        SET
          status = 'offline',
          last_seen = NOW(),
          updated_at = NOW()
        WHERE id = $1
        `,
        [req.user.id]
      );

      res.json({
        success: true,
        message: "Logged out."
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to logout."
      });
    }
  }
);

/*
========================================
UPDATE PROFILE
========================================
*/

app.patch(
  "/api/users/me",
  requireAuth,
  async (req, res) => {
    try {
      const {
        displayName,
        bio,
        customStatus,
        avatarUrl
      } = req.body;

      const result = await query(
        `
        UPDATE users
        SET
          display_name =
            COALESCE($1, display_name),

          bio =
            COALESCE($2, bio),

          custom_status =
            COALESCE($3, custom_status),

          avatar_url =
            COALESCE($4, avatar_url),

          updated_at = NOW()

        WHERE id = $5

        RETURNING
          id,
          username,
          display_name,
          email,
          avatar_url,
          bio,
          status,
          custom_status,
          created_at,
          last_seen
        `,
        [
          displayName ?? null,
          bio ?? null,
          customStatus ?? null,
          avatarUrl ?? null,
          req.user.id
        ]
      );

      res.json({
        success: true,
        user: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to update profile."
      });
    }
  }
);

/*
========================================
SET STATUS
========================================
*/

app.patch(
  "/api/users/me/status",
  requireAuth,
  async (req, res) => {
    const allowed = [
      "online",
      "idle",
      "dnd",
      "offline"
    ];

    const status = String(
      req.body.status || ""
    ).toLowerCase();

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error: "Invalid status."
      });
    }

    try {
      await query(
        `
        UPDATE users
        SET
          status = $1,
          last_seen = NOW(),
          updated_at = NOW()
        WHERE id = $2
        `,
        [status, req.user.id]
      );

      res.json({
        success: true,
        status
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to update status."
      });
    }
  }
);

/*
========================================
SEARCH USERS
========================================
*/

app.get(
  "/api/users/search",
  requireAuth,
  async (req, res) => {
    try {
      const q = String(
        req.query.q || ""
      )
        .trim()
        .toLowerCase();

      if (q.length < 2) {
        return res.json({
          success: true,
          users: []
        });
      }

      const result = await query(
        `
        SELECT
          id,
          username,
          display_name,
          avatar_url,
          bio,
          status,
          custom_status
        FROM users
        WHERE
          (
            username ILIKE $1
            OR display_name ILIKE $1
          )
          AND id <> $2
        ORDER BY display_name
        LIMIT 20
        `,
        [`%${q}%`, req.user.id]
      );

      res.json({
        success: true,
        users: result.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to search users."
      });
    }
  }
);

/*
========================================
PUBLIC PROFILE
========================================
*/

app.get(
  "/api/users/:username",
  requireAuth,
  async (req, res) => {
    try {
      const username = String(
        req.params.username
      )
        .trim()
        .toLowerCase();

      const result = await query(
        `
        SELECT
          id,
          username,
          display_name,
          avatar_url,
          bio,
          status,
          custom_status,
          created_at,
          last_seen
        FROM users
        WHERE username = $1
        LIMIT 1
        `,
        [username]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "User not found."
        });
      }

      res.json({
        success: true,
        user: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load user."
      });
    }
  }
);

/*
========================================
404
========================================
*/

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API route not found."
  });
});

/*
========================================
ERROR HANDLER
========================================
*/

app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error);

  res.status(500).json({
    error: "Internal server error."
  });
});

/*
========================================
START
========================================
*/

app.listen(PORT, async () => {
  console.log(`
╔════════════════════════════════════╗
║          SYNAPSE SERVER            ║
╠════════════════════════════════════╣
║ API: http://localhost:${PORT}        ║
║ Status: ONLINE                     ║
╚════════════════════════════════════╝
  `);

  try {
    await testDatabase();
    console.log("✓ PostgreSQL connected");
  } catch (error) {
    console.log("✗ PostgreSQL connection failed");
    console.log(
      "  Configure DATABASE_URL before using authentication."
    );
  }
});
