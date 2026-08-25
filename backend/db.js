const { Pool } = require("pg");
require("dotenv").config();

if (!process.env.DATABASE_URL) {
  console.warn("DATABASE_URL is not configured.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

pool.on("error", (error) => {
  console.error("Unexpected PostgreSQL error:", error);
});

async function query(text, params = []) {
  return pool.query(text, params);
}

async function testDatabase() {
  const result = await query("SELECT NOW() AS now");
  return result.rows[0];
}

module.exports = {
  pool,
  query,
  testDatabase
};
