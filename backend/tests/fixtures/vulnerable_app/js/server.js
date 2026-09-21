// Deliberately vulnerable Express app (test fixture, never deploy).
const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");
const app = express();

app.get("/search", (req, res) => {
  db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`); // SQL injection
  res.send("<h1>Results for " + req.query.q + "</h1>"); // reflected XSS
});

app.get("/run", (req, res) => {
  exec("ls " + req.query.dir, (err, out) => res.send(out)); // command injection
});

app.get("/eval", (req, res) => {
  res.json(eval(req.query.expr)); // code injection
});

app.get("/redir", (req, res) => res.redirect(req.query.next)); // open redirect

function hashPassword(p) {
  return crypto.createHash("md5").update(p).digest("hex"); // weak hash
}

const agent = { rejectUnauthorized: false }; // TLS verification disabled

module.exports = { app, hashPassword, agent };
