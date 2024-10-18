// app.js
const express = require("express");
const authRoutes = require("./routes/auth");

const app = express();

app.use(express.json()); // for parsing application/json

// Use routes
app.use("/api/auth", authRoutes);

module.exports = app;
