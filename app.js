// app.js
const express = require("express");
const authRoutes = require("./routes/auth");

const app = express();

app.use(express.json());


app.get("/", (req, res) => {
  res.send("Hello, World!");
});

// Use routes
app.use("/api/auth", authRoutes);

module.exports = app;

