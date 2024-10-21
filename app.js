// app.js
const express = require("express");
const authRoutes = require("./routes/auth");
const cors = require('cors');

const app = express();

app.use(express.json());


app.use(cors());

app.get("/", (req, res) => {
  res.send("Hello, World!");
});

// Use routes
app.use("/api/auth", authRoutes);

module.exports = app;

