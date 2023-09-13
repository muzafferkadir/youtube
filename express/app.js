require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const HOST = process.env.HOST || "localhost";
const PORT = process.env.PORT || 3000;

const mongoDB = process.env.DATABASE_URL;
mongoose.connect(mongoDB, { useNewUrlParser: true, useUnifiedTopology: true });

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));

app.use("/user", require("./routes/user"));
app.use("/post", require("./routes/post"));

app.listen(PORT, HOST, () => {
	console.log(`Server running at http://${HOST}:${PORT}/`);
});

module.exports = app;