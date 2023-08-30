import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const app = express();

mongoose
  .connect("mongodb://127.0.0.1:27017", {
    dbName: "backend",
  })
  .then(() => {
    console.log("Database Connected!");
  })
  .catch((error) => {
    console.log(error);
  });

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

const users = mongoose.model("users", userSchema);

// Setting up the View Engine for the HTML EJS Template
app.set("view engine", "ejs");

// Setting up the Middlewares
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies;

  if (token) {
    const decodedToken = jwt.verify(token, "secretKey");
    req.user = await users.findById(decodedToken._id);
    next();
  } else res.redirect("/login");
};

app.get("/", isAuthenticated, (req, res) => {
  res.render("logout", { name: req.user.name });
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  let user = await users.findOne({ email });

  if (user) return res.redirect("/login");

  const hashedPassword = await bcrypt.hash(password, 10);

  user = await users.create({
    name,
    email,
    password: hashedPassword,
  });

  const token = jwt.sign({ _id: user._id }, "secretKey");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });

  res.redirect("/");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  let user = await users.findOne({ email });

  if (!user) return res.redirect("/register");

  const passwordMatch = await bcrypt.compare(password, user.password);

  if (!passwordMatch)
    return res.render("login", { email, message: "Incorrect Password!" });

  const token = jwt.sign({ _id: user._id }, "secretKey");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });

  res.redirect("/");
});

app.get("/logout", (req, res) => {
  res.cookie("token", null, {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.redirect("/");
});

const portNumber = 5000;
app.listen(portNumber, () => {
  console.log(`App is Running Successfully at Port: ${portNumber}`);
});
