
const dbconnection = require("../db/dbconnection");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { StatusCodes } = require("http-status-codes");

async function register(req, res) {
  const { username, firstName, lastName, email, password } = req.body;

  if (!username || !firstName || !lastName || !email || !password) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Please enter values for all fields." });
  }
  if (password.length < 8) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Password should be at least 8 characters long." });
  }

  try {
    const [existingUser] = await dbconnection.query(
      "SELECT username, userid FROM users WHERE username = ? OR email = ?",
      [username, email]
    );

    if (existingUser.length > 0) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "User already exists." });
    }

    const salt = await bcrypt.genSalt(10);
    const encryptedPassword = await bcrypt.hash(password, salt);

    await dbconnection.query(
      "INSERT INTO users (username, firstname, lastname, email, password) VALUES (?, ?, ?, ?, ?)",
      [username, firstName, lastName, email, encryptedPassword]
    );

    return res.status(StatusCodes.CREATED).json({ msg: "User registered successfully." });
  } catch (error) {
    console.log(error.message);
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Something went wrong. Please try again later." });
  }
}

async function login(req, res) {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Please enter values for all fields." });
  }

  try {
    const [user] = await dbconnection.query(
      "SELECT username, userid, password FROM users WHERE email = ?",
      [email]
    );

    if (user.length === 0) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "Invalid user credentials." });
    }

    const isSamePassword = await bcrypt.compare(password, user[0].password);

    if (!isSamePassword) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "Invalid user credentials." });
    }

    const { username, userid } = user[0];

    const token = jwt.sign({ username, userid }, process.env.JWT_SECRET, {
      expiresIn: "30d",
    });

    return res
      .status(StatusCodes.OK)
      .json({ msg: "User logged in successfully.", token, username, userid });
  } catch (error) {
    console.log(error.message);

    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Something went wrong. Please try again later." });
  }
}

async function check(req, res) {
  const { username, userid } = req.user;

  return res
    .status(StatusCodes.OK)
    .json({ msg: "Access granted.", username, userid });
}

module.exports = { register, login, check };