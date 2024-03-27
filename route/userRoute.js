const express = require("express");
const router = express.Router();
const authMiddleWare = require("../middleware/authMiddleWare");
const { register, login, check } = require("../controller/userController");

router.post("/register", register);
router.post("/login", login);
router.get("/check", authMiddleWare,check);

module.exports = router;
