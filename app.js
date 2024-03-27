const express = require("express");
const dotenv= require('dotenv');
const bodyparser = require("body-parser");
const cors= require('cors');
dotenv.config();
const app = express();
app.use(cors())
app.use(bodyparser.urlencoded({ extended: true }));
const port = 5000;
const dbconnection = require("./db/dbconnection");

const userRoute = require("./route/userRoute");
const questionRoute = require("./route/questionRoute");
const answerRoute = require("./route/answerRoute");
app.use(express.json());

app.use("/api/user", userRoute);
app.use("/api/question", questionRoute);
app.use("/api/question", answerRoute);

async function start() {
  try {
    const result = await dbconnection.execute("select 'test'");
    app.listen(port);
    console.log("DB connection established");
    console.log(`listening on port  http://localhost:${port}`);
  } catch (err) {
    console.log(err.message);
  }
}
start();
