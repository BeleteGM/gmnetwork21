const dbconnection = require("../db/dbconnection");
const { StatusCodes } = require("http-status-codes");
const { v4: uuidv4 } = require("uuid");

async function askQuestion(req, res) {
  const { title, description } = req.body;
  const questionid = uuidv4();
  //  console.log(questionid);
  //user id extracted from authMiddleware
  const userid = req.user.userid;
  //   console.log(userid);
  if (!title || !description) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "please enter all the required fields" });
  }
  try {
    await dbconnection.query(
      "INSERT INTO questions(questionid,userid,title,description) VALUES(?,?,?,?)",
      [questionid, userid, title, description]
    );
    return res
      .status(StatusCodes.CREATED)
      .json({ msg: "question posted successfully" });
  } catch (error) {
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "something went wrong, please try again later" });
  }
}
async function allQuestion(req, res) {
  try {
    const [questions] = await dbconnection.query(`SELECT q.*, u.username 
    FROM questions q 
    INNER JOIN users u ON q.userid = u.userid 
    ORDER BY q.id DESC `);
    if (questions.length == 0) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "please enter all the required fields" });
    }
    return res.status(StatusCodes.OK).json({ questions });
  } catch (error) {
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "something went wrong, please try again later" });
  }
}
async function singleQuestion(req, res) {
  const { questionid } = req.params;
  try {
    const query = `SELECT * FROM questions WHERE questionid = ?`;
    const [question] = await dbconnection.query(query, [questionid]);

    if (question.length == 0) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "please enter all the required fields" });
    }
    return res.status(StatusCodes.OK).json({question});
  } catch (error) {
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "something went wrong, please try again later" });
  }
}

module.exports = { askQuestion, allQuestion, singleQuestion };
