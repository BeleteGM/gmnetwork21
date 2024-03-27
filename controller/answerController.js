
const dbConnection = require("../db/dbconnection");
const { StatusCodes } = require("http-status-codes");
// add answers to the database
const addAnswer = async (req, res) => {
  const { questionid, userid, answer } = req.body;
  
  if (!answer) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "please fill the answer field" });
  }
  try {
    await dbConnection.query(
      `INSERT INTO answers (questionid, userid, answer) VALUES (?, ?, ?) `,
      [questionid, userid, answer]
    );

    return res
      .status(StatusCodes.CREATED)
      .json({ msg: "answer added successfully" });
  } catch (error) {
    console.log(error.message)
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Something went wrong, please try again" });
  }
};




async function getAnswer(req, res) {
  try {
    const { questionid } = req.params;
    console.log(questionid)

    const [answers] = await dbConnection.query(
      `SELECT answers.answer, users.username FROM answers INNER JOIN users ON answers.userid = users.userid
            WHERE answers.questionid = ?`,
      [questionid]
    );
    if (answers.length > 0) {
      return res.status(StatusCodes.OK).json({ answers });
    } else {
      return res
        .status(StatusCodes.NOT_FOUND)
        .json({ msg: "no answers found" });
    }
  } catch (error) {
    console.log(error);
    res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Something went wrong while fetching answers" });
  }
}


module.exports = { addAnswer, getAnswer };
