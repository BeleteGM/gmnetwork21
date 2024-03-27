// const dbconnection = require("../db/dbconnection");
// const { StatusCodes } = require("http-status-codes");

// async function addAnswer(req, res) {
//   const { answer } = req.body;
//   const { userid } = req.user;
  
//   if (!answer) {
//     return res
//       .status(StatusCodes.BAD_REQUEST)
//       .json({ msg: "No answer posted" });
//   }

//   try {
//     // Retrieve the question ID from the database
//     const [question] = await dbconnection.query(
//       `SELECT questionid FROM questions WHERE questionid = ?`,
//       [req.params.questionid]
//     );

//     if (!question.length==0) {
//       return res
//         .status(StatusCodes.NOT_FOUND)
//         .json({ msg: "Question not found" });
//     }

//     await dbconnection.query(
//       `INSERT INTO answers (userid, questionid, answer) VALUES (?, ?, ?)`,
//       [userid, req.params.questionid, answer]
//     );

//     return res.json("Answer added");
//   } catch (error) {
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "Something went wrong, please try again later" });
//   }
// }
// const dbconnection = require('../db/dbconnection');
// const { StatusCodes } = require('http-status-codes');
// async function addAnswer(req, res) {
//   try {
//     const { answer, questionid } = req.body;
//     const userid = req.user.userid; // Assuming user ID is extracted from authentication token
// console.log(userid, answer, questionid)
//     console.log("Received request with body:", req.body);

//     // if (!answer  !questionId) {
//     //   // Ensure questionId is provided
//     //   return res.status(StatusCodes.BAD_REQUEST).json({
//     //     error: "Please provide both answer and question ID",
//     //   });
//     // }

//     // Check if the question exists
//     const [question] = await dbconnection.query(
//       "SELECT * FROM questions WHERE questionid = ?",
//       [questionid]
//     );

//     // Ensure the question exists
//     // if (!question  question.length === 0) {
//     //   return res
//     //     .status(StatusCodes.NOT_FOUND)
//     //     .json({ error: "Question not found" });
//     // }

//     // Insert the answer into the database
//     const result = await dbconnection.query(
//       "INSERT INTO answers (answer, userid, questionid) VALUES (?, ?, ?)",
//       [answer, userid, questionid]
//     );

//     console.log("Inserted answer:", result);

//     return res
//       .status(StatusCodes.CREATED)
//       .json({ message: "Answer added successfully" });
//   } catch (error) {
//     console.error("Error adding answer:", error);
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ error: "Internal Server Error" });
//   }
// }

// // async function addAnswer(req, res) {
//   const { answer,questionid } = req.body;
 

  
//   const { userid } = req.user;
//   const { username } = req.user;
// console.log(questionid, userid, username)
//   if (!answer) {
//     return res
//       .status(StatusCodes.BAD_REQUEST)
//       .json({ msg: "Provide answer field" });
//   }

//   try {
//     const uniqueId = await dbconnection.query(
//       "SELECT questionid FROM questions WHERE id = ?",
//       [id]
//     );
//     const questionid = uniqueId[0][0].questionid;

//     // console.log(questionid , "hhhhhh");

//     // if (duplicateAnswer.length > 0) {
//     //   return res.status(StatusCodes.BAD_REQUEST).json({
//     //     msg: "You have already posted an answer for this question",
//     //   });
//     // }

//     await dbconnection.query(
//       "INSERT INTO answers (userid, questionid, answer) VALUES (?, ?, ?)",
//       [userid, questionid, answer]
//     );
//     // console.log(id, "lllllllllllllll");

//     return res
//       .status(StatusCodes.OK)
//       .json({ msg: "Answer posted successfully" });
//   } catch (error) {
//     console.log(error.message);
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "Something went wrong. please try again later" });
//   }
// }



// const addAnswer = async (req, res) => {
//     const { questionid, answer } = req.body

//     const userid = req.user.userid

//     // const answerid = uuidv4()
//     console.log( questionid, answer, userid)

//     if (!questionid || !answer) {
//         return res.status(StatusCodes.BAD_REQUEST).json({
//             error: 'Please provide answer'
//         })
//     }

//     try {
        

//         await dbconnection.query('INSERT INTO answers (questionid, answer, userid) VALUES (?, ?, ?)', [ questionid, answer, userid])
        
//         return res.status(StatusCodes.CREATED).json({ msg: 'answer posted successfully' })
//     } catch (error) {
//         console.log(error.message)
//         return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: "Some error occurred. Please try again" })
//     }
// }
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



// async function getAnswer(req, res) {
//   const { id } = req.params;
//   // console.log(id);

//   //const questionid = req.params.questionid;
//   // const { questionid } = req.body;
//   try {
//     const uniqueId = await dbConnection.query(
//       "SELECT questionid FROM questions WHERE id = ?",
//       [id]
//     );

//     const questionid = uniqueId[0][0].questionid;
//     console.log(questionid);
//     const [answer] = await dbconnection.query(
//       "SELECT answer, answers.userid,username From answers INNER JOIN users ON answers.userid = users.userid WHERE questionid = ? ORDER BY answers.answerid DESC",
//       [questionid]
//     );
//     // console.log(questionid, "ddddddddddddd");

//     return res.status(StatusCodes.OK).json(answer);
//   } catch (error) {
//     console.error(error.message);
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "Something went wrong, please try again later" });
//   }
// }
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
