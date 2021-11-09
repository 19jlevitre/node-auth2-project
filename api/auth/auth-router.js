const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs');
const { tokenBuilder } = require('../../api/auth/token-builder');
const User = require('../users/users-model.js');


router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body;
  const rounds = 8
  const hash = bcrypt.hashSync(user.password, rounds)
  user.password = hash
  User.add(user)
    .then(users => {
      console.log(users)
      return res.status(201).json(users)
    }).catch(next);


  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  try {
    const user = req.body
    const token = tokenBuilder(user)
    return res.status(200).json({ message: `${user.username} is back`, token })
  } catch {
    next()
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
