const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const usersModel = require('../users/users-model');

router.post("/register", validateRoleName, async (req, res, next) => {

  const { username, password, role_name } = req.body;
  const currentUser = await usersModel.findBy({username}); // hereerreere

  try {
    // if (currentUser) {
    //   return res.status(401).json({
    //     message: "this username is already taken"
    //   })
    // }
    const hash = await bcrypt.hash(password, 4);

    await usersModel.add({
      username,
      role_name,
      password : hash,
    })
    const newUser = await usersModel.findBy({username});
    res.status(201).json(newUser);
  }
  catch(err) {
    next(err);
  }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.json({
      message: "missing fields"
    })
  }
  try {
    const user = await usersModel.findBy({username});
    const isValid = bcrypt.compare(password, user.password);

    if (!isValid) {
      return res.status(401).json({
        message: "invalid password"
      })
    }

    const token = jwt.sign({
      subject: user.user_id,
      username: user.username,
      role_name: user.role_name
    }, JWT_SECRET);

    res.cookie('token', token)
    res.status(200).json({
      message: `${username} is back!`,
      token: token
    })
  }
  catch(err) {
    next(err);
  }
});

module.exports = router;
