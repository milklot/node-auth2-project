const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken');
const userModel = require('../users/users-model');

const roleScale = ['student', 'instructor', 'admin'];

const restricted = (req, res, next) => {

  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({
      message: "Token required"
    })
  }
  else {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({
          message: "Token invalid"
        })
      }
      req.token = decoded;
      next();
    })
  }
}

const only = role_name => (req, res, next) => {

  const role = req.token.role_name;

  if (role && roleScale.indexOf(role) < roleScale.indexOf(role_name)) {
    return res.status(403).json({
      message: "This is not for you"
    })
  }
  next();
}


const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body;
  try {
    if (!username) {
      return res.status(401).json({
        message: 'Invalid credentials'
      })
    }
    else {
      const user = await userModel.findBy({username});
      if (!user) {
        return res.status(401).json({
          message: 'Invalid credentials'
        })
      }
      else {
        next();
      }
    }
  }
  catch(err) {
    next(err);
  }
}


const validateRoleName = (req, res, next) => {
  const { role_name } = req.body;
  const trimmedRole = role_name.trim();

  if (!role_name || trimmedRole.length < 1) {
    req.role_name = 'student';
    next();
  }
   else if (trimmedRole.length > 32) {
     return res.status(422).json({
       message: "Role name can not be longer than 32 chars"
     })
   }
   else if (trimmedRole == 'admin') {
     return res.status(422).json({
       message: "Role name can not be admin"
     })
   }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
