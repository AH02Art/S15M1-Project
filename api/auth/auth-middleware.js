const User = require("../users/users-model.js");
/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(request, response, next) {
  console.log("restricted middleware");
  next();
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(request, response, next) {
  try {
    const users = await User.findBy({ username: request.body.username });
    if (!users.length) {
      next();
    } else {
      next({ status: 422, message: "Username taken" });
    }
  } catch(error) {
    next(error);
  } 
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
async function checkUsernameExists(request, response, next) {
  try {
    const users = await User.findBy({ username: request.body.username });
    if (users.length) {
      next();
    } else {
      next({ status: 401, message: "Invalid credentials" });
    }
  } catch(error) {
    next(error);
  } 
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength(request, response, next) {
  console.log("checkPasswordLength middleware");
  next();
}

// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
};