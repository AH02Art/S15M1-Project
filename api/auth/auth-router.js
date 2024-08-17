// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require("express").Router();
const User = require("../users/users-model.js");
const bcrypt = require("bcryptjs");
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
} = require("./auth-middleware.js");
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post(
    "/register", 
    checkUsernameFree, 
    checkPasswordLength, 
    function(request, response, next) {
      const { username, password } = request.body;
      const hash = bcrypt.hashSync(password, 8); // 2 ^ 10

      User.add({ username, password: hash })
        .then(function(stuff) {
          response.status(201).json(stuff);
        })
        .catch(next);
    }
)


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post("/login", checkUsernameExists, function(request, response, next) {
  const { password } = request.body;
  if (bcrypt.compareSync(password, request.user.password)) {
    // making it so that the cookie is set on the client
    // making it so server stores a session with a session id
    request.session.user = request.user;
    response.json({ message: `Welcome ${request.user.username}!` })
  } else {
    next({ status: 401, message: "Invalid credentials" });
  }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get("/logout", function(request, response, next) {
  response.json("logout");
})

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;