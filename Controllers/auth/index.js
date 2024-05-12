const passport = require("passport");
const register = require("./register");
const login = require("./login");
var  blacklist=[];
const userRegister = (userRequest, role, res) =>
  register(userRequest, role, res);

const userLogin = (userRequest, role, res) => login(userRequest, role, res);

const logout =(token,res)=>{
  blacklist.push(token);
  res.status(200).json({ message: 'Token invalidated' });
}
const userAuth = passport.authenticate("jwt", { session: false });
 
const checkToken = () => (req, res, next) => {
  
  const token = req.headers.authorization;
  
  if (blacklist.includes(token)) {
    return res.status(401).json({ message: 'Invalid token' });
  }
  next();
};

const checkRole = (roles) => (req, res, next) => {
  !roles.includes(req.user.role)
    ? res.status(401).json("Unauthorized")
    : next();
};

/**
 * returns json of user data.
 * @const serializeUser
 */
const serializeUser = (user) => {
  return {
    username: user.username,
    email: user.email,
    name: user.name,
    updatedAt: user.updatedAt,
    createdAt: user.createdAt,
  };
};

module.exports = {
  userAuth,
  userLogin,
  userRegister,
  checkRole,
  checkToken,
  logout,
  serializeUser,
};
