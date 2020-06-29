const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');
var tokens = require(path.join(__dirname, '../tokens'));

const loginRedirect = async (request, response, next) => {
  try {
    console.log(request.url)
    if (request.cookies === undefined || request.cookies.access_token === undefined) {
      console.log('loginRedirect: user not logged in')
      next();
      return;
    }
    const token = request.cookies.access_token;
    const decoded = jwt.verify(token, process.env.JWT_SECRET.toString());
    //send back user id & tokens array if verified
    const user = await tokens.returnIdTokensKVP(decoded._id);
    if (!user) {
      throw new Error();
    }
    request.token = token;
    request.user = user;
    //if auth redirect to index
    response.redirect('index');
  } catch (e) {
    next();
    return
  }
};

module.exports = loginRedirect;
