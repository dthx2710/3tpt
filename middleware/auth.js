const jwt = require('jsonwebtoken');
const path = require('path')
const cookieParser = require('cookie-parser');
var tokens = require(path.join(__dirname, '../tokens'));

const auth = async (request, response, next) => {
  try{
    if (request.cookies === undefined || request.cookies.access_token === undefined){
      console.log('Auth: Not logged in. cookie:',request.cookies);
      // response.redirect('../views/login');
      console.log('Redirecting to login')
      response.redirect('login');
      return
    }
    const token = request.cookies.access_token;
    const decoded = jwt.verify(token, process.env.JWT_SECRET.toString())
    //send back user id & tokens array if verified
    const user = await tokens.returnIdTokensKVP(decoded._id);
    if (!user){
      throw new Error()
    }
    request.token=token;
    request.user=user;
    console.log(request.url)
    console.log('Authorized');
    next();
  }
  catch (e){
    console.log(e);
    //response.status(401).send({error:'Not logged in.' });
    console.log('Auth error: Not logged in');
    response.redirect('login');
  }
}

module.exports = auth;