var tokensArray=[
  // {
  //   'Id':'testId',
  //   'tokens':[123123,123123]
  // },
]

//add token to tokensArray (e.g. login)
function addToken(id, token){
  var id = parseInt(id);
  try{
    //id has existing token
    var exists = false;
    tokensArray.forEach(function(kvp){
      if (kvp.Id === id){
        kvp.tokens.push(token);
        exists = true;
        return
      }
    })
    //new id-token kvp
    if (!exists){
      var newKVP = {'Id':id,'tokens':[token]};
      tokensArray.push(newKVP);
      console.log('New token: '+token+' added to Id:'+id+'.');
    }
    console.log(tokensArray);
  }
  catch(e){
    console.log(e);
  }
}


//remove token from tokensArray (e.g. logout)
function removeToken(id, token){
  var id = parseInt(id);
  try{
    tokensArray.forEach(function(kvp){
      if (kvp.Id === id){
        kvp.tokens.forEach(function(kvpToken){
          if (kvpToken === token){
            var tokenIndex = kvp.tokens.indexOf(token);
            if (tokenIndex > -1){
              kvp.tokens.splice(tokenIndex, 1);
            }
            //kvp.tokens = kvp.tokens.filter(kvpToken!==token);
          }
        })
        //remove entry if no tokens left
        if (kvp.tokens === undefined || kvp.tokens.length == 0){
          var kvpIndex = tokensArray.indexOf(kvp);
            if (kvpIndex > -1){
              tokensArray.splice(kvpIndex, 1);
            }
          //tokensArray.filter(kvp=>!kvp);
        }
      }
    })
  }
  catch(e){
    console.log(e);
  }
}

function returnTokensOfId(id){
  var id = parseInt(id);
  var tokensofid=[];
  try{
    tokensArray.forEach(function(kvp){
      if (kvp.Id === id){
        //return tokens as Array object
        tokensofid= kvp.tokens;
      }
    })
    return tokensofid;
  }
  catch(e){
    console.log(e);
    return false;
  }
}

function returnIdTokensKVP(id){
  var id = parseInt(id);
  try{
    var kvp1={};
    tokensArray.forEach(function(kvp){
      if (kvp.Id === id){
        //return IdTokens KVP
        kvp1=kvp;
      }
    })
    return kvp1;
  }
  catch(e){
    console.log('error in returning token'+e);
    return false;
  }
}

function returnIdOfToken(token){
  var token = parseInt(token);
  var id = false;
  try{
    tokensArray.forEach(function(kvp){
      kvp.tokens.forEach(function(kvptoken){
        if (token===kvptoken){
          id = kvp.Id;
        }
      })
    })
    return id;
  }
  catch(e){
    console.log(e);
    return false;
  }
}

module.exports = {tokensArray, addToken, removeToken, returnTokensOfId, returnIdTokensKVP, returnIdOfToken};