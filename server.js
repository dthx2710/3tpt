'use strict';

//SYS Imports
const path = require('path');
const crypto = require('crypto');
const sha256 = require('js-sha256').sha256;
const fs = require('fs');

//HTTP Imports
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const auth = require(path.join(__dirname, '/middleware/auth'));
const loginRedirect = require(path.join(__dirname, '/middleware/loginRedirect'));
const tokens = require(path.join(__dirname, '/tokens'));

// // Trying out Sequelize (small brain gotta use ORM pepehands https://www.youtube.com/watch?v=ya1fwxnmlQs)
// const Sequelize = require('sequelize');
// // setup a new database
// // using database credentials set in .env
// var sequelize = new Sequelize('database', process.env.DB_USER, process.env.DB_PASS, {
//   host: '0.0.0.0',
//   dialect: 'sqlite',
//   pool: {
//     max: 5,
//     min: 0,
//     idle: 10000
//   },
//     // Security note: the database is saved to the file `database.sqlite` on the local filesystem. It's deliberately placed in the `.data` directory
//     // which doesn't get copied if someone remixes the project.
//   storage: '.data/database.sqlite'
// });

// var users =[];
// var User;




const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.set('trust proxy', true); // <- required

// http://expressjs.com/en/starter/static-files.html
const publicDirectoryPath = path.join(__dirname, '/public');
app.use(express.static(publicDirectoryPath));
// serve qrcode module
app.use("/qrcode.min.js", express.static(path.join(__dirname, '/node_modules/qrcode/build/qrcode.min.js')));
 

// init database.sqlite
const dbFile = __dirname+'/db/database.sqlite';
const exists = fs.existsSync(dbFile);
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(dbFile, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE);

// store temp rac data
var tempClientDataStore = {};

// if (!exist'CREATE TABLE Users (Id INTEGER PRIMARY KEY, username Varchar NOT NULL, password Varchar, salt Varchar, rank Varchar, name Varchar, birthdate INTEGER, shortnric Varchar, node Varchar, isadmin INTEGER)');
//if database.sqlite does not exist, create it, otherwise print records to console
// if database.sqlite does not exist, create it, otherwise print records to console
db.serialize(function(){
  SQLGet('SELECT * FROM sqlite_master WHERE type="table" AND name="Users"')
  .then((row) => {
    if(row === undefined){
      console.log('Creating Users Table');
      // console.log('New table Users created!');
      return SQLRun('CREATE TABLE Users (Id INTEGER PRIMARY KEY, username Varchar NOT NULL, password Varchar, salt Varchar, name Varchar, birthdate INTEGER, shortnric Varchar, node Varchar, isadmin INTEGER)');
    }
  })
  .catch((err)=>console.log("Error: "+err))
  // .then(SQLGet('SELECT * FROM sqlite_master WHERE type="table" AND name="Details"'))
  // .then((err, row) => {
  //   if(row === undefined){
  //     console.log('Creating Details Table');
  //     return SQLRun('CREATE TABLE Details (Id INTEGER PRIMARY KEY, userid INTEGER, startdate TEXT, name Varchar, vehicle Varchar, FOREIGN KEY (userid) REFERENCES Users(Id))');
  //   }
  // })
  .then(SQLGet('SELECT * FROM sqlite_master WHERE type="table" AND name="Rac"'))
  .then((row) => {
    if(row === undefined){
      console.log('Creating Rac Table');
      return SQLRun('CREATE TABLE Rac (Id INTEGER PRIMARY KEY, userid INTEGER, timestamp DATETIME, detailid INTEGER, journeyfrom Varchar, journeyto Varchar, vehno, avidate Varchar, risk Varchar, drvexperience Varchar, vehtype Varchar, fatigue Varchar, health Varchar, weather Varchar, familiarity Varchar, mission Varchar, novcom Varchar, servicibility Varchar, officername Varchar, officermitigation Varchar, vcomname Varchar, vcommitigation Varchar, dpname Varchar, dptime Varchar, tochecklist Varchar, vcomchecklist Varchar, FOREIGN KEY (userid) REFERENCES Users(Id))');
      // console.log('New table Rac created!');
    }
  })
   .catch((err)=>console.log("Error: "+err))
  // .then(SQLGet('SELECT * FROM sqlite_master WHERE type="table" AND name="Rac"'))
  // .then((err, row) => {
  //   if(row === undefined){
  //     console.log('Creating Rac Table');
  //     return SQLRun('CREATE TABLE Rac (Id INTEGER PRIMARY KEY, userid INTEGER, FOREIGN KEY (userid) REFERENCES Users(Id))');
  //   }
  // })
  .then(() => {
    if (!exists) {
      db.run('INSERT INTO Users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);', 1, 'admin', sha256('admintest'+'abcd'), 'abcd', 'ADMIN', '010190', '123a', 'cln', 1)
      .run('INSERT INTO Users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);', 2, 'UserA', sha256('password'+'12a'), '12a', 'UserA', '010190', '123a', 'cln', 0)
      .run('INSERT INTO Users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);', 3, '11082840', '5704966058ac4ce546c8a62f551b0f75f19bb6fce9135f3d70c7fef9624ee06e', '256b53ddbca6948ff3a3e18d310e3dcf0fa639d1f226dc785042c8b9fe34ef58', 'Dylan Tok Hong Xun', '271098', '356i', 'cln', 0)
      .run('INSERT INTO Users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);', 4, 'sharpie', sha256('password'+'abcd'), 'abcd', 'ZH HO', '010198', '123a', 'cln', 0);

      /*
      db.run('INSERT INTO Users (username, password, salt, rank, name, birthdate, shortnric, node) VALUES ("admin", "'+sha256('admintest'+'abcd')+'", "abcd","","","","","","1"), ("UserA", "'+sha256('password'+'efgh')+'", "efgh","","","","","","1"), ("11082840","5704966058ac4ce546c8a62f551b0f75f19bb6fce9135f3d70c7fef9624ee06e","256b53ddbca6948ff3a3e18d310e3dcf0fa639d1f226dc785042c8b9fe34ef58"+"LCP","Dylan Tok Hong Xun","271098","356i","cln","0")');*/
      console.log('Users data inserted!');

      // //insert details testdata
      // db.run('INSERT INTO Details (id, userid, startdate, name, vehicle) VALUES ("1","3","271019","Sembawang Wharves","PSV"),("2","3","311019","Sembawang Wharves","PSV"),("3","2","011119","9SIR Outfield","5Ton")');
      // console.log('Details data inserted!');
    }
    else {
      console.log('Database "Users" ready to go!');
      console.log('Database "Rac" ready to go!');
      /*db.each('SELECT * from Users', function(err, row) {
        if ( row ) {
          console.log('record:', row);
        }
        else if (err){
          console.log(err);
        }
      });*/

      //console.log('Database "Details" ready to go!');
      /*db.each('SELECT * from Details', function(err, row) {
        if ( row ) {
          console.log('record:', row);
        }
        else if (err){
          console.log(err);
        }
      });*/
    }
  });
});


// // Trying out Sequelize - default
// sequelize.authenticate()
//   .then(function(err) {
//     console.log('Connection has been established successfully.');
//     // define a new table 'users'
//     User = sequelize.define('users', {
//       firstName: {
//         type: Sequelize.STRING
//       },
//       lastName: {
//         type: Sequelize.STRING
//       }
//     });
    
//     setup();
//   })
//   .catch(function (err) {
//     console.log('Unable to connect to the database: ', err);
//   });

// // populate table with default users
// function setup(){
//   User.sync({force: true}) // We use 'force: true' in this example to drop the table users if it already exists, and create a new one. You'll most likely want to remove this setting in your own apps
//     .then(function(){
//       // Add the default users to the database
//       for(var i=0; i<users.length; i++){ // loop through all users
//         User.create({ firstName: users[i][0], lastName: users[i][1]}); // create a new entry in the users table
//       }
//     });  
// }


//Routing

//Maintenance
// app.use((request, response, next) =>{
//   response.status(503).send('Site is under maintenance.');
// })


// app.get('/blank', auth, function(request,response){
//   response.sendFile(__dirname + '/views/blank.html');
// })

// Helps force HTTPS
app.use((req, res, next) => {
  if(!req.secure) return res.redirect('https://' + req.get('host') + req.url);
  next();
});

app.get('/uptime', function(request,response){
  response.status(200).send("OK");
  console.log('Uptime Robot Ping');
});

app.get('/login', loginRedirect, function(request,response){
  console.log(request.protocol);
  response.sendFile(__dirname + '/views/login.html');
});

//Login
app.post('/login', function(request, response){
  const username = request.body.username;
  const pwd = request.body.password;
  
  if(username === undefined || pwd === undefined || username === '' || pwd === ''){
    response.status(400).redirect('/login');
    console.log('Login validation');
    return;
  }
  
  //Perform SQL request
  db.get('SELECT salt FROM Users WHERE username = ?', [username], (err, row) => {
    if(err || row === undefined){
      response.status(400).redirect('/login?err=1'); //No user with the username found
      console.log('Username wrong');
      return;
    }
    //auth
    db.get('SELECT Id FROM Users WHERE username = ? AND password = ?', [username, sha256(pwd + row.salt)], (err, row2) => {
      if(err || row2 === undefined){
        response.status(400).redirect('/login?err=1'); //Wrong password
        console.log('Pw wrong');
        return;
      }
      const token = generateAuthToken(row2.Id);
      tokens.addToken(row2.Id,token);
      //response.status(200).json({'username': username, 'id': row2.Id, 'token': token});
      console.log('token created');
      response.status(201).cookie('access_token', token, {}).redirect(302,'/index');
      console.log('cookie created, redirecting...');
    });
  });
});

//logout
app.get('/logout', auth, async(request,response) => {
  try{
    const userId = request.user.Id;
    const userToken = request.token;
    //remove token from tokenarray
    tokens.removeToken(userId,userToken);
    response.clearCookie('access_token', {}).redirect(302,'/login');
    console.log(tokens.tokensArray);
    console.log("logged out");
  }
  catch (e){
    response.status(500).send();
  }
});

app.get('/me.json', auth, async function(request, response){
  try{
    const token = request.cookies.access_token;
    const id = parseInt(await jwt.verify(token, process.env.JWT_SECRET.toString())._id);
    db.get('SELECT * FROM Users WHERE Id = ?', [id], (err, row) => {
      if(err || row === undefined){
        response.status(404).json({error: 'Not Found'});
      }else{
        //Add more user data here to be passed in later on
        var userData = {
          "id":id,
          "username":row.username,
          "name":row.name,
          "node":row.node,
          "isadmin":row.isadmin
        };
        console.log(userData);
        response.status(200).json(userData);
      }
    })
  }catch (e){
    console.log(e);
    response.status(400).json({error:'Bad Request' });
  }
});

app.get('/users/:userId/rac', auth, async function(request, response){
  try{
    const userId = request.params.userId;
    let dataArray = [];
    //check if admin
    db.get('SELECT isadmin, username FROM Users WHERE Id = ?', [userId], (err, row) => {
      if(err || row === undefined){
        response.status(404).send('Not Found');
      }
      else{
        //
        let isadmin = row.isadmin;
        let username = row.username
        //if is admin, show all, if not, show to detail
        if (isadmin){
          console.log('hi admin')
          db.all('SELECT Id, timestamp, detailid, vehno, risk, officername FROM Rac ORDER BY timestamp DESC', (err, rows) => {
          if(err || rows == undefined || rows == null || rows=={}){
            response.status(404).send('Not Found');
          }
          else{
            rows.forEach(function(row){
              const timestamp = new Date(parseInt(row.timestamp))
              const dtf = new Intl.DateTimeFormat('en-GB', { year: 'numeric', month: '2-digit', day: '2-digit' })
              const [{ value: mo },,{ value: da },,{ value: ye }] = dtf.formatToParts(timestamp)
              const formattedTS = `${da}/${mo}/${ye}`
              var riskData = row.risk
              // if (!row.officerrank&&!row.vcomrank&&!row.dprank){
              if (!row.officername){
                riskData = "Not Assessed"
              }
              const riskMapping = {'Low':0,'Medium':1,'High':2,'No Move':3,'Not Assessed':4}
              const riskIndex = riskMapping[riskData]
              
              var data = {
                'Id': row.Id,
                'timestamp': row.timestamp,
                'formattedTS': formattedTS,
                'detailid': row.detailid,
                'vehno': 'MID '+ row.vehno,
                'risk': riskData,
                'riskindex': riskIndex
              }
              dataArray.push(data);
            })
            //assign rac to array and pass back
            console.log('Loading table with data: '+dataArray);
            response.status(200).send(dataArray);
            return;
          }
        })
        }
        //if user
        else{
          console.log('hi user')
          db.all('SELECT Id, timestamp, detailid, vehno, risk, officername FROM Rac WHERE userid = ? ORDER BY timestamp DESC', [username], (err, rows) => {
            if(err || rows === undefined || rows == null){
              response.status(404).send('Not Found');
            }
            else{
              rows.forEach(function(row){
                const timestamp = new Date(parseInt(row.timestamp))
                const dtf = new Intl.DateTimeFormat('en-GB', { year: 'numeric', month: '2-digit', day: '2-digit' })
                const [{ value: mo },,{ value: da },,{ value: ye }] = dtf.formatToParts(timestamp)
                const formattedTS = `${da}/${mo}/${ye}`
                
                var riskData = row.risk
                // if (!row.officerrank&&!row.vcomrank&&!row.dprank){
                if (!row.officername){
                  riskData = "Not Assessed"
                }
                const riskMapping = {'Low':0,'Medium':1,'High':2,'No Move':3,'Not Assessed':4}
                const riskIndex = riskMapping[riskData]
                
                var data = {
                  'Id': row.Id,
                  'timestamp': row.timestamp,
                  'formattedTS': formattedTS,
                  'detailid': row.detailid,
                  'vehno': 'MID '+ row.vehno,
                  'risk': riskData,
                  'riskindex': riskIndex
                }
                dataArray.push(data);
              })
              //assign rac to array and pass back
              console.log('Loading table with data: '+dataArray);
              response.status(200).send(dataArray);
              return;
            }
          })
        }
      }
    })
    //ORDER BY DATE, LATEST TO OLDEST
  }catch (e){
    console.log(e);
    response.status(400).send('Bad Request');
  }
});

app.get('/users/:userId/rac/:racId', auth, async function(request, response){
  try{
    const userId = request.params.userId;
    const racId = request.params.racId;
    let rac = {};
    db.get('SELECT * FROM Rac WHERE Id=?', [racId], (err,row)=>{
      if(err || row === undefined){
        response.status(404).send('Not Found');
      }
      else{
        let userid = row.userid
        if (userId == userid || userId == 'admin'){
          rac = row
          console.log('Sending RAC '+row.Id+' for viewing: '+rac);
          response.status(200).send(rac);
          return
        }
        else{
          response.status(404).send('Not Found');
        }
      }
    })
  }catch (e){
    console.log(e);
    response.status(400).send('Bad Request');
  }
})

app.get('/user/:userId/:parameter', async function(request, response){
  try{
    const username = request.params.userId;
    const param = request.params.parameter;
    const query = `SELECT ${param} FROM Users WHERE username=?`
    db.get(query,[username], (err,row)=>{
      if(err || row === undefined){
        console.log('cannotfindla')
        response.status(404).send('Not Found');
      }
      else{
        console.log('found: ',row)
        response.status(200).send(row);
        return
      }
    })
  }catch(e){
    console.log(e);
    response.status(400).send('Bad Request')
  }
})

app.get('/qrcode/:usertype/:racId/:timestamp', (req, res) => {
  try{
    const usertype = req.params.usertype;
    var racid = req.params.racId;
    const timestamp = req.params.timestamp;
    
    const mainPage = fs.readFileSync(__dirname + '/views/qr.html').toString('utf8');
    

    db.get('SELECT * FROM Rac WHERE Id = ?', [racid], (err, row) => {
      if(err || row === undefined){
        res.status(404).json({error: 'Not Found'});
      }else{
        //Add more user data here to be passed in later on
        let jsonData = {
          "rac": row,
          "usertype":usertype,
          "timestamp":timestamp
        }

        console.log(usertype);
         console.log(tempClientDataStore)
        tempClientDataStore[racid][['officer','vcom','dp'][usertype-1]]["scanned"] = true;
        let data = `<script> var data = ${JSON.stringify(jsonData)}; </script>`;
        res.status(200).send(mainPage + data);
      }
    })
  }catch (e){
    console.log(e);
    res.status(400).send({error:'Bad Request' });
  }
});

app.post('/qrreply/:usertype/:racId/:timestamp', (req, res) => {
  try{
    const usertype = req.params.usertype
    var racid = req.params.racId
    const timestamp = req.params.timestamp
    const reply = req.body;
    const {name, mitigation, time, alsovcom, checklist} = reply
    if(alsovcom){
      tempClientDataStore[racid]['vcom'] = reply;
      tempClientDataStore[racid]['officer'] = reply;
    }
    else{tempClientDataStore[racid][usertype] = reply;}
    
    console.log(tempClientDataStore);
    var query
    var input
    if (!time){
      if(usertype=="officer"){
        if(alsovcom){
          query = `UPDATE Rac SET officername=?, officermitigation=?, vcomname=?, vcommitigation=?, vcomchecklist=? WHERE Id = ?`
          input = [name, mitigation, name, mitigation, checklist, racid]
        }
        else{
          query = `UPDATE Rac SET ${usertype}name=?, ${usertype}mitigation=? WHERE Id = ?`
          input = [name, mitigation, racid]
        }
      }
      else if(usertype=="vcom"){
        query = `UPDATE Rac SET ${usertype}name=?, ${usertype}mitigation=?, vcomchecklist=? WHERE Id = ?`
        input = [name, mitigation, checklist, racid]
      }
      
    }
    else{
      query = `UPDATE Rac SET ${usertype}name=?, ${usertype}time=? WHERE Id = ?`
      input = [name, time, racid]
    }
    console.log(reply,query,input)
    //update table
    db.serialize(function(){
      db.run(query,input,function(err) {
        if (err) {
          return console.log(err.message);
        }
        else{
          console.log(`Row(s) updated: ${this.changes}`);
        }
      })
    })
    
    res.status(200).send('user '+racid+' data received.');
    }
  catch (e){
    console.log(e);
    res.status(400).send({error:'Bad Request' });
  }/*
   "rank":document.getElementById(userTypeShort+'rank').value,
        "name":document.getElementById(userTypeShort+'name').value,
        "mitigation":mitigation,
        "time":time*/
});

app.get('/qrget/:usertype/:racId/:type', (req, res) => {
  try{
    const usertypeArray = ["officer","vcom","dp"]
    const usertype = usertypeArray[parseInt(req.params.usertype)-1]
    const type = req.params.type
    var racid = req.params.racId
    var data = {};
    const tempdata = {
      "officer":{"scanned":false},
      "vcom":{"scanned":false},
      "dp":{"scanned":false}
    }
    if(!tempClientDataStore[racid])
    {tempClientDataStore[racid] = tempdata;}
    //check if already approved before
    if (type == '1'){
      const query = `SELECT ${usertype}name FROM Rac WHERE Id = ${racid}`
      console.log(query)
      db.serialize(function(){
        SQLGet(query).then(row => {
          if(row[1] != undefined){
            if(row[1][usertype+'name']!=null){
               data = {
                'approved':true,
                'name':row[1][usertype+'name']
             }
            }
          }
          res.status(200).send(data);
        })
      })
    }
    //send polling status
    else if (type == '2'){
      data = tempClientDataStore[racid][usertype];
      res.status(200).send(data);
    }
    
    else if (type == '3'){
      tempClientDataStore[racid] = tempdata;
      res.status(200).send({text:'Link Expired'});
    }
    
      
    }
  catch (e){
    console.log(e);
    res.status(400).send({error:'Bad Request' });
  }
});

app.get('/qrcode', function(request, response){
  //response.status(200).sendFile(__dirname + '/views/qr.html');
  var page = fs.readFileSync(__dirname + '/views/qr.html').toString('utf8')
  response.status(200).send(page);
});

app.post('/racdata/:username', (req, res) =>{
  const toid = req.params.username
  const rac = req.body;
  //clear existing rac data
  tempClientDataStore[toid]={};
  const data = {
    "rac":rac,
    "officer":{"scanned":false},
    "vcom":{"scanned":false},
    "dp":{"scanned":false}
  }
  tempClientDataStore[toid] = data;
  console.log(tempClientDataStore);
  res.status(200).send('user '+toid+' data received.');
})

app.post('/createrac/:username', (req, res) =>{
  const toid = req.params.username
  const data = req.body;
  //new rac db entry
  console.log("Creating new RAC entry")
  
  db.serialize(function(){
     // b.run('INSERT INTO Rac VALUES (userid, timestamp, detailid, vehno, journeyfrom, journeyto, avidate, risk, drvexperience, vehtype, fatigue, health, weather, familiarity, mission, novcom, servicibility, officerrank, officername, officermitigation, vcomrank, vcomname, vcommitigation, dprank, dpname, dptime);',
     //      toid, Date.now(), data['detailid'], data['journeyfrom'], data['journeyto'], data['vehno'], data['vehavi'], data['risk'], data['drv-experience'], data['veh-type'], data['fatigue'], data['health'], data['weather'], data['familiarity'], data['mission'], data['no-vcom'], data['servicibility'], data['officerrank'], data['officername'], data['officermitigation'], data['vcomrank'], data['vcomname'], data['vcommitigation'], data['dprank'], data['dpname'], data['dptime']
     //      ,f
        db.run('INSERT INTO Rac(userid, timestamp, detailid, journeyfrom, journeyto, vehno, avidate, risk, drvexperience, vehtype, fatigue, health, weather, familiarity, mission, novcom, servicibility, officername, officermitigation, vcomname, vcommitigation, dpname, dptime, tochecklist) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
          toid, Date.now(), data['detailid'], data['journeyfrom'], data['journeyto'], data['vehno'], data['vehavi'], data['risk'], data['drv-experience'], data['veh-type'], data['fatigue'], data['health'], data['weather'], data['familiarity'], data['mission'], data['no-vcom'], data['servicibility'], data['officername'], data['officermitigation'], data['vcomname'], data['vcommitigation'], data['dpname'], data['dptime'], data['tochecklist']
          ,function(err) {
    if (err) {
      return console.log(err.message);
    }
    // get the last insert id
    console.log(`A row has been inserted with rowid ${this.lastID}`);
  })
  })
//return SQLRun('CREATE TABLE Rac (Id INTEGER PRIMARY KEY, userid INTEGER, timestamp DATETIME, detailid INTEGER, journeyfrom Varchar, journeyto Varchar, vehno, avidate Varchar, risk Varchar, drvexperience Varchar, vehtype Varchar, fatigue Varchar, health Varchar, weather Varchar, familiarity Varchar, mission Varchar, novcom Varchar, servicibility Varchar, officerrank Varchar, officername Varchar, officermitigation Varchar, vcomrank Varchar, vcomname Varchar, vcommitigation Varchar, dprank Varchar, dpname Varchar, dptime Varchar, FOREIGN KEY (userid) REFERENCES Users(Id))');
         
  res.status(200).send('user '+toid+' data received.');
})

app.post('/createuser/:auth', (req, res) =>{
  const key = req.params.auth;
  if (key != "dolicon"){res.status(400).send({error:'Bad Request'});}
  else{
  const data = req.body;
  const {username,name,birthdate,shortnric,node} = data
  var password = birthdate+shortnric;
  const salt = genRandomString(32)
  const pw = sha256(password+salt)
  db.run('INSERT INTO Users(username, password, salt, name, birthdate, shortnric, node, isadmin) VALUES (?,?,?,?,?,?,?,?,?)',username,pw,salt,name,birthdate,shortnric,node,0,function(err) {
    if (err) {
      return console.log(err.message);
    }
    // get the last insert id
    console.log(`A row has been inserted with rowid ${this.lastID}`);
  })
  res.status(200).send('User data created');}
})

app.get('/deluser/:username/:auth', (req, res) =>{
  const key = req.params.auth;
  if (key != "dolicon"){res.status(400).send({error:'Bad Request'});}
  else{
    const username = req.params.username;
    db.run('DELETE FROM Users WHERE username=?', username, function(err) {
  if (err) {
    return console.error(err.message);
  }
  console.log(`Row(s) deleted ${this.changes}`);
  console.log('Users: ',printAllUsers())
      res.status(200).send('User deleted');
    })};
})

app.get('/delrac/:racid/:auth', (req,res) =>{
  const key = req.params.auth;
  const racid = req.params.racid;
  if (key != "dolicon"){res.status(400).send({error:'Bad Request' });}
  db.run('DELETE FROM Rac WHERE Id=?', racid, function(err) {
  if (err) {
    return console.error(err.message);
  }
  console.log(`Row(s) deleted ${this.changes}`);
  });
})

app.get('/addraccol/:colname/:datatype/:auth', (req,res) =>{
  const key = req.params.auth;
  const colname = req.params.colname;
  const datatype = req.params.datatype;
  if (key != "dolicon"){res.status(400).send({error:'Bad Request' });}
  addRacColumn(colname,datatype).catch((err)=>console.log("Adding column Error: "+err)).then(()=>res.status(200).send({'msg':'Added column'}))
})

//prevent favicon redirects on login page
app.get('/img/favicon/login', (req, res) => res.status(204));

app.get('/', auth, function(request, response) {
  console.log('Requested url (/): '+ request.url);
  response.sendFile(__dirname + '/views/index.html');
});

//All other routes
app.get('/*',auth , function(request, response){
  console.log('Requested url (/*): ' + request.url);
  if(fs.existsSync(__dirname + '/views' + request.url + '.html')){
    response.sendFile(__dirname + '/views' + request.url + '.html')
  }else{
    response.status(404).sendFile(__dirname + '/views/404.html');
  }
});

// Fail Routing
app.get('*', auth, function(request, response){
  console.log('Requested url (*): '+ request.url);
  response.status(404).sendFile(__dirname + '/views/404.html');
});

// listen for requests :)
var listener = app.listen(process.env.PORT, function() {
  console.log('Your app is listening on port ' + listener.address().port);
});

//jwt
function generateAuthToken(id){
  const token = jwt.sign({ _id: id.toString() }, process.env.JWT_SECRET.toString(), {expiresIn: '7 days'});
  return token;
}

// crypto.randomBytes(32, (err, buf) => {
//   if (err) throw err;
//   console.log(`${buf.length} bytes of random data: ${buf.toString('hex')}`+sha256('271098356i'+buf.toString('hex')));
// });  

function genRandomString(length){
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex') /** convert to hexadecimal format */
            .slice(0,length);   /** return required number of characters */
};

function SQLGet(query){
  return new Promise((resolve) => {
    db.get(query, (err, row) => {
      resolve([err, row]);
    });
  });
}

function SQLRun(query){
  return new Promise((resolve) => {
    db.run(query, () => {
      resolve();
    });
  });
}

function printAllUsers(){
  db.all('SELECT * FROM Users',[],(err,rows)=>{if(err){throw err;}rows.forEach((row)=>console.log(row))})
}

function printAllRacs(){
  db.all('SELECT * FROM Rac',[],(err,rows)=>{if(err){throw err;}rows.forEach((row)=>console.log(row))})
}

function addRacColumn(columnName,datatype){
  const query = `ALTER TABLE Rac ADD ${columnName} ${datatype};`
  // const racdelcolquery = "CREATE TABLE IF NOT EXISTS t1_backup(Id INTEGER PRIMARY KEY, userid INTEGER, timestamp DATETIME, detailid INTEGER, journeyfrom Varchar, journeyto Varchar, vehno, avidate Varchar, risk Varchar, drvexperience Varchar, vehtype Varchar, fatigue Varchar, health Varchar, weather Varchar, familiarity Varchar, mission Varchar, novcom Varchar, servicibility Varchar, officername Varchar, officermitigation Varchar, vcomname Varchar, vcommitigation Varchar, dpname Varchar, dptime Varchar, tochecklist Varchar, vcomchecklist Varchar, FOREIGN KEY (userid) REFERENCES Users(Id));"
  // const racdelcolquery = "INSERT INTO t1_backup SELECT Id,userid,timestamp,detailid,journeyfrom,journeyto,vehno,avidate,risk,drvexperience,vehtype,fatigue,health,weather,familiarity,mission,novcom,servicibility,officername,officermitigation,vcomname,vcommitigation,dpname,dptime,tochecklist FROM Rac;"
  // const racdelcolquery = "DROP TABLE Rac;"
  // const racdelcolquery = "ALTER TABLE t1_backup RENAME TO Rac;"

  // const userdelcolquery = "CREATE TABLE t1_backup(Id INTEGER PRIMARY KEY, username Varchar NOT NULL, password Varchar, salt Varchar, name Varchar, birthdate INTEGER, shortnric Varchar, node Varchar, isadmin INTEGER)"
  // const userdelcolquery = "INSERT INTO t1_backup SELECT Id,username,password,salt,name,birthdate,shortnric,node,isadmin FROM Users"
 // const userdelcolquery = "DROP TABLE Users;"
// const userdelcolquery = "ALTER TABLE t1_backup RENAME TO Users;"
  
  // const userdelcolquery = "DROP TABLE t1_backup"
  return new Promise((resolve) => {
    db.run(query, () => {
      resolve();
      printAllUsers()
    });
  });
}