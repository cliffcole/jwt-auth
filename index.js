const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const passportJwt = require('passport-jwt');
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt;
const config = require('./secret.json');
const morgan = require('morgan');

const PORT = 3001; //port api will listen on

const app = express();

//initialize built-in json middleware
app.use(express.json());

//middleware for logging request which make them easier to read
app.use(morgan('dev'));

//configure jtw options
const jwtOptions = {}
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
jwtOptions.secretOrKey = config.secret;

//initialize passport as middleware
app.use(passport.initialize());

// set the passport strategy to validate tokens on any protected route
passport.use(new JwtStrategy(jwtOptions, (jwt_payload, done) => {
    // returning dummy data, this could be information anything but will
    // be added to your req.user in the route that call this
    
    return done(null, "dummy data");
    
    // You could add another check against the user if you set the payload
    // to have the username
    /* models.Users.findOne({where: {id: jwt_payload.user}}).then(response => {
        return done(null,response);
    }); */
}));

// This is a protected path.  we use passport middleware on any path we want to
// protect so only an valid token will work.
app.get('/protected', passport.authenticate('jwt',{session: false}), (req, res, next) => {
    //shows authentication token worked
    console.log("Inside protected route");
    
    // show req.user from the passport strategy as mentioned above for an example
    console.log(req.user);

    //striping the "Bearer " off the authorization to just show the token
    let token = req.headers.authorization.replace('Bearer ','');
    
    // decode the token to see what is inside and return it as json
    let decode = jwt.verify(token, config.secret);
    res.json(decode);
})

// This is the login to generate the users token.
app.post('/login', (req,res,next) => {

    // create a payload, this will be some information about the 
    // user or whatever you decide.  Typically could be user info
    let payload = {
        somekey: "someinformationhere"
    }

    // Sign the token using the payload, secret, and optional expiration
    let token = jwt.sign(payload,config.secret,{expiresIn: 60 * 60});
    
    //return a response with the token just generated
    res.json({
        message: "ok", 
        token: token
    });
});

/* 
In the login post you would typically want to get the username and password out of the
req.body and verify they match the username and password in your database
*/
app.listen(PORT, () => {
    console.log("Listening on 3001");
});
