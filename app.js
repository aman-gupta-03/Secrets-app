//jshint esversion:6

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const { Schema } = mongoose;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require( 'passport-google-oauth20' ).Strategy;
const FacebookStrategy = require( 'passport-facebook' ).Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "thisisasecret",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser: true});

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user);
});
  
passport.deserializeUser(function(user, done) {
    done(null, user);
});

passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    passReqToCallback   : true
  },
  function(request, accessToken, refreshToken, profile, done) {
    User.findOrCreate({ username: profile.emails[0].value, googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets", 
    profileFields: ['id', 'email']
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile.emails[0].value,facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
    res.render('home');
});

app.get('/auth/google',
  passport.authenticate('google', { scope:
      [ 'email', 'profile' ] }
));

app.get('/auth/facebook',
  passport.authenticate('facebook', { scope:
    [ 'email' ] 
}));

app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
}));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

app.get("/login", (req, res) => {
    res.render('login');
});

app.get("/register", (req, res) => {
    res.render('register');
});

app.get("/secrets", (req, res) => {
    if(req.isAuthenticated()){
        User.find({'secret': {$ne: null}}, (err, found) => {
            if(err){
                console.log(err);
            } else{
                res.render('secrets', {secrets: found});
            }
        });
    } else {
        res.redirect('/login');
    }
});

app.get("/submit", (req, res) => {
    if(req.isAuthenticated()){
        res.render('submit');
    } else {
        res.redirect('/login');
    }
});

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect('/');
});

app.post("/register", (req, res) => {
    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if(err){
            console.log(err);
            res.redirect('/register');
        } else{
            passport.authenticate("local")(req, res, () => {
                res.redirect('/secrets');
            });
        }
    });
    
});

app.post("/login", (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if(err){
            console.log(err);
        } else{
            passport.authenticate("local")(req, res, () => {
                res.redirect('/secrets');
            });
        }
    });
});

app.post("/submit", (req, res) => {
    const secret = req.body.secret;

        User.findById(req.user._id, (err, found) => {
            if(err){
                console.log(err);
            } else {
                if(found){
                    found.secret = secret;
                    found.save(() => {
                        res.redirect('/secrets');
                    });
                }
            }
        });

});





app.listen(3000, () => {
    console.log('Server is listening on port 3000');
});