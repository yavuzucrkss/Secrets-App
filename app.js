//jshint esversion:6 
require('dotenv').config(); //must be top on page
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session')
const ejs = require('ejs');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');


const findOrCreate = require("mongoose-findorcreate");
const { use } = require('passport');

const GoogleStrategy = require('passport-google-oauth20').Strategy;

//const encrypt = require("mongoose-encryption"); //uses to library of mongoose-encryption
//const md5 = require("md5");
//we use bcrypt instead of md5 
// const bcrypt = require("bcrypt");
// const saltRounds = 10; //we have to make more security on password --> increase to saltRound


const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static('public'));


//below app.use()
//set initial configuration
app.use(session({
    secret: "Our Little Secret.",
    resave: false,
    saveUninitialized: false
}))

//use passport packaege with session
app.use(passport.initialize());
app.use(passport.session());
//above mongoose.connect()

mongoose.connect('mongodb://localhost:27017/userDB', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('MongoDB connected');
    })
    .catch((err) => {
        console.error('MongoDB connection error:', err);
    });

const userSchema = new mongoose.Schema({ //--> mongoose.Schema() is necessary for use to encrpytion
    email: String,
    password: String,
    googleId: String,
    secret: String
});


//adding passportLocalMongoose to Scheme..
userSchema.plugin(passportLocalMongoose);

userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

//use passport on User model
passport.use(User.createStrategy());


passport.serializeUser((user, done) => {
    done(null, user.id)
})

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user.id)
    })
})

//below that serialize/deserializeUser
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        //this code referring by passport package and it is psedo code
        //so for we use on mongoose we have to install mongoose-findorcreate package 
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] })); //gives authentication by profile from google 

app.get('/auth/google/secrets', //if callback triggers, routing to particulor html page.
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });

app.route("/register")

    .get((req, res) => {
        res.render("register")
    })

    .post((req, res) => {

        User.register({ username: req.body.username }, req.body.password, (err, user) => {
            if (err) {
                console.log(err);
                res.redirect("/register");
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets")
                })
            }
        })
    });


app.route("/login")

    .get((req, res) => {
        res.render("login");
    })
    //login post
    .post((req, res) => {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        })

        req.login(user, err => {
            if (err) console.log(err);
            else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets");
                });
            }
        })

    })

app.get("/secrets", (req, res) => {
    User.find({ "secret": { $ne: null } }, (err, foundUser) => {
        if (!err) {
            if (foundUser) {
                res.render("secrets", { usersWithSecrets: foundUser });
            }
        }
    })
});

app.get("/logout", (req, res) => {
    //just needs logout
    req.logout(err => {
        if (err) console.log(err);
        else res.redirect("/");
    })
});


app.get("/submit", (req, res) => {
    if (req.isAuthenticated) res.render("submit");
    else res.redirect("/login");

})

app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;
    User.findById(req.user, (err, foundUser) => {
        if (err) console.log(err);
        else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function () {
                    res.redirect("/secrets");
                })
            }
        }
    });
})

app.listen(3000, function () {
    console.log('Server started on port 3000');
});
