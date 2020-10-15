//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

// have to require these to used passport
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// Requie google authentication and findotcreate
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

const findOrCreate = require("mongoose-findorcreate");

// Bcrypt adds salt rounds to hash to make it longer
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

// MD5 Hashing
// const md5 = require("md5");

// Mongoose-encryption
// const encrypt = require("mongoose-encryption")


const app = express();



app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

// after requiring passport and session use them must be in this order
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
// used to get rid of error message
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  // firstname: String,
  // lastname: String,
  email: String,
  password: String,
  googleId: String,
  secret: String
});

// create plugin for passport and findorcreate
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Used for mongoose-encryption
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields:["password"] });


const User = new mongoose.model("User", userSchema);

// used to set up a local strategy
passport.use(User.createStrategy());

// Used to serializeUser for for passportLocalMongoose
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

// Used to serializeUser for oauth20
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// Google oauth2
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(request, accessToken, refreshToken, profile, done) {
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return done(err, user);
    });
  }
));

// Facebook auth2
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({
      facebookId: profile.id
    }, function(err, user) {
      if (err) {
        return done(err);
      }
      done(null, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
});

// Get route used to authenticate on server for google
app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile"]
  })
);

// Get route used to authenticate on server for facebook
app.get("/auth/facebook",
  passport.authenticate('facebook'));

// Get route used to authenticate local if successfull go to webpage if not go back to login
app.get("/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

// Get route to authenticate local for facebook
app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");

  });

app.get("/login", function(req, res) {
  res.render("login");
});


app.get("/register", function(req, res) {
  res.render("register");
});

// Create secret route
app.get("/secrets", function(req, res) {
  // Used to check if secrets are authenticated
  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // }else {
  //   res.redirect("/login");
  // }
  //

  User.find({"secret": {$ne: null}}, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        res.render("secrets", {
          usersWithSecrets: foundUser
        });
      }
    }
  });
});
// Submit webpage
app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;


  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });
});


// Logout route
app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
})


app.post("/register", function(req, res) {
  // bcrypt hashing password
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     // wrapp in md5 if used
  //     password: hash
  //   });
  //   newUser.save(function(err) {
  //     if (err) {
  //       console.log(err);
  //     } else {
  //       res.render("secrets");
  //     }
  //   });
  // });

  // This code is used for passport only
  User.register({
    // firstname: req.body.firstname,
    // lastname: req.body.lastname,
    username: req.body.username,
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register")
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/login", function(req, res) {
  // const username = req.body.username;
  // // wrapp in md5 if used
  // const password = req.body.password;
  //
  // // This will deencrypt the password so it can be found
  //
  // User.findOne({
  //   email: username
  // }, function(err, foundUser) {
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if (foundUser) {
  //       // bcrypt comparing password to log in
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //         if (result === true) {
  //           res.render("secrets");
  //         }
  //       });
  //
  //     }
  //   }
  // });

  // Code for passportLocalMongoose

  const user = new User({
    // firstname: req.body.firstname,
    // lastname: req.body.lastname,
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  })

});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function() {
  console.log("Server has started Successfully");
});
