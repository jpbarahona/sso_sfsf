var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var SamlStrategy = require('passport-saml').Strategy;
var fs = require('fs');

var User = require('../models/user');

var decryptionCert = fs.readFileSync('./certificate.crt', 'utf-8');

// Register
router.get('/register', function(req, res){
	res.render('register');
});

// Login
router.get('/login/sf',
  passport.authenticate('saml', {successRedirect:'/', failureRedirect:'/users/login',failureFlash: true}),
  function(req, res) {
    res.redirect('/');
  });

// Register User
router.post('/register', function(req, res){
	var name = req.body.name;
	var email = req.body.email;
	var username = req.body.username;
	var password = req.body.password;
	var password2 = req.body.password2;

	// Validation
	req.checkBody('name', 'Name is required').notEmpty();
	req.checkBody('email', 'Email is required').notEmpty();
	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('username', 'Username is required').notEmpty();
	req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

	var errors = req.validationErrors();

	if(errors){
		res.render('register',{
			errors:errors
		});
	} else {
		var newUser = new User({
			name: name,
			email:email,
			username: username,
			password: password
		});

		User.createUser(newUser, function(err, user){
			if(err) throw err;
			console.log(user);
		});

		req.flash('success_msg', 'You are registered and can now login');

		res.redirect('/users/login/sf');
	}
});

passport.use(new LocalStrategy(
  function(username, password, done) {
   User.getUserByUsername(username, function(err, user){
   	if(err) throw err;
   	if(!user){
   		return done(null, false, {message: 'Unknown User'});
   	}

   	User.comparePassword(password, user.password, function(err, isMatch){
   		if(err) throw err;
   		if(isMatch){
   			return done(null, user);
   		} else {
   			return done(null, false, {message: 'Invalid password'});
   		}
   	});
   });
  }));


var myStrategy = new SamlStrategy(
	{
    path: '/users/login/sf',
    entryPoint: 'https://hcm19preview.sapsf.com/sf/idp/SAML2/SSO/Redirect/company/abastiblesT1',
    issuer: 'https://hcm19preview.sapsf.com/sf/idp/SAML2/company/abastiblesT1'
  },
  function(profile, done) {
   User.getUserByUsername(profile.nameID, function(err, user){    
   	if (err) {
        return done(err);
      }
      return done(null, user);
   });
  });

passport.use(myStrategy);

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

router.post('/login/sf',
  passport.authenticate('saml', {failureRedirect:'/users/login',failureFlash: true}),
  function(req, res) {
    res.redirect('/sso/sf');
    //res.redirect('<Nombre APP>://login?user=' + JSON.stringify(req.user));
  });

router.get('/logout', function(req, res){
	req.logout();

	req.flash('success_msg', 'You are logged out');

	res.redirect('/users/login');
});

module.exports = router;