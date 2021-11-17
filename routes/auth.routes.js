const router = require("express").Router();
const UserModel = require('../models/User.model');
const bcrypt = require('bcryptjs');

router.get('/signin', (req, res, next) => {
    res.render('auth/signin.hbs')
});

router.get('/signup', (req, res, next) => {
    res.render('auth/signup.hbs')
});
router.post('/signup', (req, res, next) =>{
    const {username, password} = req.body

    let salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt)
    UserModel.create({username, password: hash})
    .then(() => {
        res.redirect('/')
    })
    .catch((err) => {
        next(err)
    })
})

router.post('/signin', (req, res, next) =>{
    const {username, password} = req.body
    
    UserModel.find({username})
    .then((usernameResponse) => {
        // if the email exists check the password
        if (usernameResponse.length) {
            //bcrypt decryption 
            let userObj = usernameResponse[0]

            // check if password matches
            let isMatching = bcrypt.compareSync(password, userObj.password);
            if (isMatching) {
                // loggedInUser = userObj
                req.session.myProperty = userObj
                // req.session.welcome = 'Helllo'

                res.redirect('/profile')
            }
            else {
              res.render('auth/signin.hbs', {error: 'Password not matching'})
              return;
            }
        }
        else {
          res.render('auth/signin.hbs', {error: 'User username does not exist'})
          return;
        }
    })
    .catch((err) => {
      next(err)
    }) 
})
const checkLogIn = (req, res, next) => {
    if (req.session.myProperty ) {
      //invokes the next available function
      next()
    }
    else {
      res.redirect('/signin')
    }
}
router.get('/profile', checkLogIn, (req, res, next) => {
    let myUserInfo = req.session.myProperty  
    res.render('auth/profile.hbs', {name: myUserInfo.username})
})

router.get('/search', checkLogIn, (req, res, next) => {
    res.send('Search page')
})

router.get('/logout', (req, res, next) => {
    // Deletes the session
    // this will also automatically delete the session from the DB
    req.session.destroy()
    res.redirect('/signin')
})

module.exports = router;