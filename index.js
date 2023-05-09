require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const url = require('url');

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('./databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

const navLinks = [
    { name: "Home", link: "/" },
    { name: "Members", link: "/members" },
    { name: "Login", link: "/login" },
    { name: "Admin", link: "/admin" }
];

app.use("/", (req, res, next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
});

app.get('/', (req, res) => {
    if (req.session.authenticated) {
        res.render('authenticated', { username: req.session.username});
    } else {
        res.render('unauthenticated')
    }
});

app.get('/createUser', (req, res) => {
    res.render('createUser');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/submitUser', async (req, res) => {
    const { username, email, password } = req.body;

    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().max(254).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ username, email, password });

    if (validationResult.error != null) {
        console.log(validationResult.error);
        const errorMessage = validationResult.error.details[0].message;

        if (errorMessage.includes("username")) {
            res.render('nameRequired');
        } else if (errorMessage.includes("email")) {
            res.render('emailRequired');
        } else if (errorMessage.includes("password")) {
            res.render('passwordRequired');
        }
        return;
    }

    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert the new user to the database
    await userCollection.insertOne({ 
        username: username, 
        email: email, 
        password: hashedPassword,
        user_type: 'user' // set default value for user_type as 'user'
    });

    // Set session variables for the new user and redirect to the members page
    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().email().max(254).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ username: 1, password: 1, user_type: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        res.render('userNotFound');
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        res.render('userNotFound');
        return;
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    } else {
        res.render('members', {username: req.session.username});
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({username: 1, user_type: 1, _id: 1}).toArray();
 
    res.render("admin", {users: result});
});

app.post('/promote_user', sessionValidation, adminAuthorization, async (req,res) => {
    const user_id = req.body.user_id;
    const ObjectId = require('mongodb').ObjectId;
    const result = new ObjectId(user_id);
    await userCollection.updateOne({_id: result}, {$set: {user_type: 'admin'}});
    console.log(user_id + " promoted to admin");
    res.redirect('/admin');
});

app.post('/demote_user', sessionValidation, adminAuthorization, async (req,res) => {
    const user_id = req.body.user_id;
    const ObjectId = require('mongodb').ObjectId;
    const result = new ObjectId(user_id);
    await userCollection.updateOne({_id: result}, {$set: {user_type: 'user'}});
    console.log(user_id + " demoted to user");
    res.redirect('/admin');
});
 
app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 