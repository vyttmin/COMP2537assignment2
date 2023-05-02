require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

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

app.get('/', (req, res) => {
    if (req.session.authenticated) {
        res.send(`
            <h2>Welcome, ${req.session.username}!</h2>
            <a href="/members">Members Area</a><br/>
            <a href="/logout">Log out</a>
        `);
    } else {
        res.send(`
            <a href="/createUser">Sign up</a><br/>
            <a href="/login">Log in</a>
        `);
    }
});

app.get('/createUser', (req, res) => {
    var html = `
    Sign Up:
    <br>
    <form action='/submitUser' method='post'>
        <div><input name='username' type='text' placeholder='username'></div>
        <div><input name='email' type='text' placeholder='email'></div>
        <div><input name='password' type='password' placeholder='password'></div>
        <br>
        <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/login', (req, res) => {
    var html = `
        log in
        <form action='/loggingin' method='post'>
        <input name='email' type='text' placeholder='email'>
        <input name='password' type='password' placeholder='password'>
        <button>Submit</button>
        </form>
        `;
    res.send(html);
});

app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().max(254).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        const errorMessage = validationResult.error.details[0].message;

        if (errorMessage.includes("username")) {
            var html = `
            Name is required. <br><a href="/createUser">Try Again</a>
            `;
            res.send(html);
        } else if (errorMessage.includes("email")) {
            var html = `
            Email is required. <br><a href="/createUser">Try Again</a>
            `;
            res.send(html);
        } else if (errorMessage.includes("password")) {
            var html = `
            Password is required. <br><a href="/createUser">Try Again</a>
            `;
            res.send(html);
        }
        return;
    }

    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert the new user to the database
    await userCollection.insertOne({ username: username, email: email, password: hashedPassword });

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

    const result = await userCollection.find({ email: email }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        var html = `
        User and password not found. <br><a href="/login">Try Again</a>
        `;
        res.send(html);
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        var html = `
            User and password not found. 
            <a href="/login">Try Again</a>
            `;
        res.send(html);
        return;
    }
});



app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    } else {
        const pokemonImages = [
            { name: 'Bulbasaur', src: '/pokemon01.png' },
            { name: 'Charmander', src: '/pokemon02.png' },
            { name: 'Squirtle', src: '/pokemon03.png' },
        ];

        function getRandomImage() {
            const randomIndex = Math.floor(Math.random() * pokemonImages.length);
            return pokemonImages[randomIndex];
        }

        const img = getRandomImage();

        res.send(`
            <h2>Hello, ${req.session.username}!</h2>
            <a href="/logout">Log out</a>
            <br>
            ${img.name}: <img src='${img.src}' style='width:250px;'>
        `);
    }
});


app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 