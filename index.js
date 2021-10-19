import express from 'express';
import jwt from 'jsonwebtoken';
// import crypto from 'crypto';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';

// Read environment varibales from .env
dotenv.config();

// Setup express application
const app = express();
app.use(express.json());

// if you suspect that someone stole tokens, you should the secret and all tokens will be invalid, when users try to continue using your app
// const secret = "HGDJHFGHJDFJKVJHSKASO";
// const secret = Math.random()+"potato";
// This makes a very secure random secret with every app reboot
// const secret = crypto.randomBytes(64).toString('hex');
const secret = process.env.SECRET
console.log({ secret });

// hashes a password
async function hash(password) {
    return await bcrypt.hash(password, 10)
}

// checks if a password matches a given hash
async function checkHash(password, hash){
    return await bcrypt.compare(password, hash)
}

const users = [
    { username: "joel", password: await hash("123") }, 
    { username: "veera", password: await hash("1234") }, 
    { username: "rauli", password: await hash("12345") } 
]

// this middleware can be used to check if a request contains a valid middleware
function checkTokenMiddleware(req, res, next) {
    const tokenRaw = req.headers.authorization;
    if (!tokenRaw) {
        return res.status(401).send("Missing authorization header");
    }
    // console.log(tokenRaw);
    const tokenToCheck = tokenRaw.split(" ")[1]; // get only the token out of the header (which is a string), without the Bearer
    if (!tokenToCheck) {
        return res.status(401).send("Invalid authorization token");
    }
    // console.log(tokenToCheck);
    
    // verify if token is correct
    jwt.verify(tokenToCheck, process.env.SECRET, (err, payload) => {
        // console.log({ err, payload });

        if (err) {
            return res.status(400).send(err.message) // you can't send 2 responses like res.sendStatus(400).send(err.message) --> get's the error "Can't set headers after they are sent"
        }

        // req.userData = payload;
        // Joel's newer version:
        req.user = { username: payload.username };
        next();
    });

}

// Register new user
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
    if (user) {
        return res.status(401).send("username already in use")
    }

    users.push({
        username,
        password: await hash(password)
    })

    res.send("User " + username + " registered")
})

// Returns a fresh token
// app.get('/token', (req, res) => {
app.get('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
    if (!user) { return res.status(401).send("No such user"); };

    const passwordOk = await checkHash(password, user.password);
    if (!passwordOk) {
        return res.status(401).send("Invalid username/password");
    }

    // return token to the client
    const payload = { 
        // never add secrets here like passwords as they can be decoded!
        // userId: 42, // req.body.userId would 1st be checked before this happens
        // username: "Veera cat",
        // admin: true
        username: user.username,
    };

    const options = {
        // expiresIn: "1m" // read documentation in the npm package for jsonwebtoken, this is 1 min
        expiresIn: process.env.EXPIRES
    };

    const token = jwt.sign(payload, process.env.SECRET, options);
    res.send(token);
});

// this endpoint is SECURED! only request with a valid token can access it 
app.get('/secure', checkTokenMiddleware, (req, res) => {
    // check token (with middleware function) and return something
    res.send(`Hooray, ${req.user.username}, you have access to the secure endpoint`);
});

app.listen(process.env.PORT, () => {
    console.log("Listening at http://localhost:"+process.env.PORT);
});