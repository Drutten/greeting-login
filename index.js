const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const users = require('./db/users.json');
let refreshTokens = require('./db/refreshtokens.json');
const FAKE_SECRET = 'notsosecret';

const app = express();
app.use(express.json());
app.use(cors());

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find((u) => {
        return u.username === username && u.password === password;
    });
    if (user) {
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        refreshTokens.push(refreshToken);
        res.status(200).json({
            username,
            accessToken,
            refreshToken,
        });
    }
    else {
        res.status(400).json({error: 'Incorrect username or password'});
    }
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const alreadyTaken = users.find((u) => u.username === username);
    if (alreadyTaken) {
        return res.status(400).json({
            error: 'Username already taken. Must be unique'
        });
    }
    if (!username || !password) {
        return res.status(400).json({
            error: 'Username and password are required'
        });
    }
    const user = {
        username,
        password,
    }
    users.push(user);
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);
    res.status(200).json({
        username,
        accessToken,
        refreshToken,
    });
});

app.post('/logout', verify, (req, res) => {
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    res.status(200).json({message: 'Logged out'});
});

app.post('/refresh', (req, res) => {
    // get refresh token from user
    const refreshToken = req.body.token;
    if (!refreshToken) {
        return res.status(401).json({error: 'Unauthorized'});
    }
    if (!refreshTokens.includes(refreshToken)) {
        return res.status(403).json({error: 'Token not valid'});    
    }
    // create new token
    jwt.verify(refreshToken, FAKE_SECRET, (err, user) => {
        if (err) {
            console.log(err);
        }
        refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateAccessToken(user);
        refreshTokens.push(newRefreshToken);
        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        });
    });
})

app.get('/test', verify, (req, res) => {
    res.status(200).json('Accessed test route');
});

function verify(req, res, next) {
    const auth = req.headers.authorization;
    if (auth) {
        const token = auth.split(' ')[1];
        jwt.verify(token, FAKE_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({error:'Token not valid'});
            }
            req.user = user;
            next();
        });
    } else {
        res.status(401).json({error: 'Unauthorized'});
    }
}

function generateAccessToken(user) {
    const { username } = user;
    return jwt.sign(
        { username }, 
        FAKE_SECRET,
        { expiresIn: '15m' },
    );
}

function generateRefreshToken(user) {
    const { username } = user;
    return jwt.sign(
        { username }, 
        FAKE_SECRET,
    );
}

app.listen(8080, () => console.log('API is running on localhost:8080'));
