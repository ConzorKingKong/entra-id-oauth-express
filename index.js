require('dotenv').config()

const express = require('express');
const session = require('express-session');
const axios = require('axios');
const qs = require('querystring');
const crypto = require('crypto');

const app = express();

// Configuration settings for Microsoft Entra ID
const config = {
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET_VALUE,
  tenantId: process.env.TENANT_ID,
  redirectUri: process.env.REDIRECT_URI,
  authority: 'https://login.microsoft.com',
  scope: 'User.Read'
};

// Add session middleware
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: true
}));

// Code verifier and challenge for PKCE
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('hex');
}

function generateCodeChallenge(codeVerifier) {
  return crypto.createHash('sha256').update(codeVerifier).digest('base64url');
}

// The root path links us to the /auth endpoint, which generates
// the url to start oauth flow
app.get('/', (req, res) => {
  res.send('<a href="/auth">Login with Microsoft Entra ID</a>');
});

// The auth endpoint generates our oauth url for Microsoft Entra ID
app.get('/auth', (req, res) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  req.session.codeVerifier = codeVerifier;

  const authUrl = `${config.authority}/${config.tenantId}/oauth2/v2.0/authorize?` + qs.stringify({
    client_id: config.clientId,
    response_type: 'code',
    redirect_uri: config.redirectUri,
    response_mode: 'query',
    scope: config.scope,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  res.redirect(authUrl);
});

// This is our Redirect URI
// After the flow has started, Microsoft sends us back
// an authorization code, authorizing us to get access and refresh tokens
// on behalf of the user
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;

  const tokenUrl = `${config.authority}/${config.tenantId}/oauth2/v2.0/token`;

  const tokenParams = {
    client_id: config.clientId,
    scope: config.scope,
    code,
    redirect_uri: config.redirectUri,
    grant_type: 'authorization_code',
    client_secret: config.clientSecret,
    code_verifier: req.session.codeVerifier
  };

  try {
    const response = await axios.post(tokenUrl, qs.stringify(tokenParams), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    // save the token data in the user session in express
    req.session.tokenSet = response.data;
    res.redirect('/profile');
  } catch (error) {
    console.error('Token exchange error:', error);
    res.redirect('/');
  }
});

// grab token data from express session
// and get user info from microsoft
app.get('/profile', async (req, res) => {
  if (!req.session.tokenSet) {
    return res.redirect('/');
  }

  const { access_token } = req.session.tokenSet;

  try {
    const userInfo = await axios.get('https://graph.microsoft.com/v1.0/me', {
      headers: {
        Authorization: `Bearer ${access_token}`
      }
    });

    res.send(`<h1>Profile</h1><pre>${JSON.stringify(userInfo.data, null, 2)}</pre><a href="/logout">logout</a>`);
  } catch (error) {
    console.error('Error fetching user info:', error);
    res.redirect('/');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/');
  });
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});