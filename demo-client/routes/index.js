var express = require('express');
var router = express.Router();
var OAuth2 = require('simple-oauth2');
var randomstring = require("randomstring");
var jws = require("jws");

var oauth2 = OAuth2.create({
  client: {
    id: process.env.HYDRA_CLIENT_ID,
    secret: process.env.HYDRA_CLIENT_SECRET
  },
  auth: {
    tokenHost: endpoint = process.env.HYDRA_URL,
    authorizeHost: 'http://localhost:4444',
    authorizePath: authorizePath = '/oauth2/auth',
    tokenPath: tokenPath = '/oauth2/token'
  },
  options: {
    useBodyAuth: false,
    useBasicAuthorizationHeader: true
  }
});
var cb = 'http://localhost:4000/callback';
var state = randomstring.generate(10);
var state_prefix_map = {
  'profile': 'p-',
  'refresh': 'r-',
};

function get_state(route) {
  return state_prefix_map[route] + state;
}

function validate_state(check) {
  var match = check.match('^(\\w-)?(\\w+)$');
  var result;
  if (match) {
    var mapped = Object.entries(state_prefix_map).find(s => s[1] === match[1]);
    result = { valid: match[2] === state,
      route: mapped ? mapped[0] : undefined
    };
  }
  return result;
}

router.get('/', function(req, res, next) {
  res.render('auth', { title: 'OAuth 2 / OpenID Connect Demo',
    what: 'Login via Hydra',
    uri: oauth2.authorizationCode.authorizeURL({
      redirect_uri: cb,
      scope: 'openid',
      state: state,
    })
  });
});

router.get('/profile', function(req, res, next) {
  res.render('auth', { title: 'OAuth 2 / OpenID Connect Demo',
    what: 'Zugriff auf Profilinformationen via Hydra autorisieren',
    uri: oauth2.authorizationCode.authorizeURL({
      redirect_uri: cb,
      scope: 'openid email profile',
      state: get_state('profile'),
    })
  });
});

router.get('/refresh', function(req, res, next) {
  res.render('auth', { title: 'OAuth 2 / OpenID Connect Demo',
    what: 'Login via Hydra (mit Refresh Token)',
    uri: oauth2.authorizationCode.authorizeURL({
      redirect_uri: cb,
      scope: 'openid offline email profile',
      state: get_state('refresh'),
    })
  });
});

function render_token(res, route, token)
{
  var id_token;
  if (token.id_token) {
    id_token = jws.decode(token.id_token);
  }

  return res.render('token', {
    token: token,
    id: id_token,
    route: route
  });
}

router.get('/callback', async (req, res, next) => {
  var { valid, route } = validate_state(req.query.state);
  if (!valid) {
    return res.status(500).render('error', { message: 'Invalid state', route: route, error: { status: 500 }});
  }

  var options = {
    redirect_uri: cb,
    code: req.query.code,
  };

  try {
    var token = await oauth2.authorizationCode.getToken(options);

    return render_token(res, route, token);
  } catch(error) {
    console.error('Access Token Error', error.message);
    return res.status(500).render('error', { message: 'Access Token error', error: error,
      route: route });
  }
});

router.post('/callback', async (req, res, next) => {
  var { valid, route } = validate_state(req.query.state);
  if (!valid) {
    return res.status(500).render('error', { message: 'Invalid state', route: route, error: { status: 500 }});
  }
  // recreate the token
  var token = oauth2.accessToken.create({
    refresh_token: req.body.refresh_token,
  });

  try {
    token = await token.refresh();

    return render_token(res, route, token.token);
  } catch(error) {
    console.error('Access Token Error', error.message);
    return res.status(500).render('error', { message: 'Access Token error', error: error,
      route: route });
  }
});

module.exports = router;
