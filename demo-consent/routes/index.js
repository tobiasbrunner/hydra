var express = require('express');
var router = express.Router();
var OAuth2 = require('simple-oauth2');
var Hydra = require('ory-hydra-sdk');


const scope = 'hydra.consent';
var oauth2 = OAuth2.create({
  client: {
    id: process.env.HYDRA_CLIENT_ID,
    secret: process.env.HYDRA_CLIENT_SECRET
  },
  auth: {
    tokenHost: endpoint = process.env.HYDRA_URL,
    authorizePath: authorizePath = '/oauth2/auth',
    tokenPath: tokenPath = '/oauth2/token'
  }
});

Hydra.ApiClient.instance.basePath = process.env.HYDRA_URL;

var hydra = new Hydra.OAuth2Api();

var refreshToken = () => oauth2.clientCredentials
  .getToken({ scope })
  .then((result) => {
    const token = oauth2.accessToken.create(result);
    const hydraClient = Hydra.ApiClient.instance
    hydraClient.authentications.oauth2.accessToken = token.token.access_token
    return Promise.resolve(token)
  });

refreshToken().then();

var catcher = (w) => (error) => {
  console.error(error)
  w.render('error', { error })
  w.status(500)
  return Promise.reject(error)
};

// This is a mock object for the user. Usually, you would fetch this from, for example, mysql, or mongodb, or somewhere else.
// The data is arbitrary, but will require a unique user id.
const user = {
  email: 'dan@acme.com',
  password: 'secret',

  email_verified: true,
  user_id: 'user:12345:dandean',
  name: 'Dan Dean',
  nickname: 'Danny',
};

var resolver = (resolve, reject) => (error, data, response) => {
  if (error) {
    return reject(error)
  } else if (response.statusCode < 200 || response.statusCode >= 400) {
    return reject(new Error('Consent endpoint gave status code ' + response.statusCode + ', but status code 200 was expected.'))
  }

  resolve(data)
};

var resolveConsent = (r, w, consent, grantScopes = []) => {
  const { email, email_verified, user_id: subject, name, nickname } = user
  const idTokenExtra = {}

  // Sometimes the body parser doesn't return an array, so let's fix that.
  if (!Array.isArray(grantScopes)) {
    grantScopes = [grantScopes]
  }

  // This is the openid 'profile' scope which should include some user profile data. (optional)
  if (grantScopes.indexOf('profile') >= 0) {
    idTokenExtra.name = name
    idTokenExtra.nickname = nickname
  }

  // This is to fulfill the openid 'email' scope which returns the user's email address. (optional)
  if (grantScopes.indexOf('email') >= 0) {
    idTokenExtra.email = email
    idTokenExtra.email_verified = email_verified
  }

  refreshToken().then(() => {
    // Do not return this directly, otherwise `then()` will be called, causing superagent to fail with the double
    // callback bug.
    hydra.getOAuth2ConsentRequest(r.query.consent,
      resolver(
        (consentRequest) => hydra.acceptOAuth2ConsentRequest(r.query.consent, {
            subject,
            grantScopes,
            idTokenExtra,
            accessTokenExtra: {}
          },
          resolver(() => w.redirect(consentRequest.redirectUrl), catcher(w))
        ),
        catcher(w)
      )
    )
  })
};

router.get('/consent', (r, w) => {
  // This endpoint is hit when hydra initiates the consent flow

  if (!r.session.isAuthenticated) {
    // The user is not authenticated yet, so redirect him to the log in page
    return w.redirect('/login?consent=' + r.query.consent)
  } else if (r.query.error) {
    // An error occurred (at hydra)
    return w.render('error', { error: { name: r.query.error, message: r.query.error_description } })
  }

  refreshToken().then(() => {
    // Do not return this directly, otherwise `then()` will be called, causing superagent to fail with the double
    // callback bug.
    hydra.getOAuth2ConsentRequest(r.query.consent, resolver((consentRequest) => {
      // consentRequest contains informations such as requested scopes, client id, ...

      // Here you could, for example, allow clients to force a user's consent. Since you're able to
      // say which scopes a client can request in hydra, you could allow this for a few highly priviledged clients!
      //
      // if (consentRequest.scp.find((s) => s === 'force-consent')) {
      //   resolveConsent(r, w, r.query.consent, consentRequest.requestedScopes)
      //   return Promise.resolve()
      // }
      if (consentRequest.requestedScopes.find((s) => s === 'offline')) {
        resolveConsent(r, w, r.query.consent, consentRequest.requestedScopes)
        return Promise.resolve()
      }

      // render the consent screen
      w.render('consent', { title: 'Eine Anwendung möchte auf Daten zugreifen', scopes: consentRequest.requestedScopes })

    }, catcher(w)))
  })
})

router.post('/consent', (r, w) => {
  if (!r.session.isAuthenticated) {
    return w.redirect('/login?consent=' + r.body.consent)
  }

  resolveConsent(r, w, r.query.consent, r.body.allowed_scopes)
})

router.get('/login', (r, w) => {
  w.render('login', { title: 'Login erforderlich', error: r.query.error, user, consent: r.query.consent })
})

router.post('/login', (r, w) => {
  const form = r.body
  if (form.email !== user.email || form.password !== user.password) {
    w.redirect('/login?error=Ungültiger+Login&consent=' + form.consent)
  }

  r.session.isAuthenticated = true
  w.redirect('/consent?consent=' + r.body.consent)
})

router.get('/logout', (r, w) => {
  if (r.session.isAuthenticated) {
    w.send('<form action="" method="POST"><input type="submit" value="Logout"></form>')
  }
})

router.post('/logout', (r, w) => {
  r.session.isAuthenticated = false
  w.redirect('/')
})

router.get('/', (r, w) => w.send(r.session.isAuthenticated ? 'Logged in' : 'Logged out'))

module.exports = router;
