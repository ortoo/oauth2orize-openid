/**
 * Module dependencies.
 */
var url = require('url')
  , qs = require('querystring')
  , merge = require('utils-merge')
  , AuthorizationError = require('oauth2orize-koa').AuthorizationError;


/**
 * Handles requests to obtain a response with an access token and ID token.
 *
 * References:
 *  - [OpenID Connect Standard 1.0 - draft 21](http://openid.net/specs/openid-connect-standard-1_0.html)
 *  - [OpenID Connect Messages 1.0 - draft 20](http://openid.net/specs/openid-connect-messages-1_0.html)
 *  - [OAuth 2.0 Multiple Response Type Encoding Practices - draft 08](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
 *
 * @param {Object} options
 * @param {Function} issue
 * @return {Object} module
 * @api public
 */
module.exports = function(options, issueToken, issueIDToken) {
  if (typeof options == 'function') {
    issueIDToken = issueToken;
    issueToken = options;
    options = undefined;
  }
  options = options || {};

  if (!issueToken) throw new TypeError('oauth2orize-openid.idTokenToken grant requires an issueToken callback');
  if (!issueIDToken) throw new TypeError('oauth2orize-openid.idTokenToken grant requires an issueIDToken callback');

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [ separators ];
  }


  /* Parse requests that request `id_token token` as `response_type`.
   *
   * @param {http.ServerRequest} req
   * @api public
   */
  function request(ctx) {
    var clientID = ctx.query['client_id']
      , redirectURI = ctx.query['redirect_uri']
      , scope = ctx.query['scope']
      , state = ctx.query['state'];

    if (!clientID) { throw new AuthorizationError('Missing required parameter: client_id', 'invalid_request'); }

    if (scope) {
      for (var i = 0, len = separators.length; i < len; i++) {
        var separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }

      if (!Array.isArray(scope)) { scope = [ scope ]; }
    }

    return {
      clientID: clientID,
      redirectURI: redirectURI,
      scope: scope,
      state: state
    };
  }

  /* Sends responses to transactions that request `id_token token` as `response_type`.
   *
   * @param {Object} txn
   * @param {http.ServerResponse} res
   * @param {Function} next
   * @api public
   */
  async function response(ctx) {
    var txn = ctx.state.oauth2;
    if (!txn.redirectURI) { throw new Error('Unable to issue redirect for OAuth 2.0 transaction'); }
    if (!txn.res.allow) {
      var err = {};
      err['error'] = 'access_denied';
      if (txn.req && txn.req.state) { err['state'] = txn.req.state; }

      let parsed = url.parse(txn.redirectURI);
      parsed.hash = qs.stringify(err);

      let location = url.format(parsed);
      return ctx.redirect(location);
    }


    // NOTE: To facilitate code reuse, the `issueToken` callback should
    //       interoperate with the `issue` callback implemented by
    //       `oauth2orize.grant.token`.

    var arity = issueToken.length;
    var result;
    if (arity == 3) {
      result = await issueToken(txn.client, txn.user, txn.res);
    } else { // arity == 2
      result = await issueToken(txn.client, txn.user);
    }

    var accessToken, params;
    if (Array.isArray(result)) {
      [accessToken, params] = result;
    } else {
      accessToken = result;
    }

    if (!accessToken) { throw new AuthorizationError('Request denied by authorization server', 'access_denied'); }

    var tok = {};
    tok['access_token'] = accessToken;
    if (params) { merge(tok, params); }
    tok['token_type'] = tok['token_type'] || 'Bearer';
    if (txn.req && txn.req.state) { tok['state'] = txn.req.state; }

    // NOTE: To facilitate code reuse, the `issueIDToken` callback should
    //       interoperate with the `issue` callback implemented by
    //       `oauth2orize-openid.grant.idToken`.

    // TODO: Need txn.req. to issueIDToken, for nonce claim
    // TODO: Need raw access token, for at_hash
    // TODO: May need ares, for claims
    // TODO: Need grant???

    arity = issueIDToken.length;
    var idToken;
    if (arity == 3) {
      // TODO: Clean this up

      // passing the access token to id token callback for the purpose of
      // at_hash generation required by the implicit flow
      // http://openid.net/specs/openid-connect-implicit-1_0.html
      //issueIDToken(txn.client, txn.user, tok, issued);
      //issueIDToken(txn.client, txn.user, scope, req, issued);
    } else { // arity == 4
      idToken = await issueIDToken(txn.client, txn.user, txn.req, tok.access_token);
    }

    if (!idToken) { throw new AuthorizationError('Request denied by authorization server', 'access_denied'); }

    tok['id_token'] = idToken;

    var parsed = url.parse(txn.redirectURI);
    parsed.hash = qs.stringify(tok);

    var location = url.format(parsed);
    ctx.redirect(location);
  }


  /**
   * Return `id_token token` grant module.
   */
  var mod = {};
  mod.name = 'id_token token';
  mod.request = request;
  mod.response = response;
  return mod;
};
