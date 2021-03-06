'use strict';

/**
 * Module dependencies.
 */

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

var url = require('url'),
    qs = require('querystring'),
    AuthorizationError = require('oauth2orize-koa').AuthorizationError;

/**
 * Handles requests to obtain a response with an authorization code and ID
 * token.
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
module.exports = function (options, issueCode, issueIDToken) {
  if (typeof options == 'function') {
    issueIDToken = issueCode;
    issueCode = options;
    options = undefined;
  }
  options = options || {};

  if (!issueCode) throw new TypeError('oauth2orize-openid.codeIDToken grant requires an issueCode callback');
  if (!issueIDToken) throw new TypeError('oauth2orize-openid.codeIDToken grant requires an issueIDToken callback');

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [separators];
  }

  /* Parse requests that request `code id_token` as `response_type`.
   *
   * @param {http.ServerRequest} req
   * @api public
   */
  function request(ctx) {
    var clientID = ctx.query['client_id'],
        redirectURI = ctx.query['redirect_uri'],
        scope = ctx.query['scope'],
        state = ctx.query['state'];

    if (!clientID) {
      throw new AuthorizationError('Missing required parameter: client_id', 'invalid_request');
    }

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

      if (!Array.isArray(scope)) {
        scope = [scope];
      }
    }

    return {
      clientID: clientID,
      redirectURI: redirectURI,
      scope: scope,
      state: state
    };
  }

  /* Sends responses to transactions that request `code id_token` as `response_type`.
   *
   * @param {Object} txn
   * @param {http.ServerResponse} res
   * @param {Function} next
   * @api public
   */

  let response = function () {
    var ref = _asyncToGenerator(function* (ctx) {
      var txn = ctx.state.oauth2;
      if (!txn.redirectURI) {
        throw new Error('Unable to issue redirect for OAuth 2.0 transaction');
      }
      if (!txn.res.allow) {
        var err = {};
        err['error'] = 'access_denied';
        if (txn.req && txn.req.state) {
          err['state'] = txn.req.state;
        }

        let parsed = url.parse(txn.redirectURI);
        parsed.hash = qs.stringify(err);

        let location = url.format(parsed);
        return ctx.redirect(location);
      }

      // NOTE: To facilitate code reuse, the `issueCode` callback should
      //       interoperate with the `issue` callback implemented by
      //       `oauth2orize.grant.code`.

      var arity = issueCode.length;
      var code;
      if (arity == 4) {
        code = yield issueCode(txn.client, txn.req.redirectURI, txn.user, txn.res);
      } else {
        // arity == 3
        code = yield issueCode(txn.client, txn.req.redirectURI, txn.user);
      }

      if (!code) {
        throw new AuthorizationError('Request denied by authorization server', 'access_denied');
      }

      var tok = {};
      tok['code'] = code;

      // NOTE: To facilitate code reuse, the `issueIDToken` callback should
      //       interoperate with the `issue` callback implemented by
      //       `oauth2orize-openid.grant.idToken`.

      arity = issueIDToken.length;
      var idToken;
      if (arity == 3) {
        // TODO: Pass any additional arguments that may be needed to issue an access token.
        //issueIDToken(txn.client, txn.user, scope, issued);
        //issueIDToken(txn.client, txn.user, scope, req, issued);
      } else {
          // arity == 4
          idToken = yield issueIDToken(txn.client, txn.user, txn.req, tok.code);
        }

      if (!idToken) {
        throw new AuthorizationError('Request denied by authorization server', 'access_denied');
      }

      tok['id_token'] = idToken;
      if (txn.req && txn.req.state) {
        tok['state'] = txn.req.state;
      }

      var parsed = url.parse(txn.redirectURI);
      parsed.hash = qs.stringify(tok);

      var location = url.format(parsed);
      ctx.redirect(location);
    });

    return function response(_x) {
      return ref.apply(this, arguments);
    };
  }();

  /**
   * Return `code id_token` grant module.
   */

  var mod = {};
  mod.name = 'code id_token';
  mod.request = request;
  mod.response = response;
  return mod;
};