'use strict';

/**
 * Module dependencies.
 */

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { return step("next", value); }, function (err) { return step("throw", err); }); } } return step("next"); }); }; }

var url = require('url'),
    qs = require('querystring'),
    merge = require('utils-merge'),
    AuthorizationError = require('oauth2orize-koa').AuthorizationError;

/**
 * Handles requests to obtain a response with an access token and authorization
 * code.
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
module.exports = function (options, issueToken, issueCode) {
  if (typeof options == 'function') {
    issueCode = issueToken;
    issueToken = options;
    options = undefined;
  }
  options = options || {};

  if (!issueToken) throw new TypeError('oauth2orize-openid.codeToken grant requires an issueToken callback');
  if (!issueCode) throw new TypeError('oauth2orize-openid.codeToken grant requires an issueCode callback');

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [separators];
  }

  /* Parse requests that request `code token` as `response_type`.
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

  /* Sends responses to transactions that request `code token` as `response_type`.
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

      // NOTE: To facilitate code reuse, the `issueToken` callback should
      //       interoperate with the `issue` callback implemented by
      //       `oauth2orize.grant.token`.

      var arity = issueToken.length;
      var result;
      if (arity == 3) {
        result = yield issueToken(txn.client, txn.user, txn.res);
      } else {
        // arity == 2
        result = yield issueToken(txn.client, txn.user);
      }

      var accessToken, params;
      if (Array.isArray(result)) {
        var _result = result;

        var _result2 = _slicedToArray(_result, 2);

        accessToken = _result2[0];
        params = _result2[1];
      } else {
        accessToken = result;
      }

      if (!accessToken) {
        throw new AuthorizationError('Request denied by authorization server', 'access_denied');
      }

      var tok = {};
      tok['access_token'] = accessToken;
      if (params) {
        merge(tok, params);
      }
      tok['token_type'] = tok['token_type'] || 'Bearer';
      if (txn.req && txn.req.state) {
        tok['state'] = txn.req.state;
      }

      // NOTE: To facilitate code reuse, the `issueCode` callback should
      //       interoperate with the `issue` callback implemented by
      //       `oauth2orize.grant.code`.

      arity = issueCode.length;
      var code;
      if (arity == 6) {
        // TODO: Is access_token param really necessary???
        code = yield issueCode(txn.client, txn.req.redirectURI, txn.user, txn.res, txn.req, tok.access_token);
      } else if (arity == 5) {
        code = yield issueCode(txn.client, txn.req.redirectURI, txn.user, txn.res, txn.req);
      } else if (arity == 4) {
        code = yield issueCode(txn.client, txn.req.redirectURI, txn.user, txn.res);
      } else {
        // arity == 3
        code = yield issueCode(txn.client, txn.req.redirectURI, txn.user);
      }

      if (!code) {
        throw new AuthorizationError('Request denied by authorization server', 'access_denied');
      }

      tok['code'] = code;

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
   * Return `code token` grant module.
   */

  var mod = {};
  mod.name = 'code token';
  mod.request = request;
  mod.response = response;
  return mod;
};