/* global describe, it, expect, before */
var chai = require('chai')
  , Context = require('../context')
  , oauth = require('oauth2orize-koa')
  , idTokenToken = require('../../lib/grant/idTokenToken');


describe('grant.idTokenToken', function() {

  describe('module', function() {
    var mod = idTokenToken(function(){}, function(){});

    it('should be named id_token token', function() {
      expect(mod.name).to.equal('id_token token');
    });

    it('should expose request and response functions', function() {
      expect(mod.request).to.be.a('function');
      expect(mod.response).to.be.a('function');
    });
  });

  it('should throw if constructed without a issueToken callback', function() {
    expect(function() {
      idTokenToken();
    }).to.throw(TypeError, 'oauth2orize-openid.idTokenToken grant requires an issueToken callback');
  });

  it('should throw if constructed without a issueIDToken callback', function() {
    expect(function() {
      idTokenToken(function(){});
    }).to.throw(TypeError, 'oauth2orize-openid.idTokenToken grant requires an issueIDToken callback');
  });

  describe('request parsing', function() {
    function issueToken(){}
    function issueIDToken(){}

    describe('request', function() {
      var err, out;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.undefined;
        expect(out.state).to.equal('f1o1o1');
      });
    });

    describe('request with scope', function() {
      var err, out;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(1);
        expect(out.scope[0]).to.equal('read');
        expect(out.state).to.equal('f1o1o1');
      });
    });

    describe('request with list of scopes', function() {
      var err, out;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read write';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(2);
        expect(out.scope[0]).to.equal('read');
        expect(out.scope[1]).to.equal('write');
        expect(out.state).to.equal('f1o1o1');
      });
    });

    describe('request with list of scopes using scope separator option', function() {
      var err, out;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken({ scopeSeparator: ',' }, issueToken, issueIDToken));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read,write';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(2);
        expect(out.scope[0]).to.equal('read');
        expect(out.scope[1]).to.equal('write');
        expect(out.state).to.equal('f1o1o1');
      });
    });

    describe('request with list of scopes separated by space using multiple scope separator option', function() {
      var err, out;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken({ scopeSeparator: [' ', ','] }, issueToken, issueIDToken));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read write';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(2);
        expect(out.scope[0]).to.equal('read');
        expect(out.scope[1]).to.equal('write');
        expect(out.state).to.equal('f1o1o1');
      });
    });

    describe('request with list of scopes separated by comma using multiple scope separator option', function() {
      var err, out;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken({ scopeSeparator: [' ', ','] }, issueToken, issueIDToken));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read,write';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(out.clientID).to.equal('c123');
        expect(out.redirectURI).to.equal('http://example.com/auth/callback');
        expect(out.scope).to.be.an('array');
        expect(out.scope).to.have.length(2);
        expect(out.scope[0]).to.equal('read');
        expect(out.scope[1]).to.equal('write');
        expect(out.state).to.equal('f1o1o1');
      });
    });

    describe('request with missing client_id parameter', function() {
      var err, out;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.constructor.name).to.equal('AuthorizationError');
        expect(err.message).to.equal('Missing required parameter: client_id');
        expect(err.code).to.equal('invalid_request');
      });
    });
  });

  describe('decision handling', function() {

    describe('transaction', function() {
      function issueToken(client, user) {
        if (client.id == 'c123' && user.id == 'u123') {
          return 'xyz';
        }
        throw new Error('something is wrong');
      }

      function issueIDToken(client, user, areq, accessToken) {
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
        expect(accessToken).to.equal('xyz');

        return 'idtoken';
      }


      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'id_token token',
          redirectURI: 'http://example.com/auth/callback',
          nonce: 'n-0S6_WzA2Mj'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };

        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=Bearer&id_token=idtoken');
      });
    });

    describe('transaction with request state', function() {
      function issueToken(client, user) {
        if (client.id == 'c123' && user.id == 'u123') {
          return 'xyz';
        }
        throw new Error('something is wrong');
      }

      function issueIDToken(client, user, areq, accessToken) {
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
        expect(accessToken).to.equal('xyz');

        return 'idtoken';
      }


      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'id_token token',
          redirectURI: 'http://example.com/auth/callback',
          state: 'f1o1o1',
          nonce: 'n-0S6_WzA2Mj'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };

        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=Bearer&state=f1o1o1&id_token=idtoken');
      });
    });

    describe('transaction that adds params to response', function() {
      function issueToken(client, user) {
        if (client.id == 'c223' && user.id == 'u123') {
          return ['xyz', { 'expires_in': 3600 }];
        }
        throw new Error('something is wrong');
      }

      function issueIDToken(client, user, areq, accessToken) {
        expect(client.id).to.equal('c223');
        expect(user.id).to.equal('u123');
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
        expect(accessToken).to.equal('xyz');

        return 'idtoken';
      }


      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'c223', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'id_token token',
          redirectURI: 'http://example.com/auth/callback',
          nonce: 'n-0S6_WzA2Mj'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };

        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&expires_in=3600&token_type=Bearer&id_token=idtoken');
      });
    });

    describe('transaction that adds params including token_type to response', function() {
      function issueToken(client, user) {
        if (client.id == 'c323' && user.id == 'u123') {
          return ['xyz', { 'token_type': 'foo', 'expires_in': 3600 }];
        }
        throw new Error('something is wrong');
      }

      function issueIDToken(client, user, areq, accessToken) {
        expect(client.id).to.equal('c323');
        expect(user.id).to.equal('u123');
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
        expect(accessToken).to.equal('xyz');

        return 'idtoken';
      }


      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'c323', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'id_token token',
          redirectURI: 'http://example.com/auth/callback',
          nonce: 'n-0S6_WzA2Mj'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };

        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=foo&expires_in=3600&id_token=idtoken');
      });
    });

    describe('disallowed transaction', function() {
      function issueToken(client, user) {
        if (client.id == 'c123' && user.id == 'u123') {
          return 'xyz';
        }
        throw new Error('something is wrong');
      }

      function issueIDToken(client, user, areq, accessToken) {
        return 'idtoken';
      }


      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'id_token token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: false };

        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#error=access_denied');
      });
    });

    describe('disallowed transaction with request state', function() {
      function issueToken(client, user) {
        if (client.id == 'c123' && user.id == 'u123') {
          return 'xyz';
        }
        throw new Error('something is wrong');
      }

      function issueIDToken(client, user, areq, accessToken) {
        return 'idtoken';
      }


      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'id_token token',
          redirectURI: 'http://example.com/auth/callback',
          state: 'f2o2o2'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: false };

        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#error=access_denied&state=f2o2o2');
      });
    });

    describe('unauthorized client', function() {
      function issueToken(client, user) {
        if (client.id == 'cUNAUTHZ') {
          return false;
        }
        throw new Error('something is wrong');
      }

      function issueIDToken(client, user, areq, accessToken) {
        return 'idtoken';
      }


      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'cUNAUTHZ', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'id_token token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };

        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.constructor.name).to.equal('AuthorizationError');
        expect(err.message).to.equal('Request denied by authorization server');
        expect(err.code).to.equal('access_denied');
        expect(err.status).to.equal(403);
      });
    });

    describe('encountering an error while issuing token', function() {
      function issueToken(client, user) {
        if (client.id == 'cUNAUTHZ') {
          return false;
        }
        throw new Error('something is wrong');
      }

      function issueIDToken(client, user, areq, accessToken) {
        return 'idtoken';
      }


      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'cERROR', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'id_token token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };

        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something is wrong');
      });
    });

    describe('throwing an error while issuing token', function() {
      function issueToken(client, user) {
        if (client.id == 'cTHROW') {
          throw new Error('something was thrown');
        }
        throw new Error('something is wrong');
      }

      function issueIDToken(client, user, areq, accessToken) {
        return 'idtoken';
      }

      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'cTHROW', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'id_token token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };

        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something was thrown');
      });
    });

    describe('transaction without redirect URL', function() {
      function issueToken(client, user) {
        if (client.id == 'c123' && user.id == 'u123') {
          return 'xyz';
        }
        throw new Error('something is wrong');
      }

      function issueIDToken(client, user, areq, accessToken) {
        return 'idtoken';
      }


      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'c123', name: 'Example' };
        txn.req = {
          type: 'id_token token',
          redirectURI: 'http://example.com/auth/callback'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true };

        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('Unable to issue redirect for OAuth 2.0 transaction');
      });
    });
  });

  describe('decision handling with user response', function() {
    function issueToken(client, user, ares) {
      if (client.id == 'c123' && user.id == 'u123' && ares.scope == 'foo') {
        return 'xyz';
      }
      throw new Error('something is wrong');
    }

    function issueIDToken(client, user, areq, accessToken) {
      expect(client.id).to.equal('c123');
      expect(user.id).to.equal('u123');
      expect(areq.nonce).to.equal('n-0S6_WzA2Mj');
      expect(accessToken).to.equal('xyz');

      return 'idtoken';
    }

    describe('transaction with response scope', function() {
      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idTokenToken(issueToken, issueIDToken));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://example.com/auth/callback';
        txn.req = {
          type: 'id_token token',
          redirectURI: 'http://example.com/auth/callback',
          nonce: 'n-0S6_WzA2Mj'
        };
        txn.user = { id: 'u123', name: 'Bob' };
        txn.res = { allow: true, scope: 'foo' };

        try{
          await server._respond(ctx, function() {
            throw new Error('This should not be called');
          });
        } catch(e) {
          err = e;
        }

        done();
      });

      it('should respond', function() {
        expect(ctx.status).to.equal(302);
        expect(ctx.response.get('Location')).to.equal('http://example.com/auth/callback#access_token=xyz&token_type=Bearer&id_token=idtoken');
      });
    });
  });

});
