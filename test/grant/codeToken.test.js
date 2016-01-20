/* global describe, it, expect, before */
var chai = require('chai')
  , Context = require('../context')
  , oauth = require('oauth2orize-koa')
  , codeToken = require('../../lib/grant/codeToken');


describe('grant.codeToken', function() {

  describe('module', function() {
    var mod = codeToken(function(){}, function(){});

    it('should be named code token', function() {
      expect(mod.name).to.equal('code token');
    });

    it('should expose request and response functions', function() {
      expect(mod.request).to.be.a('function');
      expect(mod.response).to.be.a('function');
    });
  });

  it('should throw if constructed without a issueToken callback', function() {
    expect(function() {
      codeToken();
    }).to.throw(TypeError, 'oauth2orize-openid.codeToken grant requires an issueToken callback');
  });

  it('should throw if constructed without a issueCode callback', function() {
    expect(function() {
      codeToken(function(){});
    }).to.throw(TypeError, 'oauth2orize-openid.codeToken grant requires an issueCode callback');
  });

  describe('request parsing', function() {
    function issueToken(){}
    function issueCode(){}

    describe('request', function() {
      var err, out;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(codeToken(issueToken, issueCode));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('code token', ctx);
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
        server.grant(codeToken(issueToken, issueCode));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('code token', ctx);
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
        server.grant(codeToken(issueToken, issueCode));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read write';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('code token', ctx);
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
        server.grant(codeToken({ scopeSeparator: ',' }, issueToken, issueCode));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read,write';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('code token', ctx);
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
        server.grant(codeToken({ scopeSeparator: [' ', ','] }, issueToken, issueCode));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read write';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('code token', ctx);
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
        server.grant(codeToken({ scopeSeparator: [' ', ','] }, issueToken, issueCode));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read,write';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('code token', ctx);
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
        server.grant(codeToken(issueToken, issueCode));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('code token', ctx);
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
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');

        return 'at-xyz';
      }

      function issueCode(client, redirectURI, user) {
        expect(client.id).to.equal('c123');
        expect(redirectURI).to.equal('http://example.com/auth/callback');
        expect(user.id).to.equal('u123');

        return 'c-123';
      }


      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(codeToken(issueToken, issueCode));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://www.example.com/auth/callback';
        txn.req = {
          type: 'code token',
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
        expect(ctx.response.get('Location')).to.equal('http://www.example.com/auth/callback#access_token=at-xyz&token_type=Bearer&code=c-123');
      });
    });

  });

});
