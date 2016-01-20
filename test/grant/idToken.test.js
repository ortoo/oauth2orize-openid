/* global describe, it, expect, before */
var chai = require('chai')
  , Context = require('../context')
  , oauth = require('oauth2orize-koa')
  , idToken = require('../../lib/grant/idToken');


describe('grant.idToken', function() {

  describe('module', function() {
    var mod = idToken(function(){});

    it('should be named id_token', function() {
      expect(mod.name).to.equal('id_token');
    });

    it('should expose request and response functions', function() {
      expect(mod.request).to.be.a('function');
      expect(mod.response).to.be.a('function');
    });
  });

  it('should throw if constructed without a issue callback', function() {
    expect(function() {
      idToken();
    }).to.throw(TypeError, 'oauth2orize-openid.idToken grant requires an issue callback');
  });

  describe('request parsing', function() {
    function issue(){}

    describe('request', function() {
      var err, out;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idToken(issue));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token', ctx);
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
        server.grant(idToken(issue));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token', ctx);
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
        server.grant(idToken(issue));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read write';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token', ctx);
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
        server.grant(idToken({ scopeSeparator: ',' }, issue));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read,write';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token', ctx);
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
        server.grant(idToken({ scopeSeparator: [' ', ','] }, issue));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read write';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token', ctx);
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
        server.grant(idToken({ scopeSeparator: [' ', ','] }, issue));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.client_id = 'c123';
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.scope = 'read,write';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token', ctx);
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
        server.grant(idToken(issue));
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.redirect_uri = 'http://example.com/auth/callback';
        ctx.request.query.state = 'f1o1o1';

        try {
          out = await server._parse('id_token', ctx);
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
      function issueIDToken(client, user, areq) {
        expect(client.id).to.equal('c123');
        expect(user.id).to.equal('u123');
        expect(areq.nonce).to.equal('n-0S6_WzA2Mj');

        return 'idtoken';
      }


      var ctx, err;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(idToken(issueIDToken));

        ctx = new Context();
        var txn = ctx.state.oauth2 = {};
        txn.client = { id: 'c123', name: 'Example' };
        txn.redirectURI = 'http://www.example.com/auth/callback';
        txn.req = {
          type: 'id_token',
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
        expect(ctx.response.get('Location')).to.equal('http://www.example.com/auth/callback#id_token=idtoken');
      });
    });

  });

});
