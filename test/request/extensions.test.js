/* global describe, it, expect, before */
var chai = require('chai')
  , Context = require('../context')
  , oauth = require('oauth2orize-koa')
  , extensions = require('../../lib/request/extensions')
  , qs = require('querystring')


describe('authorization request extensions', function() {

  describe('module', function() {
    var mod = extensions();

    it('should be wildcard', function() {
      expect(mod.name).to.equal('*');
    });

    it('should expose request and response functions', function() {
      expect(mod.request).to.be.a('function');
      expect(mod.response).to.be.undefined;
    });
  });

  describe('request parsing', function() {

    describe('request with all parameters', function() {
      var err, ext;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(extensions());
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.nonce = 'a1b2c3';
        ctx.request.query.display = 'touch';
        ctx.request.query.prompt = 'none';
        ctx.request.query.max_age = '600';
        ctx.request.query.ui_locales = 'en-US';
        ctx.request.query.claims_locales = 'en';
        ctx.request.query.id_token_hint = 'HEADER.PAYLOAD.SIGNATURE';
        ctx.request.query.login_hint = 'bob@example.com';
        ctx.request.query.acr_values = '0';

        try {
          ext = await server._parse('code token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(ext.nonce).to.equal('a1b2c3');
        expect(ext.display).to.equal('touch');
        expect(ext.prompt).to.be.an('array');
        expect(ext.prompt).to.have.length(1);
        expect(ext.prompt[0]).to.equal('none');
        expect(ext.maxAge).to.equal(600);
        expect(ext.uiLocales).to.be.an('array');
        expect(ext.uiLocales).to.have.length(1);
        expect(ext.uiLocales[0]).to.equal('en-US');
        expect(ext.claimsLocales).to.be.an('array');
        expect(ext.claimsLocales).to.have.length(1);
        expect(ext.claimsLocales[0]).to.equal('en');
        expect(ext.idTokenHint).to.equal('HEADER.PAYLOAD.SIGNATURE');
        expect(ext.loginHint).to.equal('bob@example.com');
        expect(ext.acrValues).to.be.an('array');
        expect(ext.acrValues).to.have.length(1);
        expect(ext.acrValues[0]).to.equal('0');
      });
    });

    describe('request without parameters', function() {
      var err, ext;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(extensions());
        var ctx = new Context();
        ctx.request.query = {};

        try {
          ext = await server._parse('code token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(ext.nonce).to.be.undefined;
        expect(ext.display).to.equal('page');
        expect(ext.prompt).to.be.undefined;
        expect(ext.maxAge).to.be.undefined;
        expect(ext.uiLocales).to.be.undefined;
        expect(ext.claimsLocales).to.be.undefined;
        expect(ext.idTokenHint).to.be.undefined;
        expect(ext.loginHint).to.be.undefined;
        expect(ext.acrValues).to.be.undefined;
        expect(ext.claims).to.be.undefined;
      });
    });

    describe('request with multiple prompts', function() {
      var err, ext;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(extensions());
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.prompt = 'login consent';

        try {
          ext = await server._parse('code token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(ext.prompt).to.be.an('array');
        expect(ext.prompt).to.have.length(2);
        expect(ext.prompt[0]).to.equal('login');
        expect(ext.prompt[1]).to.equal('consent');
      });
    });

    describe('request with multiple UI locales', function() {
      var err, ext;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(extensions());
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.ui_locales = 'en es';

        try {
          ext = await server._parse('code token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(ext.uiLocales).to.be.an('array');
        expect(ext.uiLocales).to.have.length(2);
        expect(ext.uiLocales[0]).to.equal('en');
        expect(ext.uiLocales[1]).to.equal('es');
      });
    });

    describe('request with multiple claims locales', function() {
      var err, ext;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(extensions());
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.claims_locales = 'en es';

        try {
          ext = await server._parse('code token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(ext.claimsLocales).to.be.an('array');
        expect(ext.claimsLocales).to.have.length(2);
        expect(ext.claimsLocales[0]).to.equal('en');
        expect(ext.claimsLocales[1]).to.equal('es');
      });
    });

    describe('request with multiple ACR values', function() {
      var err, ext;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(extensions());
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.acr_values = '2 1';

        try {
          ext = await server._parse('code token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(ext.acrValues).to.be.an('array');
        expect(ext.acrValues).to.have.length(2);
        expect(ext.acrValues[0]).to.equal('2');
        expect(ext.acrValues[1]).to.equal('1');
      });
    });

    describe('request with claims', function() {
      var err, ext;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(extensions());
        var ctx = new Context();
        // http://lists.openid.net/pipermail/openid-specs-mobile-profile/Week-of-Mon-20141124/000070.html
        ctx.request.query = qs.parse('response_type=code&client_id=ABCDEFABCDEFABCDEFABCDEF&scope=openid&redirect_uri=https%3A%2F%2Femail.t-online.de%2F%3Fpf%3D%2Fem&claims=%7B%0A++%22id_token%22%3A%0A++%7B%0A+++%22email%22%3A+%7B%22essential%22%3A+true%7D%0A++%7D%0A%7D');


        try {
          ext = await server._parse('code token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(ext.claims).to.be.an('object');
        expect(ext.claims.id_token).to.be.an('object');
        expect(ext.claims.id_token.email).to.be.an('object');
        expect(ext.claims.id_token.email.essential).to.equal(true);
      });
    });

    describe('request with claims that fail to parse as JSON', function() {
      var err, ext;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(extensions());
        var ctx = new Context();
        // http://lists.openid.net/pipermail/openid-specs-mobile-profile/Week-of-Mon-20141124/000070.html
        ctx.request.query = {};
        ctx.request.query.claims = 'xyz';

        try {
          ext = await server._parse('code token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should throw error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.constructor.name).to.equal('AuthorizationError');
        expect(err.message).to.equal('Failed to parse claims as JSON');
      });
    });

    describe('request with registration', function() {
      var err, ext;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(extensions());
        var ctx = new Context();
        ctx.request.query = qs.parse('response_type=id_token&client_id=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj&registration=%7B%22logo_uri%22%3A%22https%3A%2F%2Fclient.example.org%2Flogo.png%22%7D')

        try {
          ext = await server._parse('code token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should parse request', function() {
        expect(ext.registration).to.be.an('object');
        expect(ext.registration.logo_uri).to.equal('https://client.example.org/logo.png');
      });
    });

    describe('request with registration that fails to parse as JSON', function() {
      var err, ext;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(extensions());
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.registration = 'xyz';

        try {
          ext = await server._parse('code token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should throw error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.constructor.name).to.equal('AuthorizationError');
        expect(err.message).to.equal('Failed to parse registration as JSON');
      });
    });

    describe('request with prompt including none with other values', function() {
      var err, ext;

      before(async function(done) {
        var server = oauth.createServer();
        server.grant(extensions());
        var ctx = new Context();
        ctx.request.query = {};
        ctx.request.query.prompt = 'none login';

        try {
          ext = await server._parse('code token', ctx);
        } catch (e) {
          err = e;
        }

        done();
      });

      it('should throw error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.constructor.name).to.equal('AuthorizationError');
        expect(err.message).to.equal('Prompt includes none with other values');
      });
    });

  });

});
