'use strict';

class Request {

}

class Response {
  constructor() {
    this.headers = {};
  }

  get header() {
    return this.headers;
  }

  get(name) {
    return this.headers[name.toLowerCase()];
  }

  set(name, val) {
    this.headers[name.toLowerCase()] = val;
  }

  redirect(url) {
    this.set('Location', url);
    this.status = this.status || 302;
  }
}

class Context {

  constructor() {
    this.request = new Request();
    this.response = new Response();

    this.state = {};
  }

  get body() {
    return this.response.body;
  }

  set body(val) {
    this.response.body = val;
  }

  get query() {
    return this.request.query;
  }

  get status() {
    return this.response.status;
  }

  set status(val) {
    this.response.status = val;
  }

  set(name, val) {
    this.response.set(name, val);
  }

  redirect(url, alt) {
    return this.response.redirect(url, alt);
  }

}

module.exports = Context;
