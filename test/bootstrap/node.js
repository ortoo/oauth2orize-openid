require('babel-register')({
  only: './test/'
});
var chai = require('chai');

global.expect = chai.expect;
