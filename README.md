# egg-oauth2.0

[![NPM version][npm-image]][npm-url]
[![build status][travis-image]][travis-url]
[![Test coverage][codecov-image]][codecov-url]
[![David deps][david-image]][david-url]
[![Known Vulnerabilities][snyk-image]][snyk-url]
[![npm download][download-image]][download-url]

[npm-image]: https://img.shields.io/npm/v/egg-oauth2.0.svg?style=flat-square
[npm-url]: https://npmjs.org/package/egg-oauth2.0
[travis-image]: https://img.shields.io/travis/eggjs/egg-oauth2.0.svg?style=flat-square
[travis-url]: https://travis-ci.org/eggjs/egg-oauth2.0
[codecov-image]: https://img.shields.io/codecov/c/github/eggjs/egg-oauth2.0.svg?style=flat-square
[codecov-url]: https://codecov.io/github/eggjs/egg-oauth2.0?branch=master
[david-image]: https://img.shields.io/david/eggjs/egg-oauth2.0.svg?style=flat-square
[david-url]: https://david-dm.org/eggjs/egg-oauth2.0
[snyk-image]: https://snyk.io/test/npm/egg-oauth2.0/badge.svg?style=flat-square
[snyk-url]: https://snyk.io/test/npm/egg-oauth2.0
[download-image]: https://img.shields.io/npm/dm/egg-oauth2.0.svg?style=flat-square
[download-url]: https://npmjs.org/package/egg-oauth2.0

<!--
Description here.
-->

## Install

```bash
$ npm i egg-oauth2.0 --save
```

## Usage

```js
// {app_root}/config/plugin.js
exports.oauth20 = {
  enable: true,
  package: 'egg-oauth2.0',
};
```

## Configuration

```js
// {app_root}/config/config.default.js
exports.oauth20 = {
};
```

see [config/config.default.js](config/config.default.js) for more detail.

## Example

<!-- example here -->

## Questions & Suggestions

Please open an issue [here](https://github.com/eggjs/egg/issues).

## License

[MIT](LICENSE)
