/*!
 * Express - IP Filter
 * Copyright(c) 2014 Bradley and Montgomery Inc.
 * MIT Licensed
 */

'use strict';

/**
 * Module dependencies.
 */

var _ = require('lodash');
var ipUtil = require('ip');
var rangeCheck = require('range_check');
var IpDeniedError = require('./deniedError');

/**
 * express-ipfilter:
 *
 * IP Filtering middleware;
 *
 * Examples:
 *
 *      let ipfilter = require('ipfilter'),
 *          ips = ['127.0.0.1'];
 *          getIps = function() { return ['127.0.0.1']; };
 *
 *      app.use(ipfilter(ips));
 *      app.use(ipfilter(getIps));
 *
 * Options:
 *
 *  - `mode` ['allow','deny'], whether to deny or grant access to the IPs provided. Defaults to 'deny'.
 *  - `logF` Function to use for logging.
 *  - `log` console log actions. Defaults to true.
 *  - `allowedHeaders` Array of headers to check for forwarded IPs.
 *  - 'excluding' routes that should be excluded from ip filtering
 *
 * @param [ips] {Array} IP addresses or {Function} that returns the array of IP addresses
 * @param [opts] {Object} options
 * @api public
 */
module.exports = function ipFilter(ips, opts) {
  ips = ips || false;

  var MODE_ALLOW = 'allow';
  var MODE_DENY = 'deny';
  var LOG_LEVEL_ALLOW = MODE_ALLOW;
  var LOG_LEVEL_DENY = MODE_DENY;
  var LOG_LEVEL_ALL = 'all';

  var isGetIpsFunction = _.isFunction(ips);
  var getIps = isGetIpsFunction ? ips : function () {
    return ips;
  };

  var logger = function logger(message) {
    console.log(message);
  };
  var settings = _.defaults(opts || {}, {
    mode: MODE_DENY,
    log: true,
    logLevel: LOG_LEVEL_ALL,
    logF: logger,
    allowedHeaders: [],
    excluding: [],
    detectIp: getClientIp
  });

  function getClientIp(req) {
    var ipAddress = void 0;

    var headerIp = _.reduce(settings.allowedHeaders, function (acc, header) {
      var testIp = req.headers[header];
      if (testIp !== '') {
        acc = testIp;
      }

      return acc;
    }, '');

    if (headerIp) {
      var splitHeaderIp = headerIp.split(',');
      ipAddress = splitHeaderIp[0];
    }

    if (!ipAddress) {
      ipAddress = req.connection.remoteAddress;
    }

    if (!ipAddress) {
      return '';
    }

    if (ipUtil.isV6Format(ipAddress) && ~ipAddress.indexOf('::ffff')) {
      ipAddress = ipAddress.split('::ffff:')[1];
    }

    if (ipUtil.isV4Format(ipAddress) && ~ipAddress.indexOf(':')) {
      ipAddress = ipAddress.split(':')[0];
    }

    return ipAddress;
  }

  var matchClientIp = function matchClientIp(ip) {
    // optimize search, stop if found
    var result = _.find(getIps(), function (constraint) {
      return testIp(ip, constraint);
    });
    return result !== undefined;
  };

  var testIp = function testIp(ip, constraint, mode) {
    // Check if a single ip or a range
    if (typeof constraint === 'string') {
      if (rangeCheck.validRange(constraint)) {
        return testCidrBlock(ip, constraint, mode);
      } else {
        return testExplicitIp(ip, constraint, mode);
      }
    }

    if (Array.isArray(constraint)) {
      if (constraint.length !== 2) {
        throw new Error('Range constraint must contains 2 elements');
      }
      return testRange(ip, constraint);
    }

    throw new Error('constraint not supported');
  };

  var testExplicitIp = function testExplicitIp(ip, constraint) {
    return ip === constraint;
  };

  var testCidrBlock = function testCidrBlock(ip, constraint) {
    return rangeCheck.inRange(ip, constraint);
  };

  var testRange = function testRange(ip, constraintRange) {
    var startIp = ipUtil.toLong(constraintRange[0]);
    var endIp = ipUtil.toLong(constraintRange[1]);
    var longIp = ipUtil.toLong(ip);
    return longIp >= startIp && longIp <= endIp;
  };

  var error = function error(ip, next) {
    var err = new IpDeniedError('Access denied to IP address: ' + ip);
    return next(err);
  };

  // region prepare option to avoid costly object creation for each request
  var optimized = {};

  var init = function init() {
    checkSettings();
    // optimize mode to avoid costly string comparison
    optimized.isAllowMode = settings.mode === MODE_ALLOW;
    optimized.hasExcluding = settings.excluding.length;
    optimized.exludingRegExp = _.map(settings.excluding, function (exclude) {
      return new RegExp(exclude);
    });
    optimized.isLogAllow = settings.log && _.indexOf([LOG_LEVEL_ALL, LOG_LEVEL_ALLOW], settings.logLevel) > -1;
    optimized.isLogDeny = settings.log && _.indexOf([LOG_LEVEL_ALL, LOG_LEVEL_DENY], settings.logLevel) > -1;
  };

  var checkSettings = function checkSettings() {
    if (_.indexOf([MODE_ALLOW, MODE_DENY], settings.mode) < 0) {
      throw new Error('mode must be ' + MODE_ALLOW + ' or ' + MODE_DENY);
    }
    if (_.indexOf([LOG_LEVEL_ALL, LOG_LEVEL_ALLOW, LOG_LEVEL_DENY], settings.logLevel) < 0) {
      throw new Error('logLevel must be ' + LOG_LEVEL_ALL + ', ' + LOG_LEVEL_ALLOW + ' or ' + LOG_LEVEL_DENY);
    }
    checkIps();
  };

  var checkIps = function checkIps() {
    if (!isGetIpsFunction) {
      var _ips2 = getIps();
      // check if string, or Range
      _.each(_ips2, function (constraint) {
        if (typeof constraint === 'string') {
          return true;
        }
        if (Array.isArray(constraint)) {
          if (constraint.length !== 2) {
            throw new Error('Range constraint must contains 2 elements');
          }
          return true;
        }
        throw new Error('Range constraint not supported');
      });
    }
  };

  init();
  // endregion

  return function (req, res, next) {
    if (optimized.hasExcluding) {
      var findExcluding = _.find(optimized.exludingRegExp, function (regex) {
        return regex.test(req.url);
      });

      if (findExcluding !== undefined) {
        if (optimized.isLogAllow) {
          settings.logF('Access granted for excluded path: ' + req.url);
        }
        return next();
      }
    }

    var _ips = getIps();
    if (!_ips || !_ips.length) {
      if (optimized.isAllowMode) {
        // ip list is empty, thus no one allowed
        return error('0.0.0.0/0', next);
      } else {
        // there are no blocked ips, skip
        return next();
      }
    }

    var ip = settings.detectIp(req);
    var ipFound = matchClientIp(ip, req);
    if (ipFound && optimized.isAllowMode) {
      // Grant access
      if (optimized.isLogAllow) {
        settings.logF('Access granted to IP address: ' + ip);
      }
      return next();
    }

    // Deny access
    if (optimized.isLogDeny) {
      settings.logF('Access denied to IP address: ' + ip);
    }

    return error(ip, next);
  };
};
//# sourceMappingURL=ipfilter.js.map
