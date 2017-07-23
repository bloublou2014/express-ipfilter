/*!
 * Express - IP Filter
 * Copyright(c) 2014 Bradley and Montgomery Inc.
 * MIT Licensed
 */

'use strict';

/**
 * Module dependencies.
 */
let _ = require('lodash');
let ipUtil = require('ip');
let rangeCheck = require('range_check');
let IpDeniedError = require('./deniedError');

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

  const MODE_ALLOW = 'allow';
  const MODE_DENY = 'deny';
  const LOG_LEVEL_ALLOW = MODE_ALLOW;
  const LOG_LEVEL_DENY = MODE_DENY;
  const LOG_LEVEL_ALL = 'all';

  let isGetIpsFunction = _.isFunction(ips);
  let getIps = isGetIpsFunction ? ips : function () {
    return ips;
  };

  let logger = function (message) {
    console.log(message);
  };
  let settings = _.defaults(opts || {}, {
    mode: MODE_DENY,
    log: true,
    logLevel: LOG_LEVEL_ALL,
    logF: logger,
    allowedHeaders: [],
    excluding: [],
    detectIp: getClientIp
  });

  function getClientIp(req) {
    let ipAddress;

    let headerIp = _.reduce(settings.allowedHeaders, function (acc, header) {
      let testIp = req.headers[header];
      if (testIp !== '') {
        acc = testIp;
      }

      return acc;
    }, '');

    if (headerIp) {
      let splitHeaderIp = headerIp.split(',');
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

  let matchClientIp = function (ip) {
    // optimize search, stop if found
    let result = _.find(getIps(), function (constraint) {
      return testIp(ip, constraint);
    });
    return result !== undefined;
  };

  let testIp = function (ip, constraint, mode) {
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

  let testExplicitIp = function (ip, constraint) {
    return (ip === constraint);
  };

  let testCidrBlock = function (ip, constraint) {
    return (rangeCheck.inRange(ip, constraint));
  };

  let testRange = function (ip, constraintRange) {
    let startIp = ipUtil.toLong(constraintRange[0]);
    let endIp = ipUtil.toLong(constraintRange[1]);
    let longIp = ipUtil.toLong(ip);
    return (longIp >= startIp && longIp <= endIp);
  };

  let error = function (ip, next) {
    let err = new IpDeniedError('Access denied to IP address: ' + ip);
    return next(err);
  };

  // region prepare option to avoid costly object creation for each request
  let optimized = {};

  let init = function () {
    checkSettings();
    // optimize mode to avoid costly string comparison
    optimized.isAllowMode = (settings.mode === MODE_ALLOW);
    optimized.hasExcluding = (settings.excluding.length);
    optimized.exludingRegExp = _.map(settings.excluding, function (exclude) {
      return new RegExp(exclude);
    });
    optimized.isLogAllow = (settings.log && _.indexOf([LOG_LEVEL_ALL, LOG_LEVEL_ALLOW], settings.logLevel) > -1);
    optimized.isLogDeny = (settings.log && _.indexOf([LOG_LEVEL_ALL, LOG_LEVEL_DENY], settings.logLevel) > -1);
  };

  let checkSettings = function () {
    if (_.indexOf([MODE_ALLOW, MODE_DENY], settings.mode) < 0) {
      throw new Error('mode must be ' + MODE_ALLOW + ' or ' + MODE_DENY);
    }
    if (_.indexOf([LOG_LEVEL_ALL, LOG_LEVEL_ALLOW, LOG_LEVEL_DENY], settings.logLevel) < 0) {
      throw new Error('logLevel must be ' + LOG_LEVEL_ALL + ', ' + LOG_LEVEL_ALLOW + ' or ' + LOG_LEVEL_DENY);
    }
    checkIps();
  };

  let checkIps = function () {
    if (!isGetIpsFunction) {
      let ips = getIps();
      // check if string, or Range
      _.each(ips, function (constraint) {
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
      let findExcluding = _.find(optimized.exludingRegExp, function (regex) {
        return regex.test(req.url);
      });

      if (findExcluding !== undefined) {
        if (optimized.isLogAllow) {
          settings.logF('Access granted for excluded path: ' + req.url);
        }
        return next();
      }
    }

    let _ips = getIps();
    if (!_ips || !_ips.length) {
      if (optimized.isAllowMode) {
        // ip list is empty, thus no one allowed
        return error('0.0.0.0/0', next);
      } else {
        // there are no blocked ips, skip
        return next();
      }
    }

    let ip = settings.detectIp(req);
    let ipFound = matchClientIp(ip, req);
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
