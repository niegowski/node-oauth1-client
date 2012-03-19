// Copyright (c) 2012 Kuba Niegowski
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

"use strict";

var URL = require("url"),
    util = require("util"),
    http = require("http"),
    https = require("https"),
    crypto = require("crypto"),
    events = require("events"),
    querystring = require("querystring");


var OAuth = exports.OAuth = function(consumer_key, consumer_secret, version, signature_method) {
    events.EventEmitter.call(this);
    
    this._consumer_key = consumer_key;
    this._consumer_secret = consumer_secret;
    this._token = "";
    this._token_secret = "";
    this._version = version || "1.0a";
    this._signature_method = signature_method || "HMAC-SHA1";
    this._state = "";
    
    if (this._signature_method != "HMAC-SHA1")
        throw new Error("Only HMAC-SHA1 signature method is supported");
};

util.inherits(OAuth, events.EventEmitter);

OAuth.prototype.isComplete = function() {
    return this._state == "complete";
};

// extra_params ie scope
OAuth.prototype.start = function(url, callback_url, extra_params) {
    
    if (this._state) 
        return this.emit("error", new Error("Authorization unexpected state: " + this._state));
        
    this._state = "starting";
    
    extra_params || (extra_params = {});

    var post_body = extra_params ? querystring.stringify(extra_params) : "",
        headers = {
            "content-length": post_body ? Buffer.byteLength(post_body) : 0,
            "content-type": "application/x-www-form-urlencoded"
        };
        
    if (callback_url) 
        extra_params.oauth_callback = callback_url;

    var request = this.request(merge(URL.parse(url), {
            method: "POST", 
            headers: headers, 
            params: extra_params
        }));

    request.on("response", this._handleResponse.bind(this, {
        type: "confirm", 
        data: ""
    }));
    request.on("error", this.emit.bind(this, "error"));
    
    request.write(post_body);
    request.end();
    
    return this;
};


// oauth_verifier comes from callback redirect
OAuth.prototype.verify = function(url, oauth_verifier) {

    if (this._state != "started")
        return this.emit("error", new Error("Authorization unexpected state: " + this._state));
        
    this._state = "verifying";

    var headers = {
            "content-type": "application/x-www-form-urlencoded"
        },
        request = this.request(merge(URL.parse(url), {
            method: "POST", 
            headers: headers, 
            params: {
                oauth_verifier: oauth_verifier
            }
        }));

    request.on("response", this._handleResponse.bind(this, {
        type: "complete", 
        data: ""
    }));
    request.on("error", this.emit.bind(this, "error"));
    
    request.end();
    
    return this;
};

// all get and post params must be used for signing
OAuth.prototype.request = OAuth.prototype.createRequest = function(options, callback) {

    var url = URL.format(options),
        parsed_url = URL.parse(url, true);
    
    var headers = options.headers = options.headers || {};
    headers.host = headers.host || options.hostname || options.host;
    headers.authorization = this._makeAuthorizationHeader(options.method || "GET", url, 
        merge({}, parsed_url.query, options.params)
    );

    return (options.protocol == "https:" ? https : http).request(options, callback);
};

OAuth.prototype.clear = function() {
    
    this._token = "";
    this._token_secret = "";
    this._state = "";
};

OAuth.prototype.serialize = function() {
    
    if (!this.isComplete())
        return "";
    
    return new Buffer(JSON.stringify({
        token: this._token,
        secret: this._token_secret
    }), "utf8").toString("base64");
};

OAuth.prototype.unserialize = function(data) {

    this.clear();
    
    var obj = JSON.parse(new Buffer(data, "base64").toString("utf8"));
    this._token = obj.token;
    this._token_secret = obj.secret;
    this._state = "complete";
    
    return this;
};

OAuth.prototype._handleResponse = function(ctx, response) {
    response.setEncoding("utf8");
  
    response.on("data", function(data) {
        ctx.data += data;
    });
  
    response.on("end", this._handleResponseEnd.bind(this, ctx, response));
    response.on("close", this._handleResponseEnd.bind(this, ctx, response));
};

OAuth.prototype._handleResponseEnd = function(ctx, response) {
    response.removeAllListeners("end");
    response.removeAllListeners("close");
    
    if (response.statusCode >= 200 && response.statusCode < 300) {

        var result = querystring.parse(ctx.data);
        this._token = result.oauth_token;
        this._token_secret = result.oauth_token_secret;
        
        if (ctx.type == "complete")
            this._state = "complete";
        else if (ctx.type == "confirm")
            this._state = "started";
        
        this.emit(ctx.type, result.oauth_token);

    } else if (response.statusCode == 301 || response.statusCode == 302) {
        this.emit("error", new Error("Redirects are not supported"));
        
    } else {
        this.emit("error", new Error("HTTP Status code: " + response.statusCode));
    }
};



OAuth.prototype._makeAuthorizationHeader = function(method, url, params) {
    
    var list = this._makeParamsList(merge({
            oauth_timestamp: Math.floor(new Date().getTime() / 1000),
            oauth_nonce: this._makeNonce(32),
            oauth_version: this._version,
            oauth_signature_method: this._signature_method,
            oauth_consumer_key: this._consumer_key
        }, params, this._token ? {
            oauth_token: this._token
        } : null
    ));
    
    var args = "";
    for (var i = 0; i < list.length; i++) {
        args += list[i][0] + "=" + list[i][1];
        if (i < list.length-1) args += "&";
    }
    list.push(["oauth_signature", this._createSignature(method, url, args)]);
    
    var header = "OAuth ";
    for (var i = 0; i < list.length; i++) {
        if (list[i][0].match(/^oauth_/i))
            header += list[i][0] + "=\"" + list[i][1] + "\", ";
    }
    return header.substring(0, header.length-2);
};

OAuth.prototype._makeParamsList = function(params) {

    var list = [];
    for (var key in params)
        list.push([key, params[key]]);

    for (var i = 0; i < list.length; i++) {
        list[i][0] = escape(list[i][0]);
        list[i][1] = escape(list[i][1]);
    }
    
    list = list.sort(function(a, b) {
        if (a[0] == b[0])
            return a[1] < b[1] ? -1 : 1;
        return a[0] < b[0] ? -1 : 1;
    });
    
    return list;
};

OAuth.prototype._createSignature = function(method, url, args) {
    
    var signature = "";
    
    if (this._signature_method == "HMAC-SHA1") {
        
        var key = escape(this._consumer_secret) + "&" + escape(this._token_secret);
        signature = crypto.createHmac("sha1", key)
                        .update(method.toUpperCase() + "&" + escape(url) + "&" + escape(args))
                        .digest("base64");
    }
    
    return escape(signature);
};

OAuth.prototype._makeNonce = function(nonceSize) {
   var result = "";
   for (var i = 0; i < nonceSize; i++)
       result += Math.floor(Math.random() * 16).toString(16);
   return result;
};




var merge = exports.merge = function(dst) {
    for (var i = 1; i < arguments.length; i++) {
        var src = arguments[i];
        if (src) {
            for (var key in src) {
                if (src.hasOwnProperty(key))
                    dst[key] = src[key];
            }
        }
    }
    return dst;
};

var escape = function(string) {
    return (encodeURIComponent(string)
                .replace(/!/g, "%21")
                .replace(/'/g, "%27")
                .replace(/\(/g, "%28")
                .replace(/\)/g, "%29")
                .replace(/\*/g, "%2A")
            );
};

