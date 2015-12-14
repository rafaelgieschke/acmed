#!/usr/bin/env node
"use strict";

/**
 * @license
 * Copyright 2015 Rafael Gieschke.
 * Released under the MIT License (<https://opensource.org/licenses/MIT>).
 */

const CONF = "/etc/nghttpx/";
const PROD = "https://acme-v01.api.letsencrypt.org/directory";
const TEST = "https://acme-staging.api.letsencrypt.org/directory";
const DEBUG = false;

const fs = require("fs");
const jose = require("node-jose");
const fetch = require("node-fetch");
const KJUR = require("jsrsasign");
const crypto = require("crypto");
const child_process = require("child_process");
const URLSafeBase64 = require("urlsafe-base64");
const toArray = require("stream-to-array");
const urlParsing = require("url");

Promise.resolve().then(async(function* () {
  try {
    fs.statSync(`${CONF}/default.cert`);
  } catch (e) {
    const defaultKey = yield readOrNew(`${CONF}/default.key`, true);
    installFakeCerts(defaultKey, CONF, ["default"]);
  }
  const updater = new Updater(CONF);
  fs.watch(CONF, (event, filename) => {
    const match = filename.match(/^(.*)\.acme(-test)?$/);
    try { fs.statSync(`${CONF}/${filename}`); } catch (e) { return; }
    if (match) updater.updateCert(match[2] ? TEST : PROD, match[1]);
  });
  setInterval(() => updater.checkAll(), 1000 * 60 * 60 * 24);
  updater.checkAll();
}));

function parseDate(x509Date) {
  const parts = x509Date.match(/^(..)(..)(..)(..)(..)(..)Z$/);
  return new Date(Date.UTC(2000 + (+parts[1]), parts[2] - 1, +parts[3],
    +parts[4], +parts[5], +parts[6]));
}

class Updater {
  constructor(CONF) {
    this.conf = CONF;
    this._queue = Promise.resolve();
  }
  checkAll() {
    for (let filename of fs.readdirSync(CONF)) {
      const match = filename.match(/^(.*)\.acme(-test)?$/);
      if (!match) continue;
      this.updateCert(match[2] ? TEST : PROD, match[1]);
    }
  }
  updateCert(BASE, DOMAIN) {
   this._queue = this._queue.then(() => undefined, () => undefined)
      .then(() => {
        console.log(`Updating ${DOMAIN}.`);
        if (!this.needsUpdate(DOMAIN)) {
          throw new Error("Does not need to be updated");
        }
        return getCert(BASE, this.conf, [DOMAIN, `www.${DOMAIN}`]);
    });
    this._queue.then(res => console.log(`Updated ${DOMAIN}.`),
      err => console.log(`Error: ${err}.`));
    return this._queue;
  }
  needsUpdate(DOMAIN) {
    try {
      const pem = fs.readFileSync(`${this.conf}/${DOMAIN}.cert`).toString();
      const cert = new KJUR.X509();
      cert.readCertPEM(pem);
      const days = (parseDate(cert.getNotAfter()) - new Date())/1000/60/60/24;
      console.log(days);
      if (days > 50) return false;
    } catch (e) {}
    return true;
  } 
}

function async(genF) {
  return function () { return spawn(genF, this, arguments); };
  // Spawn from <http://tc39.github.io/ecmascript-asyncawait/#desugaring>.
  function spawn(genF, self, args) {
    return new Promise(function(resolve, reject) {
      var gen = genF.apply(self, args);
      function step(nextF) {
        var next;
        try {
          next = nextF();
        } catch(e) {
          // finished with failure, reject the promise
          reject(e);
          return;
        }
        if(next.done) {
          // finished with success, resolve the promise
          resolve(next.value);
          return;
        }
        // not finished, chain off the yielded promise and `step` again
        Promise.resolve(next.value).then(function(v) {
          step(function() { return gen.next(v); });
        }, function(e) {
          step(function() { return gen.throw(e); });
        });
      }
      step(function() { return gen.next(undefined); });
    });
  }
}

function sign(key, data, nonce) {
  return jose.JWS.createSign(
    {format: "flattened", alg: "RS256", fields: {nonce}},
    {key, reference: "jwk"}
  ).update(JSON.stringify(data)).final().then(JSON.stringify);
}

class acmeClient {
  constructor(base, key) {
    this.base = base;
    this.key = key;
    this.nonce = null;
    this.debug = DEBUG;
    this._ready = this.fetchJSON(base).then(res => this.actions = res);
  }
  fetch() {
    if (this.debug) console.log(arguments);
    return fetch.apply(this, arguments).then(res => {
      this.nonce = res.headers.get("replay-nonce");
      return res;
    });
  }
  fetchJSON() {
    var headers;
    return this.fetch.apply(this, arguments).then(res => {
      headers = res.headers;
      if (!headers.get("content-type").match(/json/)) {
        return {body: res, headers};
      }
      return res.json().then(res => (res.headers = headers, res));
    }).then(res => (this.debug && console.log(res), res));
  }
  call(action, options, url) {
    if (!options) options = {};
    options.resource = action;
    if (this.debug) console.log(options);
    return this._ready
      .then(() => sign(this.key, options, this.nonce))
      .then(body => this.fetchJSON(url || this.actions[action],
        {method: "POST", body}));
  }
}

acmeClient.prototype.doAuth = async(function* (DOMAIN, CONF, selfKey) {
  const auth = yield this.call("new-authz",
    {identifier: {type: "dns", value: DOMAIN}});
  const challenge = auth.challenges.filter(v => v.type === "tls-sni-01")[0];
  const domains = tlsSni01(this.key.toJSON(), challenge.token, challenge.n);
  installFakeCerts(selfKey, CONF, domains[1]);
  rewriteConf(CONF);
  const challenge2 = yield this.call("challenge",
    {type: challenge.type, keyAuthorization: domains[0]}, challenge.uri);
  for (var status = { status: "pending" }; status.status === "pending"; ) {
    yield sleep(1000);
    status = yield (yield fetch(challenge.uri)).json();
  }
  if (status.status !== "valid") throw new Error(status);
  return status;
});

function getLinks(url, headers, rel) {
  const links = headers.getAll("link").join(", ").match(/(<[^>]+>[^,]*)/g);
  return (links || []).filter(v => v.match(/;rel="(.+)"$/)[1] === rel)
    .map(v => urlParsing.resolve(url, v.match(/<([^>]+)>/)[1]));
}

function fetchCert(url) {
  var headers;
  return fetch(url).then(res => (headers = res.headers, toArray(res.body))
  ).then(res => "-----BEGIN CERTIFICATE-----\n" +
    Buffer.concat(res).toString("base64").replace(/(.{64})/g, "$1\n").trim() +
    "\n-----END CERTIFICATE-----\n"
  ).then(res => {
    const up = getLinks(url, headers, "up");
    if (up[0]) return fetchCert(up[0]).then(res2 => res + res2);
    return res;
  });
}

function getCSR(key, domains) {
  if (!(domains instanceof Array)) domains = [domains];
  const key2 = KJUR.KEYUTIL.getKey(key);
  const csri = new KJUR.asn1.csr.CertificationRequestInfo();
  csri.setSubjectByParam({str: `/CN=${domains[0]}`});
  csri.setSubjectPublicKeyByGetKey(key2);
  csri.extensionsArray = [new KJUR.asn1.DERSequence({array: [
    new KJUR.asn1.DERObjectIdentifier({oid: "1.2.840.113549.1.9.14"}),
    new KJUR.asn1.DERSet({array: [
      new KJUR.asn1.DERSequence({array: [subjectAltName(domains)]})]})]})];
  const csr = new KJUR.asn1.csr.CertificationRequest({csrinfo: csri});
  csr.sign("SHA256withRSA", key2);
  return URLSafeBase64.encode(new Buffer(csr.getEncodedHex(), "hex"));
}

function subjectAltName(domains) {
  const ext = new KJUR.asn1.x509.Extension();
  ext.oid = "2.5.29.17";
  ext.names = domains.map(dns => ({dns}));
  ext.getExtnValueHex = function () {
    return (new KJUR.asn1.x509.GeneralNames(this.names)).getEncodedHex();
  };
  return ext;
}

function getFakeCert(key, domains) {
  if (!(domains instanceof Array)) domains = [domains];
  const prvkeyobj = KJUR.KEYUTIL.getKey(key);
  const tbscertobj = new KJUR.asn1.x509.TBSCertificate();
  tbscertobj.setSerialNumberByParam({int: 0});
  tbscertobj.setIssuerByParam({str: ""});  
  tbscertobj.setSubjectByParam({str: ""});  
  tbscertobj.setSubjectPublicKeyByGetKey(prvkeyobj);
  tbscertobj.setSignatureAlgByParam({name: "SHA256withRSA"});
  tbscertobj.setNotBeforeByParam({str: "000101000000Z"});
  tbscertobj.setNotAfterByParam({str: "000101000000Z"});
  tbscertobj.appendExtension(subjectAltName(domains));
  const cert = new KJUR.asn1.x509.Certificate({tbscertobj, prvkeyobj});
  cert.sign();
  return cert.getPEMString();
}

function tlsSni01(key, token, n) {
  n = n || 1;
  const auth = `${token}.${KJUR.jws.JWS.getJWKthumbprint(key)}`;
  const res = [];
  var Zi = auth;
  for (var i = 0; i < n; i++) {
    Zi = crypto.createHash("sha256").update(Zi, "utf8").digest("hex");
    res.push(`${Zi.slice(0, 32)}.${Zi.slice(32, 64)}.acme.invalid`);
  }
  return [auth, res];
}

function toPrivatePEM(key) {
  return KJUR.KEYUTIL.getPEM(KJUR.KEYUTIL.getKey(key), "PKCS8PRV");
}

var readOrNew = async(function*(keyPath, asPEM) {
  var key;
  try {
    var keyJSON = fs.readFileSync(keyPath).toString();
    key = yield jose.JWK.asKey(keyJSON, asPEM ? "pem" : "json");
  } catch (e) {
    key = yield jose.JWK.createKeyStore().generate("RSA", 2048);
    fs.writeFileSync(keyPath, asPEM ? toPrivatePEM(key.toJSON(true)) :
      JSON.stringify(key.toJSON(true)), {mode: 0o400});
  }
  return key;
});

function cleanCerts(directory) {
  for (let file of fs.readdirSync(directory)) {
    if (/\.acme\.invalid\.(key|cert)$/.test(file)) { try {
      fs.unlinkSync(`${directory}/${file}`);
    } catch (e) {} }
  }
}

function installFakeCerts(key, directory, domains) {
  for (let domain of domains) {
    fs.writeFileSync(`${directory}/${domain}.key`,
      toPrivatePEM(key.toJSON(true)), {mode: 0o400});
    fs.writeFileSync(`${directory}/${domain}.cert`,
      getFakeCert(key.toJSON(true), domain));
  }
}

function rewriteConf(directory) {
  var conf = fs.readFileSync(`${directory}/nghttpx.conf`)
    .toString().trimRight().split(/\n/);
  conf = conf.filter(v => !(/^subcert=/.test(v)));
  for (let file of fs.readdirSync(directory)) {
    const domain = file.match(/^(.+)\.cert$/);
    if (!domain) continue;
    const path = `${directory}/${domain[1]}`;
    conf.push(`subcert=${path}.key:${path}.cert`);
  }
  fs.writeFileSync(`${directory}/nghttpx.conf`, conf.concat([""]).join("\n"));
  child_process.execSync("/usr/bin/systemctl reload-or-restart nghttpx");
}

function sleep(time_ms) {
  return new Promise(function (resolve) { setTimeout(resolve, time_ms); });
}

var getCert = async(function* (BASE, CONF, DOMAINS) {
  try {
    if (!(DOMAINS instanceof Array)) DOMAINS = [DOMAINS];
    const key = yield readOrNew(`${CONF}/acme-account.jwk`);
    const selfKey = yield readOrNew(`${CONF}/acme-tls-sni-01.jwk`);
    const acme = new acmeClient(BASE, key);

    const reg0 = yield acme.call("new-reg");
    const accountURL = reg0.headers.get("location");
    var reg = yield acme.call("reg", {}, accountURL);
    const TOS = getLinks(accountURL, reg.headers, "terms-of-service");
    if (TOS.length) {
      console.log(`Agreeing to Terms of Service: <${TOS[0]}>.`);
      reg = yield acme.call("reg", {agreement: TOS[0]}, accountURL);
    }
    const authed = [];
    for (let DOMAIN of DOMAINS) { try {
      console.log(yield acme.doAuth(DOMAIN, CONF, selfKey));
      authed.push(DOMAIN);
    } catch (e) { console.log(e); } }
    let DOMAIN = DOMAINS[0];
    const certKey = yield readOrNew(`${CONF}/${DOMAIN}.key`, true);
    const cert = yield acme.call("new-cert",
      {csr: getCSR(certKey.toJSON(true), authed)});
    const certURL = cert.headers.get("location");
    const certPEM = yield fetchCert(certURL);
    fs.writeFileSync(`${CONF}/${DOMAIN}.cert`, certPEM);
    cleanCerts(CONF);
    rewriteConf(CONF);
  } catch (e) {
    cleanCerts(CONF);
    rewriteConf(CONF);
    throw e;
  }
});
