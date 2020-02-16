"use strict";

import init, { yara_match } from './pkg/yara_rs.js';

async function run() {
  await init();
  fetch('add.wasm')
    .then(response => response.arrayBuffer())
    .then(bytes => new Promise((resolve, reject) => {
      let view = new Uint8Array(bytes);
      let match = yara_match(`
      rule add
      {
        meta:
          description = "Add example wasm file"
        strings:
          $a = { 00 61 73 6D }
          $b = { 61 64 61 }
        condition:
          $a and $b
      }`, view);
      if (match) {
        throw new Error("Matched yara Rule");
      }
      resolve(bytes);
    }))
    .then(bytes => WebAssembly.instantiate(bytes, {}))
    .then(({instance, module}) => console.log(instance.exports.add(1, 4)));
}
run();

async function callback(details) {
  console.log(details);
}

/*
Listen for all onHeadersReceived events.
*/
browser.webRequest.onHeadersReceived.addListener(callback,
  {urls: ["<all_urls>"]},
  ["blocking"]
);
