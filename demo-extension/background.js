"use strict";

import init, { parse } from './yara_rs.js';

async function run() {
  await init();
  parse();
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
