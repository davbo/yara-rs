# yara-rs #

[yara][yara] pattern matching in Rust / WebAssembly.

## Current features ##

Parses a subset of yara and can perform basic string / hex matches.

## Running the demo ##

The demo shows how a malicious cryptocurrency miner, `cryptonight` can be
matched and prevented from running.

If you'd like to give it a try run the following:

```sh
yara-rs$ wasm-pack build --target=web
yara-rs$ python3 -m http.server
```

Now visit http://localhost:8000/demo/ and you should see the following the
developer console:

```
Match against rule: cryptonight
Error: Matched yara Rule
```

This means the `cryptonight` Wasm file was downloaded, checked against the yara
rule and a match was found. The Error thrown prevents the file being loaded.

## demo-extension ##

Web extension (tested in Firefox) to demonstrate how `wasm` can be matched as
they are downloaded to the browser.

[yara]: https://virustotal.github.io/yara/
