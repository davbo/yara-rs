# yara-rs #

[yara][yara] pattern matching in Rust / Web Assembly.

## Current features ##

Parses a subset of yara and can perform basic string / hex matches.

## Running the demo ##

To give the demo (blocking the download of a malicious cryptocurrency miner) a try run the following:

```sh
yara-rs$ wasm-pack build --target=web
yara-rs$ python3 -m http.server
```

Now visit http://localhost:8080 and you should see the following the developer console

```
Match against rule: cryptonight
Error: Matched yara Rule
```

## demo-extension ##

Web extension (tested in Firefox) to demonstrate how `wasm` can be matched as
they are downloaded to the browser.

[yara]: https://virustotal.github.io/yara/
