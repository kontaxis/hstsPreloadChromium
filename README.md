# hstsPreloadChromium

```
usage: hstsPreloadChromium.py [-h] [--verbose] E [E ...]

Look up entries in the Chromium HSTS preload list.

positional arguments:
  E              Entry to look up.

optional arguments:
  -h, --help     show this help message and exit
  --verbose, -v  Output information on the lookup process.
```

```
# ./hstsPreloadChromium.py google.com chrome.google.com foo.chrome.google.com
chrome.google.com
foo.chrome.google.com

# ./hstsPreloadChromium.py paypal.com foo.paypal.com
paypal.com
```
