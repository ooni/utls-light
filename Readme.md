# UTLS Light

This is a light version of
[refraction-networking/utls](https://github.com/refraction-networking/utls)
with a focus on parrotting a single browser and hence implementing only the
strict minimal set of features needed for that.

Design goals:
* Parroting the most popular browser out there (Google Chrome)
* Smallest number of changes to the go/tls codepath
* It should be possible to easily inspect the diff with upstream (see the [diff for the last update](https://github.com/ooni/utls-light/compare/2b6c2ef3b403d1a30ddb395df58171ddd004a344...4dfb1fc05321b947dbee87f475f4159c40beb22d))

Non-goals:
* Pluggable support for multiple TLS fingerprints

Thanks to @FiloSottile for the insight and suggestion to take the approach of
parsing the raw ClientHello bytes and re-serialising them.
