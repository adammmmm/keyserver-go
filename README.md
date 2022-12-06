# keyserver-go

Rebuild of the macsec key generator I built in python a couple years ago [https://github.com/adammmmm/hitless-key-rollover](https://github.com/adammmmm/hitless-key-rollover), this time while experimenting with go.
Most of it works the same.

Same reasoning and limitations apply.
Same functionality.

Configuration is done in config.json instead of yml.

An example configuration is provided.

prometheus metrics are available on :8799/metrics
the value of the metric keyserver_result represents the outcome of last run: 0 = error, 0.5 = warning, 1 = noop or success
