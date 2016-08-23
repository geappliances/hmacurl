# hmacurl
`hmacurl` is a curl-inspired command line utility that implements the AWS v4 Signature process. Currently, only the `Authorization` header method is supported.

See http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html for more information.

<img width="10%" src="https://raw.github.com/golang-samples/gopher-vector/master/gopher.png"/>


## Install
Requires Go 1.5 or newer to compile. If using Go 1.5, please make sure you've
set the `$GOVENDOREXPERIMENT` environment variable to `1` before compiling.

`go get github.com/geappliances/hmacurl`

## Run
```
$ hmacurl -h
Usage:
  hmacurl [OPTIONS] url

Application Options:
  -X, --request=GET|POST                           the http method to use (GET)
  -d, --data='my string body'                      for POST requests, the data
                                                   to be uploaded as the body.
                                                   Used if -f is not provided.
  -f, --file=./file.txt                            for POST requests, the file
                                                   to be uploaded as the body.
                                                   Used if -d is not provided
  -H, --header='Content-Type: application/json'    Extra header(s) to include
                                                   in the request when sending
                                                   HTTP to a server. You may
                                                   specify any number of extra
                                                   headers.
      --curl-only                                  If specified, will only
                                                   print out a curl command -
                                                   not actually run a request
                                                   (default: false)
  -a, --access-key=                                The access Key to use in
                                                   HMAC signing.
                                                   [$HMACURL_ACCESS_KEY]
  -s, --secret-key=                                The secret Key to use in
                                                   HMAC signing.
                                                   [HMACURL_SECRET_KEY]
  -c, --credential-scope=                          The credential scope (aka
                                                   Service Name) for the
                                                   request. (default: short
                                                   host name)
  -r, --region=                                    The region string to use in
                                                   the credential scope.
                                                   (default: us-east-1)
      --skip-host                                  Do not sign the Host header
                                                   (useful for non-standard
                                                   HMAC implementations) (false)
  -p, --proxy=                                     Proxy server to use if not
                                                   set via environment variable.
      --debug                                      Whether to output debug
                                                   information (false)

Help Options:
  -h, --help                                       Show this help message

Arguments:
  url
```

#### Run Example
`hmacurl -XPOST -H'Content-Type: text/html' -H'foo:bar' -a accessKey -s secret -d'{}' http://example.com`
