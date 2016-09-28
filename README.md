# apiauth
[ApiAuth][]-compatible package for signing and verifying HTTP requests in golang.
It uses the same hmac authentication method (HMAC-SHA1)
# Usage

Signing a request:
--
~~~go
import 	"github.com/prashant-agarwala/apiauth"

req, _ := http.NewRequest("POST", "http://apiserver.com/api/v1/lists/create.json",payload)
err    := apiauth.Sign(req, "access_id", "secret_key")
~~~

Checking authenticity of a request:
--
Write your own method to find the associated secret_key against a access_id and pass it to the method Authentic. You can return any additional result which will be returned from Authentic method
~~~go
import 	"github.com/prashant-agarwala/apiauth"

var getAPIKey apiauth.Finder = func(accessID string, request *http.Request) (string, interface{}, error) {
  return "secret_key", "result", nil
}

result, err := apiauth.Authentic(r, getAPIKey)
~~~

[ApiAuth]: https://github.com/mgomes/api_auth
