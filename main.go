package main

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"
)

const (
	// This is a sample keypair in JWK format generated using mkjwk.
	// Ref: https://mkjwk.org/
	keypair = `{
    "p": "9MMy6MHTgSwCqTg2-7iZHdbBVoMfXSq5sAOOOpuDL8B7DAxIhI_PfyrvgQdbNTO4Kom7XANdeiUx4YXWlBknZaN76xMfsH1XV26q17hqkJdB6gGdhC3N6dapv_uEoEw6fRJsLH-aJY-dSQNZde12zUsTnhMbHaswjJMTGD3G4Nc",
    "kty": "RSA",
    "q": "tVXBJ200KefbB7EKy75G_ZMQUwVY0zq2kZ4nbeNzf6qOW98-S022r38oRY13IkHi6aX3655pgG6gpZSmaBxXN6SHQUpCsGKaZZN_GcM-Ee2eMCvv7ktA52UPTvIBMpRBV95-tai9hIG6YxBmhDnGQu2VopCxT2m-5GQIOirLdU8",
    "d": "MMLPX-A1eBjiyxeY1NjftlxuV_4jBr-w-_PBksyo5ZeysCWem2xFjhn33p7x0k0WZWpys9yOGrMcoTf4sYBFYwQrcmXpuXD5zJN9kXvS9CbTThQcMbgCO-EZNTA9F4xVbzDkjkijaaDxvC2XRYdlE1J3zbvARFXH2Q_Iip4vpcDyaDH7jV22pXpLrxG6oSGu8ZDlZK04Iom7whVDvU6b6mKODL8pYjASMsgmoPH0yFxOWQmpiILyFDEr6F4720EPVnei8Pccs_BlHMDn9xw2XoRZq2E8TwRQ2TXiofkGHRK2xkoCccGenyS2nVp2XIiLY9hnTnHRaWUgJEHl1kWgAQ",
    "e": "AQAB",
    "use": "sig",
    "qi": "0x-j4oTG6kNAl2WUOuSA0lbBmp84TqkH75kz7hpGzVplWeTNiM78vNjmRseXGDcBgUIkzdX-59kBBJcpPC3h5f4_YBLN-PJPiYbKWXfOJvn96iKeM75jn776AsYOD9qp8MojAi6hNaI2fPQ0HcrOflLkq5mfgAByG38XSTE8BcU",
    "dp": "lxLAon-4T3tdrRsAfQBkqdE7Bm3qdvP_JtAbAruoDlpM2JPgUsn89e4HZGmo9z6UBtV6aoG9Ob4pepzEZCbedVKiEud74NCMj2_ETWALjnF-ArS6h7JJ7XJM1i2ln9dNJpOvZwvflh19pGpH1o0ajf4v_pqmWvql_a5t08GVtoM",
    "alg": "RS256",
    "dq": "ChuGkbEHmFJhJhObO3IWuOmqnkYNBnEeXg2HuxtTg8k4-CwAZ-gkB7I5x260Nkef41Ap-osw7ES-VZxsjh8OSX61P1FpWDWWz5SiIAh-_DbXe23niMvPCVbbvJXGtVAIOGKhg3StY6ZrgjwWysYBpBdkINSZ3YhSaJ6eysc54gc",
    "n": "rWAAe1PaHYhfnF3VD80sp_JJnfN8gyYbfruFbKRieck54wEYA7TnCHAVOvvIrxiQs5E5T1KxqARS8vPqWpGmtlreF1orGiYLhYSV2MwPxwZTZsUIFLmcRraD3Xbrqeif8BZ_GYQ-6522oG9hmVCXe3AnjvAxx2rV--I-lsKWRudVVec589NHkP18Jv-xD0TGWO2JY2UInXbmPYBn3XDQNa6iWtI6_sQ-QnV2Q2Kktrtk7V37cJ4DyaUyH_ZgkB5RKeMU7b8DQCBO-AZ0CfBgqwY3SQmNz0ntMu1x7QSaS37GLV9y_NfkTPHAjOBAQBy6nZpL2JeJA-o9ij8EhZ6lWQ"
 }`

	iss = "sample-app"
	aud = "http://localhost:8080/realms/demo/protocol/openid-connect/token"
	sub = "sample-app"
)

func main() {
	key, err := jwk.ParseKey([]byte(keypair))
	if err != nil {
		panic(err)
	}
	t := openid.New()
	t.Set(jwt.IssuerKey, iss)
	t.Set(jwt.SubjectKey, sub)
	t.Set(jwt.AudienceKey, aud)
	t.Set(jwt.IssuedAtKey, time.Now().Unix())
	t.Set(jwt.ExpirationKey, time.Now().Add(time.Minute).Unix())
	t.Set(jwt.JwtIDKey, uuid.New().String())
	token, err := jwt.Sign(t, jwa.RS256, key)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(token))
}
