package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type MyCustomClaims struct {
	Email string
	jwt.StandardClaims
}

var signingKey = []byte("Any random key here.")

func (mcc MyCustomClaims) Valid() error {
	if mcc.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}
	if mcc.Email == "" {
		return fmt.Errorf("Invalid email.")
	}
	return nil
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/submit", setTokenOnCookie)
	http.ListenAndServe(":8080", nil)
}

// Create a JWT token.
func createJWTToken(email string) (string, error) {
	claims := MyCustomClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		},
		Email: email,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	signedString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("SignedString couldn't be generated.")
	}
	return signedString, nil
}

func setTokenOnCookie(res http.ResponseWriter, req *http.Request) {
	email := req.FormValue("emailString")
	if email == "" {
		//TODO:
		return
	}
	ss, err := createJWTToken(email)
	if err != nil {
		http.Error(res, "JWT couldn't be created.", http.StatusInternalServerError)
		return
	}

	c := http.Cookie{
		Name:  "openly-session",
		Value: ss + "|" + email, //This is again on us how we want to set the cookie.
	}
	http.SetCookie(res, &c)
	http.Redirect(res, req, "/", http.StatusSeeOther)
}

func index(res http.ResponseWriter, req *http.Request) {
	var message string
	var retrievedClaimEmail string
	c, err := req.Cookie("openly-session")
	if err != nil {
		c = &http.Cookie{}
	}
	signedString := c.Value
	afterVerificationToken, err := jwt.ParseWithClaims(signedString, &MyCustomClaims{}, func(beforeVerificationToken *jwt.Token) (interface{}, error) {
		if beforeVerificationToken.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("signing algorithm methods don't match")
		}
		return []byte(signingKey), nil
	})

	isTokenValid := err == nil && afterVerificationToken.Valid
	message = "Not Logged in"
	if isTokenValid {
		message = "Logged in"
		retrievedClaims := afterVerificationToken.Claims.(*MyCustomClaims)
		retrievedClaimEmail = retrievedClaims.Email
		fmt.Println(retrievedClaims.Email)
		fmt.Println(retrievedClaims.StandardClaims.ExpiresAt)
	}

	html := `<!DOCTYPE html>
	<html lang="en">
		<head>
			<meta charset = "UTF-8">
			<title>JWT&Cookie Example</title>
		</head>
		<body>
			<p>Cookie:` + c.Value + `</p>
			<p> ` + message + `</p>
			<p> ` + retrievedClaimEmail + `</p>
            <form action="/submit" method="post">
                <input type="email" name="emailString"/>
                <input type="submit" />
            </form>
		</body>
	</html>`
	io.WriteString(res, html)

}
