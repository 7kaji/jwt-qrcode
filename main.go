package main

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/skip2/go-qrcode"
	"net/http"
	"time"
)

type Item struct {
	ItemCode string `json:"item_code"`
	Price    int    `json:"price"`
	Amount   int    `json:"amount"`
}

const sharedSecret = "secretKey" // TODO: In a production environment, use a more secure key and manage it appropriately.


func main() {
	e := echo.New()

	e.POST("/generate_qr", generateQR)
	e.POST("/verify_token", verifyToken)
	e.Start(":8080")
}

func generateQR(c echo.Context) error {
	item := new(Item)
	if err := c.Bind(item); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Failed to bind request"})
	}

	// Generate a new JWT token 
	token := jwt.New()

	// Set claims for the token
	_ = token.Set("item_code", item.ItemCode)
	_ = token.Set("price", item.Price)
	_ = token.Set("amount", item.Amount)

	// Set expiration time to 1 hour from now
	expirationTime := time.Now().Add(1 * time.Hour)
	_ = token.Set(jwt.ExpirationKey, expirationTime)

	// Generate UUID and set as jti claim
	jti := uuid.New().String()
	_ = token.Set(jwt.JwtIDKey, jti)

	// Sign the JWT
	signedTokenBytes, err := jwt.Sign(token, jwa.HS256, []byte(sharedSecret))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to sign JWT"})
	}

	fmt.Println("---debug---", string(signedTokenBytes))

	// Encode JWT as a QR code
	png, err := qrcode.Encode(string(signedTokenBytes), qrcode.Medium, 256)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate QR code"})
	}

	return c.Blob(http.StatusOK, "image/png", png)
}

func verifyToken(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "authorization header missing")
	}

	// Extract actual JWT token from "Bearer [Your JWT]" format
	if len(authHeader) <= len("Bearer ") {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid authorization header format")
	}
	tokenStr := authHeader[len("Bearer "):]

	// Parse and verify JWT
	token, err := jwt.Parse([]byte(tokenStr), jwt.WithVerify(jwa.HS256, []byte(sharedSecret)))
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "token verification failed: "+err.Error())
	}
	fmt.Println("debug", token)

	// Check the exp claim
	expValue, ok := token.Get(jwt.ExpirationKey)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "expiration claim missing in token")
	}
	expTime, ok := expValue.(time.Time)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid expiration format in token")
	}
	if time.Now().After(expTime) {
		return echo.NewHTTPError(http.StatusUnauthorized, "token has expired")
	}

	// Check the jti claim
	jtiValue, ok := token.Get(jwt.JwtIDKey)
	if !ok {
		// return echo.NewHTTPError(http.StatusUnauthorized, "jti claim missing in token")
		fmt.Println("jti claim missing in token")
	}
	jti, ok := jtiValue.(string)
	if !ok {
		// return echo.NewHTTPError(http.StatusUnauthorized, "invalid jti format in token")
		fmt.Println("invalid jti format in token")
	}
	fmt.Println("jti", jti)

	// Retrieve claims
	claims := token.PrivateClaims() // map[string]interface{}型

	for key, value := range claims {
		fmt.Printf("Key: %s, Value: %v\n", key, value)
	}

	// Sample code for a specific claim
	// if sub, exists := claims["sub"]; exists {
	// 	fmt.Printf("sub claim: %v\n", sub)
	// }

	// Post-verification processing
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Successfully authenticated!",
	})
}
