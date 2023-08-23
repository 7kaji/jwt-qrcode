package main

import (
	"fmt"
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

const sharedSecret = "secretKey" // 本番環境ではもっと強固なキーを使用して、適切に管理すること

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

	// 新しいJWTトークンを生成
	token := jwt.New()

	// トークンにクレームをセット
	_ = token.Set("item_code", item.ItemCode)
	_ = token.Set("price", item.Price)
	_ = token.Set("amount", item.Amount)

	// 現在時刻から1時間後の時刻を有効期限として設定
	expirationTime := time.Now().Add(1 * time.Hour)
	_ = token.Set(jwt.ExpirationKey, expirationTime)

	// JWTを署名
	signedTokenBytes, err := jwt.Sign(token, jwa.HS256, []byte(sharedSecret))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to sign JWT"})
	}

	fmt.Println("---debug---", string(signedTokenBytes))

	// JWTをQRコードとしてエンコード
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

	// "Bearer [Your JWT]" の形式から、実際のJWTトークンを取得
	if len(authHeader) <= len("Bearer ") {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid authorization header format")
	}
	tokenStr := authHeader[len("Bearer "):]

	// JWTの解析と検証
	token, err := jwt.Parse([]byte(tokenStr), jwt.WithVerify(jwa.HS256, []byte(sharedSecret)))
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "token verification failed: "+err.Error())
	}
	fmt.Println("debug", token)

	// exp クレームの確認
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

	// クレームを取得
	claims := token.PrivateClaims() // map[string]interface{}型

	for key, value := range claims {
		fmt.Printf("Key: %s, Value: %v\n", key, value)
	}

	// 特定のクレーム
	// if sub, exists := claims["sub"]; exists {
	// 	fmt.Printf("sub claim: %v\n", sub)
	// }

	// 検証が成功した後の処理
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Successfully authenticated!",
	})
}
