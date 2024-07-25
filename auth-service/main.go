package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/lucsky/cuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Client struct {
	ID           string `gorm:"primaryKey"`
	Name         string `gorm:"uniqueIndex"`
	ClientSecret string `json: "-"`
	Website      string
	Logo         string
	Code         sql.NullString `gorm:"default:null"`
	RedirectURI  string         `json:"redirect_uri"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

type NewUserRequst struct {
	Email    string
	Password string
}

type User struct {
	ID        string         `gorm:"primaryKey"`
	Email     string         `gorm: "uniqueIndex"`
	Password  string         `json:"-"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type AuthRequest struct {
	ResponseType string `json:"response_type" query:"response_type"`
	ClientID     string `json:"client_id" query:"client_id"`
	RedirectURI  string `json:"redirect_uri" query:"redirect_uri"`
	Scope        string `json:"scope" query:"scope"`
	State        string `json:"state" query:"state"`
}

type ConfirmAuthRequest struct {
	Identity  string `json:"identity"`
	Password  string `json:"password"`
	Authorize bool   `json:"authorize" query:"authorize"`
	State     string `json:"state" query:"state"`
	Scope     string `json:"scope" query:"scope"`
	ClientID  string `json:"client_id" query:"client_id"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type" query:"grant_type"`
	Code         string `json:"code" form:"code" query:"code"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri" query:"redirect_uri"`
	ClientID     string `json:"client_id" form:"client_id" query:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret" query:"client_secret"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)

	return string(bytes), err
}

func main() {
	err := godotenv.Load()
	if err != nil {
		panic("unable to load .env file")
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		panic("DATABASE_URL is not set")
	}
	DB, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	// Migrate the schema
	DB.AutoMigrate(&Client{})

	// generate temp code
	clientSecret, err := cuid.NewCrypto(rand.Reader)
	if err != nil {
		panic("failed to gen dummy client secret")
	}

	DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name", "website", "redirect_uri", "logo", "client_secret"}),
	}).Create(&Client{
		ID:           "1",
		Name:         "fiber",
		Website:      "https://test.com",
		RedirectURI:  "https://localhost:8080/auth/callback",
		Logo:         "https://img.freepik.com/free-vector/map-window-combination-logo_557339-642.jpg",
		ClientSecret: clientSecret,
	})
	views := html.New("./views", ".html")

	api := fiber.New(fiber.Config{
		AppName: "Authorization Service",
		Views:   views,
	})
	api.Use(logger.New())
	api.Use(recover.New())

	api.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})
	api.Get("/user", func(c *fiber.Ctx) error {
		user := new(User)
		if err := c.BodyParser(user); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		if user.Email == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_email"})
		}
		if user.Password == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_password"})
		}
		hash, err := hashPassword(user.Password)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"status": "error"})
		}

		user.Password = hash
		if err := DB.Create(&user).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"status": "error"})
		}
		return c.JSON(fiber.Map{"status": "success", "message": "created user"})
	})
	api.Get("/auth", func(c *fiber.Ctx) error {
		authRequest := new(AuthRequest)
		if err := c.QueryParser(authRequest); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		if authRequest.ResponseType != "code" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		if authRequest.ClientID == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		if !strings.Contains(authRequest.RedirectURI, "https") {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}
		if authRequest.Scope == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_requests"})
		}
		if authRequest.State == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_requests"})
		}

		// Check for a new Client
		client := new(Client)
		if err := DB.Where("name = ?", authRequest.ClientID).First(&client).Error; err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_client"})
		}
		// generate temp code
		code, err := cuid.NewCrypto(rand.Reader)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "server_errors"})
		}

		c.Cookie(&fiber.Cookie{
			Name:     "temp_auth_request_code",
			Value:    code,
			Secure:   true,
			Expires:  time.Now().Add(1 * time.Minute),
			HTTPOnly: true,
		})

		return c.Render("authorize_client", fiber.Map{
			"Logo":    client.Logo,
			"Name":    client.Name,
			"Website": client.Website,
			"Scopes":  strings.Split(authRequest.Scope, " "),
			"State":   authRequest.State,
		})
	})
	api.Get("/confirm_auth", func(c *fiber.Ctx) error {
		tempCode := c.Cookies("temp_auth_request_code")
		c.ClearCookie("temp_auth_request_code")
		if tempCode == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_requests"})
		}

		confirmAuthRequest := new(ConfirmAuthRequest)

		if err := c.QueryParser(confirmAuthRequest); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}

		// Validiate params
		if confirmAuthRequest.ClientID == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_client_ids"})
		}
		if confirmAuthRequest.State == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_state"})
		}

		// Check for a new Client
		client := new(Client)
		if err := DB.Where("name = ?", confirmAuthRequest.ClientID).First(&client).Error; err != nil {
			// validate clienet and code
			return c.Status(400).JSON(fiber.Map{"error": "invalid_client"})
		}

		if !confirmAuthRequest.Authorize {
			return c.Redirect(client.RedirectURI + "?error=access_denied")
		}

		// Save generated auth code to table
		DB.Model(&client).Update("code", tempCode)

		return c.Redirect(client.RedirectURI + "?code=" + tempCode + "&state=" + confirmAuthRequest.State)
	})

	api.Post("/token", func(c *fiber.Ctx) error {
		tokenRequest := new(TokenRequest)

		if err := c.BodyParser(tokenRequest); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}
		if tokenRequest.ClientID == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_client_id"})
		}
		if tokenRequest.Code == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_codes"})
		}

		if tokenRequest.RedirectURI == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}
		if tokenRequest.ClientSecret == "" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_request"})
		}
		// lookup client
		client := new(Client)
		if err := DB.Where("name = ?", tokenRequest.ClientID).First(&client).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": tokenRequest})
		}

		// validate clienet and code
		if !client.Code.Valid {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_codes"})
		}
		if tokenRequest.Code != client.Code.String {
			return c.Status(400).JSON(fiber.Map{"error": "invalid_codes"})
		}

		//     generate access token
		token := jwt.New(jwt.SigningMethodHS256)

		claims := token.Claims.(jwt.MapClaims)
		// claims["username"] = userData.Username
		// claims["user_id"] = userData.ID
		claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

		accessToken, err := token.SignedString([]byte(client.ClientSecret))
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		tokenResponse := new(TokenResponse)
		tokenResponse.AccessToken = accessToken
		tokenResponse.ExpiresIn = 3600

		return c.Status(200).JSON(tokenResponse)
	})
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	api.Listen(fmt.Sprintf(":%s", port))
}
