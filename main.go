package main

import (
	"context"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/hashicorp/vault-client-go"
	"github.com/joho/godotenv"
	"github.com/terra-farm/go-xen-api-client"
	"log"
	"os"
	"time"
	"xcp-microservice/handlers"
	"xcp-microservice/middleware"
)

var XAPI *xenapi.Client

func main() {
	log.Printf("Starting XCP-NG microservice")
	var err error
	// Load the .env file
	err = godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
	// Initialise XenAPI client with XCP-NG credentials
	XAPI, err = xenapi.NewClient(os.Getenv("XCP_URL"), nil)
	if err != nil {
		log.Fatalf("Failed to initialize XCP-NG client: %v", err)
	}

	// Get creds from hashicorp vault
	username, password := getCredentialsFromVault()

	session, err := XAPI.Session.LoginWithPassword(username, password, "1.0", "xcp-ng-microservice")
	if err != nil {
		log.Fatalf("Failed to login to XCP-NG: %v", err)
	}

	// Initialise OIDC provider and verifier (Keycloak)
	provider, err := oidc.NewProvider(context.Background(), os.Getenv("OIDC_PROVIDER_URL"))
	if err != nil {
		log.Fatalf("Failed to initialize OIDC provider: %v", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: os.Getenv("OIDC_CLIENT_ID")})

	// Pass them to the middleware package
	middleware.SetOIDC(provider, verifier)

	handlers.XAPI = XAPI
	handlers.Session = session

	// Set up Gin router
	r := gin.Default()

	// Apply authentication middleware to all routes
	r.Use(middleware.AuthMiddleware())

	// Define API endpoints for VM management
	r.GET("/vms", handlers.ListVMs())
	r.POST("/vms", handlers.CreateVM())
	r.GET("/vms/:id", handlers.GetVM())
	r.PUT("/vms/:id", handlers.UpdateVM())
	r.DELETE("/vms/:id", handlers.DeleteVM())

	// Start the server
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func getCredentialsFromVault() (string, string) {
	ctx := context.Background()
	// Initialise Vault client
	client, err := vault.New(
		vault.WithAddress(os.Getenv("VAULT_ADDR")),
		vault.WithRequestTimeout(30*time.Second))
	if err != nil {
		log.Fatalf("Failed to create Vault client: %v", err)
	}

	// Authenticate
	if err := client.SetToken(os.Getenv("VAULT_TOKEN")); err != nil {
		log.Fatalf("Failed to authenticate with Vault: %v", err)
	}

	// Read the secret from kvv2
	secret, err := client.Secrets.KvV2Read(ctx, os.Getenv("VAULT_SECRET_PATH"), vault.WithMountPath("secret"))
	if err != nil {
		log.Fatalf("Failed to read secret from Vault: %v", err)
	}
	if secret == nil {
		log.Fatal("Secret not found in Vault")
	}

	data := secret.Data.Data

	// Extract username
	username, ok := data["username"].(string)
	if !ok {
		log.Fatal("Failed to get username from Vault")
	}

	// Extract password
	password, ok := data["password"].(string)
	if !ok {
		log.Fatal("Failed to get password from Vault")
	}

	return username, password
}
