package common

import (
	"log"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/appleboy/gin-jwt.v2"

	"errors"
	"fmt"
)

// ValidateIntInput checks if a the value is bigger than the specified maxValue
func ValidateIntInput(maxValue string, input string) error {
	maxInt, err := strconv.Atoi(maxValue)
	if err != nil {
		log.Fatal("Could not parse 'MAX' value of", maxValue)
	}

	inputInt, err := strconv.Atoi(input)
	if err != nil {
		return errors.New("Bitte eine gültige Zahl eintragen")
	}

	if inputInt > maxInt {
		return fmt.Errorf("Der Maximalwert für diese Eingabe ist: %v", maxValue)
	}

	return nil
}

// GetUserName returns the username based of the gin.Context
func GetUserName(c *gin.Context) string {
	// AuthUserKey is set by basic auth
	user, exists := c.Get(gin.AuthUserKey)
	if exists {
		return strings.ToLower(user.(string))
	}
	jwtClaims := jwt.ExtractClaims(c)
	return strings.ToLower(jwtClaims["id"].(string))
}

// GetUserMail returns the users mail address based of the gin.Context
func GetUserMail(c *gin.Context) string {
	jwtClaims := jwt.ExtractClaims(c)
	return jwtClaims["mail"].(string)
}

// DebugMode returns if gin is running in debug mode
func DebugMode() bool {
	mode := gin.Mode()

	return mode != gin.ReleaseMode
}

func RemoveDuplicates(elements []string) []string {
	encountered := map[string]bool{}

	// Create a map of all unique elements.
	for v := range elements {
		encountered[elements[v]] = true
	}

	// Place all keys from the map into a slice.
	result := []string{}
	for key := range encountered {
		result = append(result, key)
	}
	return result
}
