package hierarchy

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Custom errors for role management.
var (
	ErrRoleNotFound = errors.New("role not found")
)

// Hierarchy struct to hold the role hierarchy.
// It maps unsigned 8-bit integers (representing levels) to role names (strings).
// Example usage: 0 -> "none", 1 -> "user", 2 -> "employee", etc.
type Hierarchy struct {
	Roles map[uint8]string
}

// NewHierarchy initializes a new Hierarchy instance with the provided map of roles.
// The roleHierarchy map should define the role levels and corresponding role names.
// Example input: map[uint8]string{0: "none", 1: "user", 2: "employee"}.
// Returns a pointer to the initialized Hierarchy instance.
func NewHierarchy(roleHierarchy map[uint8]string) *Hierarchy {
	return &Hierarchy{Roles: roleHierarchy}
}

// GetRoleLevel retrieves the level (uint8) associated with a given role name (string).
// If the role exists, it returns the corresponding level. Otherwise, it returns an error.
//
// Parameters:
// - role: the name of the role to look up.
//
// Returns:
// - uint8: the level of the role if found.
// - error: an error if the role does not exist in the hierarchy.
func (h *Hierarchy) GetRoleLevel(role string) (uint8, error) {
	for level, r := range h.Roles {
		if r == role {
			return level, nil
		}
	}
	return 0, ErrRoleNotFound
}

// Auth checks if a user's role level is greater than or equal to a required role level.
// Returns true if the user's role level meets or exceeds the required level.
// If either role does not exist, it returns an error.
//
// Parameters:
// - requiredRole: the role name that represents the minimum access level required.
// - userRole: the role name of the user being checked.
//
// Returns:
// - bool: true if the user's role level is sufficient, false otherwise.
// - error: an error if either role is not found in the hierarchy.
func (h *Hierarchy) Auth(requiredRole string, userRole string) (bool, error) {
	requiredLevel, err := h.GetRoleLevel(requiredRole)
	if err != nil {
		return false, fmt.Errorf("required role check failed: %w", err)
	}

	userLevel, err := h.GetRoleLevel(userRole)
	if err != nil {
		return false, fmt.Errorf("user role check failed: %w", err)
	}

	return userLevel >= requiredLevel, nil
}

// GetRolesAbove returns all roles that are above the specified role in the hierarchy.
// The returned slice contains role names for all roles with a higher level than the given role.
// If the role is not found, it returns an error.
//
// Parameters:
// - role: the name of the role to compare against.
//
// Returns:
// - []string: a slice of role names that are above the specified role.
// - error: an error if the specified role is not found.
func (h *Hierarchy) GetRolesAbove(role string) ([]string, error) {
	roleLevel, err := h.GetRoleLevel(role)
	if err != nil {
		return nil, err
	}

	var rolesAbove []string
	for level, r := range h.Roles {
		if level > roleLevel {
			rolesAbove = append(rolesAbove, r)
		}
	}
	return rolesAbove, nil
}

// GetRolesBelow returns all roles that are below the specified role in the hierarchy.
// The returned slice contains role names for all roles with a lower level than the given role.
// If the role is not found, it returns an error.
//
// Parameters:
// - role: the name of the role to compare against.
//
// Returns:
// - []string: a slice of role names that are below the specified role.
// - error: an error if the specified role is not found.
func (h *Hierarchy) GetRolesBelow(role string) ([]string, error) {
	roleLevel, err := h.GetRoleLevel(role)
	if err != nil {
		return nil, err
	}

	var rolesBelow []string
	for level, r := range h.Roles {
		if level < roleLevel {
			rolesBelow = append(rolesBelow, r)
		}
	}
	return rolesBelow, nil
}

// IsHigherRole checks if one role is hierarchically higher than another.
// It compares the levels of the two provided roles and returns true if the first role is higher.
// If either role does not exist, it returns an error.
//
// Parameters:
// - role1: the role name to check if it is higher.
// - role2: the role name to compare against.
//
// Returns:
// - bool: true if role1 is higher than role2, false otherwise.
// - error: an error if either role is not found in the hierarchy.
func (h *Hierarchy) IsHigherRole(role1, role2 string) (bool, error) {
	role1Level, err := h.GetRoleLevel(role1)
	if err != nil {
		return false, fmt.Errorf("role1 check failed: %w", err)
	}

	role2Level, err := h.GetRoleLevel(role2)
	if err != nil {
		return false, fmt.Errorf("role2 check failed: %w", err)
	}

	return role1Level > role2Level, nil
}

// GetMaxRole returns the role with the highest level in the hierarchy.
// If no roles are found in the hierarchy, it returns an empty string.
//
// Returns:
// - string: the name of the role with the highest level, or an empty string if no roles exist.
func (h *Hierarchy) GetMaxRole() string {
	var maxLevel uint8
	var maxRole string

	for level, role := range h.Roles {
		if level > maxLevel {
			maxLevel = level
			maxRole = role
		}
	}
	return maxRole
}

// Password Utilities

// HashPassword hashes a plain-text password using bcrypt.
// bcrypt adds computational cost to password hashing, making brute-force attacks harder.
//
// Parameters:
// - password: the plain-text password to hash.
//
// Returns:
// - string: the hashed password as a string.
// - error: an error if hashing fails.
func HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

// ComparePassword compares a plain-text password with its hashed version.
// It uses bcrypt to perform the comparison securely.
//
// Parameters:
// - hashedPassword: the hashed password stored in the system.
// - password: the plain-text password provided by the user.
//
// Returns:
// - bool: true if the password matches the hashed password, false otherwise.
func ComparePassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// JWT Utilities

// GenerateJWT creates a JWT containing the user's ID, role, and expiration time.
// The token is signed using the provided secretKey and expires after the specified duration.
//
// Parameters:
// - userID: the user's ID to include in the token claims.
// - role: the user's role to include in the token claims.
// - secretKey: the secret key used to sign the token.
// - expirationMinutes: the number of minutes until the token expires.
//
// Returns:
// - string: the signed JWT token as a string.
// - error: an error if token creation fails.
func GenerateJWT(userID string, role string, secretKey string, expirationMinutes int) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"role":    role,
		"exp":     time.Now().Add(time.Duration(expirationMinutes) * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

// ValidateJWT checks if a given JWT token is valid and verifies its signature.
// Returns the token claims if valid; otherwise, returns an error.
//
// Parameters:
// - tokenString: the JWT token string to validate.
// - secretKey: the secret key used to sign the token.
//
// Returns:
// - jwt.MapClaims: the claims contained in the token if valid.
// - error: an error if the token is invalid or the signature does not match.
func ValidateJWT(tokenString string, secretKey string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// GetRoleFromJWT extracts the user's role from a valid JWT token.
// It returns the role as a string if the token is valid, or an error if the token is invalid or the role is not found.
//
// Parameters:
// - tokenString: the JWT token string to parse.
// - secretKey: the secret key used to sign the token.
//
// Returns:
// - string: the role extracted from the token claims.
// - error: an error if the token is invalid or the role is not found in the claims.
func GetRoleFromJWT(tokenString string, secretKey string) (string, error) {
	claims, err := ValidateJWT(tokenString, secretKey)
	if err != nil {
		return "", err
	}

	role, ok := claims["role"].(string)
	if !ok {
		return "", fmt.Errorf("role not found in token")
	}

	return role, nil
}

// AuthFromJWT extracts the role from a JWT token and checks if it meets or exceeds the required role level.
// It takes the JWT token string, required role, and secret key as inputs.
//
// Parameters:
// - tokenString: the JWT token string containing the user's role.
// - requiredRole: the minimum role required to access the resource.
// - secretKey: the secret key used to validate the token.
//
// Returns:
// - bool: true if the user's role meets the required level, false otherwise.
// - error: an error if token validation or role extraction fails.
func (h *Hierarchy) AuthFromJWT(tokenString string, requiredRole string, secretKey string) (bool, error) {
	userRole, err := GetRoleFromJWT(tokenString, secretKey)
	if err != nil {
		return false, fmt.Errorf("failed to get role from JWT: %w", err)
	}

	return h.Auth(requiredRole, userRole)
}
