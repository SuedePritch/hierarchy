package hierarchy

import (
	"testing"
)

// Helper function to create a sample hierarchy for testing.
func createSampleHierarchy() *Hierarchy {
	return NewHierarchy(map[uint8]string{
		0: "none",
		1: "user",
		2: "employee",
		3: "manager",
		4: "admin",
	})
}

func TestGetRoleLevel(t *testing.T) {
	h := createSampleHierarchy()

	// Test case: Valid role
	level, err := h.GetRoleLevel("employee")
	if err != nil || level != 2 {
		t.Errorf("Expected level 2 for 'employee', got %d, err: %v", level, err)
	}

	// Test case: Non-existent role
	_, err = h.GetRoleLevel("unknown")
	if err == nil {
		t.Error("Expected error for 'unknown' role, got nil")
	}
}

func TestAuth(t *testing.T) {
	h := createSampleHierarchy()

	// Test case: User meets the required role
	auth, err := h.Auth("user", "manager")
	if err != nil || !auth {
		t.Errorf("Expected 'manager' to meet 'user' requirement, got auth: %v, err: %v", auth, err)
	}

	// Test case: User does not meet the required role
	auth, err = h.Auth("admin", "user")
	if err != nil || auth {
		t.Errorf("Expected 'user' not to meet 'admin' requirement, got auth: %v, err: %v", auth, err)
	}

	// Test case: Invalid required role
	_, err = h.Auth("invalid", "manager")
	if err == nil {
		t.Error("Expected error for 'invalid' required role, got nil")
	}

	// Test case: Invalid user role
	_, err = h.Auth("admin", "invalid")
	if err == nil {
		t.Error("Expected error for 'invalid' user role, got nil")
	}
}

func TestGetRolesAbove(t *testing.T) {
	h := createSampleHierarchy()

	// Test case: Get roles above "user"
	roles, err := h.GetRolesAbove("user")
	if err != nil || len(roles) != 3 {
		t.Errorf("Expected 3 roles above 'user', got %d, err: %v", len(roles), err)
	}

	// Test case: Get roles above "admin" (should return empty slice)
	roles, err = h.GetRolesAbove("admin")
	if err != nil || len(roles) != 0 {
		t.Errorf("Expected no roles above 'admin', got %d, err: %v", len(roles), err)
	}

	// Test case: Invalid role
	_, err = h.GetRolesAbove("invalid")
	if err == nil {
		t.Error("Expected error for 'invalid' role, got nil")
	}
}

func TestGetRolesBelow(t *testing.T) {
	h := createSampleHierarchy()

	// Test case: Get roles below "manager"
	roles, err := h.GetRolesBelow("manager")
	if err != nil || len(roles) != 3 {
		t.Errorf("Expected 3 roles below 'manager', got %d, err: %v", len(roles), err)
	}

	// Test case: Get roles below "none" (should return empty slice)
	roles, err = h.GetRolesBelow("none")
	if err != nil || len(roles) != 0 {
		t.Errorf("Expected no roles below 'none', got %d, err: %v", len(roles), err)
	}

	// Test case: Invalid role
	_, err = h.GetRolesBelow("invalid")
	if err == nil {
		t.Error("Expected error for 'invalid' role, got nil")
	}
}

func TestIsHigherRole(t *testing.T) {
	h := createSampleHierarchy()

	// Test case: Higher role check
	isHigher, err := h.IsHigherRole("admin", "user")
	if err != nil || !isHigher {
		t.Errorf("Expected 'admin' to be higher than 'user', got isHigher: %v, err: %v", isHigher, err)
	}

	// Test case: Lower role check
	isHigher, err = h.IsHigherRole("user", "admin")
	if err != nil || isHigher {
		t.Errorf("Expected 'user' not to be higher than 'admin', got isHigher: %v, err: %v", isHigher, err)
	}

	// Test case: Same level roles
	isHigher, err = h.IsHigherRole("manager", "manager")
	if err != nil || isHigher {
		t.Errorf("Expected 'manager' not to be higher than itself, got isHigher: %v, err: %v", isHigher, err)
	}

	// Test case: Invalid roles
	_, err = h.IsHigherRole("invalid1", "invalid2")
	if err == nil {
		t.Error("Expected error for invalid roles, got nil")
	}
}

func TestGetMaxRole(t *testing.T) {
	h := createSampleHierarchy()

	// Test case: Get the role with the highest level
	maxRole := h.GetMaxRole()
	if maxRole != "admin" {
		t.Errorf("Expected 'admin' as the highest role, got %s", maxRole)
	}

	// Test case: Empty hierarchy
	emptyHierarchy := NewHierarchy(map[uint8]string{})
	maxRole = emptyHierarchy.GetMaxRole()
	if maxRole != "" {
		t.Errorf("Expected empty string for max role in empty hierarchy, got %s", maxRole)
	}
}

// Sample secret key for JWT tests
const secretKey = "mySecretKey"

// TestGenerateJWT tests the JWT generation function.
func TestGenerateJWT(t *testing.T) {
	// Test case: Generate a valid JWT
	token, err := GenerateJWT("12345", "admin", secretKey, 10)
	if err != nil || token == "" {
		t.Errorf("Failed to generate JWT, got token: %s, err: %v", token, err)
	}
}

// TestValidateJWT tests the JWT validation function.
func TestValidateJWT(t *testing.T) {
	// Generate a valid JWT for testing
	token, err := GenerateJWT("12345", "user", secretKey, 10)
	if err != nil {
		t.Fatalf("Failed to generate JWT for validation test, err: %v", err)
	}

	// Test case: Validate a valid JWT
	claims, err := ValidateJWT(token, secretKey)
	if err != nil {
		t.Errorf("Expected valid JWT, got error: %v", err)
	}
	if claims["user_id"] != "12345" || claims["role"] != "user" {
		t.Error("JWT claims do not match expected values")
	}

	// Test case: Validate with an incorrect secret key
	_, err = ValidateJWT(token, "wrongSecretKey")
	if err == nil {
		t.Error("Expected error for JWT with incorrect secret key, got nil")
	}

	// Test case: Validate an expired JWT
	expiredToken, err := GenerateJWT("12345", "user", secretKey, -1)
	if err != nil {
		t.Fatalf("Failed to generate expired JWT, err: %v", err)
	}
	_, err = ValidateJWT(expiredToken, secretKey)
	if err == nil {
		t.Error("Expected error for expired JWT, got nil")
	}
}

// TestGetRoleFromJWT tests the role extraction from a JWT.
func TestGetRoleFromJWT(t *testing.T) {
	// Generate a valid JWT for testing
	token, err := GenerateJWT("12345", "manager", secretKey, 10)
	if err != nil {
		t.Fatalf("Failed to generate JWT for role extraction test, err: %v", err)
	}

	// Test case: Extract role from a valid JWT
	role, err := GetRoleFromJWT(token, secretKey)
	if err != nil {
		t.Errorf("Expected to extract role, got error: %v", err)
	}
	if role != "manager" {
		t.Errorf("Expected role 'manager', got %s", role)
	}

	// Test case: Extract role with an incorrect secret key
	_, err = GetRoleFromJWT(token, "wrongSecretKey")
	if err == nil {
		t.Error("Expected error for JWT with incorrect secret key, got nil")
	}

	// Test case: Extract role from an expired JWT
	expiredToken, err := GenerateJWT("12345", "user", secretKey, -1)
	if err != nil {
		t.Fatalf("Failed to generate expired JWT for role extraction test, err: %v", err)
	}
	_, err = GetRoleFromJWT(expiredToken, secretKey)
	if err == nil {
		t.Error("Expected error for expired JWT, got nil")
	}
}

// TestAuthFromJWT tests the role authorization from a JWT using the hierarchy.
func TestAuthFromJWT(t *testing.T) {
	h := createSampleHierarchy()

	// Generate a valid JWT for testing
	token, err := GenerateJWT("12345", "employee", secretKey, 10)
	if err != nil {
		t.Fatalf("Failed to generate JWT for authorization test, err: %v", err)
	}

	// Test case: Authorized access
	auth, err := h.AuthFromJWT(token, "user", secretKey)
	if err != nil || !auth {
		t.Errorf("Expected 'employee' to be authorized for 'user', got auth: %v, err: %v", auth, err)
	}

	// Test case: Unauthorized access
	auth, err = h.AuthFromJWT(token, "admin", secretKey)
	if err != nil || auth {
		t.Errorf("Expected 'employee' not to be authorized for 'admin', got auth: %v, err: %v", auth, err)
	}

	// Test case: Invalid token (wrong secret key)
	_, err = h.AuthFromJWT(token, "user", "wrongSecretKey")
	if err == nil {
		t.Error("Expected error for JWT with incorrect secret key, got nil")
	}

	// Test case: Expired token
	expiredToken, err := GenerateJWT("12345", "employee", secretKey, -1)
	if err != nil {
		t.Fatalf("Failed to generate expired JWT for authorization test, err: %v", err)
	}
	_, err = h.AuthFromJWT(expiredToken, "user", secretKey)
	if err == nil {
		t.Error("Expected error for expired JWT, got nil")
	}
}
