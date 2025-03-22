package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terra-farm/go-xen-api-client"
)

var XAPI *xenapi.Client
var Session xenapi.SessionRef

// ListVMs handles the GET /vms endpoint
func ListVMs() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isAdmin(c) {
			return
		}

		// Fetch all VM records from XCP-NG
		vmRecords, err := XAPI.VM.GetAllRecords(Session)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Convert map to a list of VM names (adjust fields as needed)
		var vmList []string
		for _, vm := range vmRecords {
			vmList = append(vmList, vm.NameLabel)
		}

		c.JSON(http.StatusOK, gin.H{"vms": vmList})
	}
}

// CreateVM handles the POST /vms endpoint
func CreateVM() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isAdmin(c) {
			return
		}

		var vmConfig struct {
			NameLabel   string `json:"name_label" binding:"required"`
			Template    string `json:"template" binding:"required"`
			Description string `json:"description"`
		}
		if err := c.ShouldBindJSON(&vmConfig); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Example: Create a VM from a template (adjust as per your needs)
		templateRef, err := XAPI.VM.GetByNameLabel(Session, vmConfig.Template)
		if err != nil || len(templateRef) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Template not found"})
			return
		}

		vmRef, err := XAPI.VM.Clone(Session, templateRef[0], vmConfig.NameLabel)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"vm_id": vmRef})
	}
}

// GetVM handles the GET /vms/:id endpoint
func GetVM() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isAdmin(c) {
			return
		}

		vmRef := xenapi.VMRef(c.Param("id"))
		vmRecord, err := XAPI.VM.GetRecord(Session, vmRef)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "VM not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"name_label":  vmRecord.NameLabel,
			"description": vmRecord.NameDescription,
			"power_state": vmRecord.PowerState,
		})
	}
}

// UpdateVM handles the PUT /vms/:id endpoint
func UpdateVM() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isAdmin(c) {
			return
		}

		vmRef := xenapi.VMRef(c.Param("id"))
		var update struct {
			NameLabel   string `json:"name_label"`
			Description string `json:"description"`
		}
		if err := c.ShouldBindJSON(&update); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		if update.NameLabel != "" {
			if err := XAPI.VM.SetNameLabel(Session, vmRef, update.NameLabel); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}
		if update.Description != "" {
			if err := XAPI.VM.SetNameDescription(Session, vmRef, update.Description); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{"message": "VM updated"})
	}
}

// DeleteVM handles the DELETE /vms/:id endpoint
func DeleteVM() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isAdmin(c) {
			return
		}

		vmRef := xenapi.VMRef(c.Param("id"))
		err := XAPI.VM.Destroy(Session, vmRef)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "VM deleted"})
	}
}

// isAdmin checks if the user has the admin role
func isAdmin(c *gin.Context) bool {
	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return false
	}

	claimsMap, ok := claims.(map[string]interface{})
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid claims format"})
		return false
	}

	roles, ok := claimsMap["roles"].([]interface{})
	if !ok || !containsRole(roles, "admin") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: Admin role required"})
		return false
	}

	return true
}

// containsRole checks if a role exists in the claims
func containsRole(roles []interface{}, target string) bool {
	for _, r := range roles {
		if role, ok := r.(string); ok && role == target {
			return true
		}
	}
	return false
}
