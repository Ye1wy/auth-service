package controller

import (
	"auth-service/pkg/logger"
	"fmt"

	"github.com/gin-gonic/gin"
)

type BaseController struct {
	logger *logger.Logger
}

func NewBaseController(logger *logger.Logger) *BaseController {
	return &BaseController{
		logger: logger,
	}
}

func (bc *BaseController) responce(c *gin.Context, code int, obj any) {
	switch c.GetHeader("Accept") {
	case "application/xml":
		c.XML(code, obj)
	default:
		c.JSON(code, obj)
	}
}

func (bc *BaseController) mapping(c *gin.Context, obj any) error {
	switch c.GetHeader("content-type") {
	case "application/xml":
		if err := c.BindXML(&obj); err != nil {
			return fmt.Errorf("Base Controller: Failed bind xml: %v", err)
		}
	default:
		if err := c.BindJSON(&obj); err != nil {
			return fmt.Errorf("Base Controller: Failed bind json: %v", err)
		}
	}

	return nil
}
