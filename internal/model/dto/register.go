package dto

type RegisterRequest struct {
	Username string `json:"username" xml:"username" binding:"required"`
	Password string `json:"password" xml:"password" binding:"required"`
	Email    string `json:"email" xml:"email" binding:"required"`
}
