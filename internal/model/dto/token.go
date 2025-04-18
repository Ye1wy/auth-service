package dto

type GivingToken struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type TakenToken struct {
	Refresh string `json:"refresh" binding:"required"`
}
