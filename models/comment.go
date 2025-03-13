package models

import (
    "time"
)

type Comment struct {
    ID        uint      `gorm:"primaryKey" json:"id"`
    TicketID   uint      `json:"ticket_id"`
    UserID     uint      `json:"user_id"`
    Text       string    `json:"text"`
    CreatedAt  time.Time `json:"created_at"`
}
