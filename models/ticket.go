package models

import (
    "time"
)

type Ticket struct {
    ID          uint      `gorm:"primaryKey"`
    UserID     uint
    Title      string  `gorm:"size:255"`
    Description string
    Category    string
    Priority    string
    Status      string  `gorm:"default:'open'"` // "open", "in_progress", "resolved", "closed"
    CreatedAt   time.Time
    ResolvedAt  *time.Time
}
