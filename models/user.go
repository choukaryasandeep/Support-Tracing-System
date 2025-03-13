package models


type User struct {
    ID       uint   `gorm:"primaryKey"`
    Name     string  `gorm:"size:100"`
    Email    string  `gorm:"size:100;unique"`
    Password string
    Role     string  `gorm:"size:50"` // "user", "agent", "admin"
}
