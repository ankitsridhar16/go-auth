package repository

import (
	"ankitsridhar/auth/prisma/db"
	"context"
	"log"
	"time"
)

func CheckIfUserEmailExists(ctx context.Context, email string) bool {
	var client *db.PrismaClient
	user, err := client.Users.FindUnique(db.Users.Email.Equals(email)).Exec(ctx)
	if err != nil {
		log.Fatalf("user retrieval failed")
		return false
	}

	if user == nil {
		return false
	}

	return true
}

func CreateUserSession(ctx context.Context, sessionToken string, username string, email string,
	expiresAt time.Time) (bool, error) {
	var client *db.PrismaClient
	_, err := client.Sessions.CreateOne(db.Sessions.SessionToken.Set(sessionToken),
		db.Sessions.Username.Set(username), db.Sessions.Email.Set(email),
		db.Sessions.Expiry.Set(expiresAt)).Exec(ctx)

	if err != nil {
		return false, err
	}

	return true, nil
}

func Signup(ctx context.Context, username string, email string, password string) (bool, error) {
	var client *db.PrismaClient
	_, err := client.Users.CreateOne(db.Users.Username.Set(username),
		db.Users.Password.Set(password), db.Users.Email.Set(email)).Exec(ctx)

	if err != nil {
		return false, err
	}

	return true, nil
}

//func Signin(ctx context.Context, username string, password string) bool {
//	var client *db.PrismaClient
//	user, err := client.Users.FindUnique(db.Users.Username.Equals(username)).Exec(ctx)
//	if err != nil {
//		log.Fatalf("user retrieval failed")
//		return false
//	}
//
//	errCompare := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
//	if errCompare != nil {
//		fmt.Println("passwords do not match")
//		return false
//	}
//
//}
