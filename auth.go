package aauth

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const (
	GinContextField  = "Session"
	XSRFCookieName   = "XSRF-TOKEN"
	TokenHeaderField = "X-XSRF-TOKEN"
)

type (
	FailResponse struct {
		Status string
		Err    string
	}

	Session struct {
		Token   string    `bson:"Token"`
		UserID  string    `bson:"UserID"`
		Expires time.Time `bson:"Expires"`
	}
)

func NewFailResponse(err interface{}) FailResponse {
	return FailResponse{
		Status: "fail",
		Err:    fmt.Sprintf("%v", err),
	}
}

// Middleware Decorator:
// Handles Angularjs Default Authentication
// Sendet man über den angular http Serviecs ein Request und erhält
// daraufhin ein Response mit einem Cookie welcher ein XSRF-Token Feld
// enthält wird der hinterlegte Token für zukünftige Request verwendet.
// Der Token wird als HTTP-Header-Feld X-XSRF-Token versand. Diesen
// Eigenschaft kann man für die Benutzer Authentifikation verwenden.
//
// Die Middleware fügt ein Feld Session zum gin Context.
//
// Die Middleware erwartet ein Session Collection mit den selben
// Feldern wie der Session Typ
//
// Example:
// app := gin.New()
//
// func protectedHandler(c *gin.Context) {
//      // Access only for succesfully authenticated user
// }
//
// s,_ := db.Dial("mongodb://127.0.0.1:27017")
// db := s.DB("DBName")
// auth := AngularAuth(*mgo.Database, "SessionCollName")
// app.GET(auth, portectedHandler)
//
func AngularAuth(db *mgo.Database, coll string) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := Auther(c, db, coll)
		if err != nil {
			c.JSON(http.StatusUnauthorized,
				NewFailResponse(err))
			c.Abort()
		}
	}
}

func Auther(c *gin.Context, db *mgo.Database, sessionsColl string) error {
	token := c.Request.Header.Get(TokenHeaderField)
	if token == "" {
		cookie, err := c.Request.Cookie(XSRFCookieName)
		if err != nil {
			return errors.New("Cookie not found")
		}
		token = cookie.Value
		if token == "" {
			return errors.New("Header not found")
		}
	}

	coll := db.C(sessionsColl)
	find := coll.Find(bson.M{"Token": token})
	n, err := find.Count()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("Session not found")

	}

	session := Session{}
	err = find.One(&session)
	if err != nil {
		return err
	}
	if session.Expires.Before(time.Now()) {
		return errors.New("Session expired")
	}

	c.Set(GinContextField, session)
	c.Next()
	return nil
}
