package bebber

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gopkg.in/mgo.v2"

	"github.com/gin-gonic/gin"
)

const (
	TestDBURL        = "mongodb://127.0.0.1:27017"
	TestDBName       = "testing-db"
	TestSessionsColl = "Session"
)

type (
	TestRequest struct {
		Body    string
		Handler http.Handler
		Header  http.Header
	}
)

func (t *TestRequest) SendWithToken(method, path, token string) *httptest.ResponseRecorder {
	reqData := *t
	body := bytes.NewBufferString(reqData.Body)
	reqData.Header.Add("X-XSRF-TOKEN", token)

	req, _ := http.NewRequest(method, path, body)
	req.Header = reqData.Header
	w := httptest.NewRecorder()
	reqData.Handler.ServeHTTP(w, req)
	*t = reqData
	return w
}

func NewTestSession(user, token string, db *mgo.Database, t *testing.T) {
	coll := db.C(TestSessionsColl)
	expires := time.Now().AddDate(0, 0, 1)
	session := Session{
		Token:   token,
		UserID:  user,
		Expires: expires,
	}
	err := coll.Insert(session)
	if err != nil {
		t.Fatal(err)
	}
}

func DialTestDB(t *testing.T) (*mgo.Session, *mgo.Database) {
	s, err := mgo.Dial(TestDBURL)
	if err != nil {
		t.Fatal(err)
	}
	db := s.DB(TestDBName)

	return s, db
}

func CleanTestDB(t *testing.T, s *mgo.Session, db *mgo.Database) {
	err := db.DropDatabase()
	if err != nil {
		t.Fatal(err)
	}

	s.Close()
}

func Test_VerifyAuth_OK(t *testing.T) {
	s, db := DialTestDB(t)
	defer CleanTestDB(t, s, db)

	userName := "loveMaster_999"
	userToken := "123"
	NewTestSession(userName, userToken, db, t)

	h := gin.New()
	// Test if session key in gin context
	afterAuth := func(c *gin.Context) {
		se, err := c.Get(GinContextField)
		if err != nil {
			t.Fatal(err)
		}
		c.JSON(http.StatusOK, se)
	}
	auth := AngularAuth(db, TestSessionsColl)
	h.GET("/", auth, afterAuth)

	request := TestRequest{
		Body:    "",
		Header:  http.Header{},
		Handler: h,
	}
	response := request.SendWithToken("GET", "/", userToken)

	if response.Code != 200 {
		t.Fatal("Expect http-status 200 was", response.Code)
	}

	session := Session{}
	err := json.Unmarshal(response.Body.Bytes(), &session)
	if err != nil {
		t.Fatal(err.Error())
	}

	if session.UserID != userName {
		t.Fatal("Expect", userName, "was", session.UserID)
	}

	if session.Token != userToken {
		t.Fatal("Expect", userToken, "was", session.Token)
	}

}

func Test_VerifyAuth_Fail(t *testing.T) {
	s, db := DialTestDB(t)
	defer CleanTestDB(t, s, db)

	h := gin.New()
	auth := AngularAuth(db, TestSessionsColl)
	afterAuth := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"Status": "success"})
	}
	h.GET("/", auth, afterAuth)
	request := TestRequest{
		Body:    "",
		Header:  http.Header{},
		Handler: h,
	}
	response := request.SendWithToken("GET", "/", "123")

	if response.Code != 401 {
		t.Fatal("Expect http-status 401 was", response.Code)
	}

}

func Test_VerifyAuth_ExpiresFail(t *testing.T) {
	s, db := DialTestDB(t)
	defer CleanTestDB(t, s, db)

	coll := db.C(TestSessionsColl)
	expires := time.Now().AddDate(0, 0, -1)
	session := Session{
		Token:   "123",
		UserID:  "loveMaster_999",
		Expires: expires,
	}
	err := coll.Insert(session)
	if err != nil {
		t.Fatal(err)
	}

	h := gin.New()
	auth := AngularAuth(db, TestSessionsColl)
	afterAuth := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"Status": "success"})
	}
	h.GET("/", auth, afterAuth)
	request := TestRequest{
		Body:    "",
		Header:  http.Header{},
		Handler: h,
	}

	response := request.SendWithToken("GET", "/", "123")

	if response.Code != 401 {
		t.Fatal("Expect http-status 401 was", response.Code)
	}

}
