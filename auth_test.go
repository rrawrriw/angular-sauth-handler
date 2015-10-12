package aauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

	TestUser struct {
		id   string
		pass string
	}
)

func (u TestUser) ID() string {
	return u.id
}

func (u TestUser) Password() string {
	return u.pass
}

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

func (t *TestRequest) Send(method, path string) *httptest.ResponseRecorder {
	reqData := *t
	body := bytes.NewBufferString(reqData.Body)

	req, _ := http.NewRequest(method, path, body)
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

func ParseSignInResponse(r *bytes.Buffer) (SuccessResponse, error) {

	resp := SuccessResponse{}
	err := json.Unmarshal(r.Bytes(), &resp)
	if err != nil {
		return SuccessResponse{}, err
	}

	if resp.Status != "success" {
		return SuccessResponse{}, errors.New("Wrong status")
	}

	v, ok := resp.Data.(map[string]interface{})
	if !ok {
		return SuccessResponse{}, errors.New("Wrong data type")
	}

	id, ok := v["ID"].(string)
	if !ok {
		return SuccessResponse{}, errors.New("Wrong id type")
	}

	data := UserIDData{
		ID: id,
	}

	return NewSuccessResponse(data), nil
}

func EqualSignInResponse(r1, r2 SuccessResponse) error {
	if r1.Status != r2.Status {
		return errors.New("Unequal status")
	}

	id1, ok := r1.Data.(UserIDData)
	if !ok {
		return errors.New("Wrong data in r1")
	}
	id2, ok := r1.Data.(UserIDData)
	if !ok {
		return errors.New("Wrong data in r2")
	}

	if id1 != id2 {
		return errors.New("Unequal ids")
	}

	return nil

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

func Test_GET_SignIn_OK(t *testing.T) {
	id := "456"
	name := "ladykiller_XX"
	pass := "123"

	handler := gin.New()
	req := TestRequest{
		Body:    "",
		Header:  http.Header{},
		Handler: handler,
	}

	getPass := func(x string) (User, error) {
		u := TestUser{id, pass}
		return u, nil
	}

	handler.GET("/:name/:pass", AngularSignIn(getPass))

	url := fmt.Sprintf("/%v/%v", name, pass)
	resp := req.Send("GET", url)

	userID := UserIDData{
		ID: id,
	}
	expectResp := NewSuccessResponse(userID)

	result, err := ParseSignInResponse(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	err = EqualSignInResponse(expectResp, result)
	if err != nil {
		t.Fatal("Expect", expectResp, "was", resp)
	}

}
