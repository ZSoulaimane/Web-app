package main

import (
	"fmt"
	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"templates"
)

var client *redis.Client
var store = session.NewCookieStore([]byte("t0p-s3cr3t"))
var templates *template.Tempalate

func AuthRequired(handler http.HandlerFunc)	http.Handlerfunc {
	return func (w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r,"session")
		_,ok := session.Values["username"]
		if !ok {
			http.Redirect(w, r,"/login",302)
			return
		}
		handler.ServerHTTP(w,r)
	}
}

func indexGetHandler(w http.ResponseWriter, r *http.Request) {

	comments , err := client.LRange("comments",0,10).Result()
	if err !=nil{
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server Error"))
		return
	}
	template.ExecuteTemplate(w, "index.html", comments)
}

func indexPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	comments := r.PostForm.Get("comment")
	err := client.LPush("comments",comment).Err()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server Error"))
	}
	http.Redirect(w,r,"/",302)
}

func loginGetHandler(w http.ResponseWriter,r *http.Request) {
	templates.ExecuteTemplate(w, "login.html",nil)
}

func loginPostHandler(w http.ResponseWriter,r *http.Request) {
	r.ParseForm()
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("passwword")
	hash, err := client.Get("user:" + username).Bytes()
	if err == redis.nil {
		templates.ExcuteTemplate(w, "login.html", "unknown user")
		return
	} else if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error"))
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err !=nil {
		templates.Executetemplate(w,"login.html","invalid login")
		return
	}
	session ,_ := store.Get(r,"session")
	session.Values["username"] = username
	session.Save(r,w)
}

func registerGetHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "login.html",nil)
}

func registerPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	cost := bcrypt.DefaultCost
	hash, err := bcrypt.GenerateFormPassword([]byte(password),cost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
		return
	}
	err = client.Set("user:" + username, hash , 0)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
		return
	}
	http.Redirect(w,r,"/",302)
}

func main() {
	client = redis.NewClient(&redis.Options{
			Addr : "localhost:6379",
		})
	templates = template.Must(template.ParseGlob("templates/*.html"))
	r := mux.NewRouter()
	r.HandleFunc("/", AuthRequired(indexGetHandler)).Methods("GET")
	r.HandleFunc("/", AuthRequired(indexPostHandler)).Methods("POST")
	r.HandleFunc("/login", loginGetHandler).Methods("GET")
	r.HandleFunc("/login", loginPostHandler).Methods("POST")
	r.HandleFunc("/register", registerGetHandler).Methods("GET")
	r.HandleFunc("/register", registerPostHandler).Methods("POST")
	fs := http.FileServer(http.Dir("./static/"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/",fs))
	http.Handle("/", r)
	http.ListenAndServe(":8080", nil)
}
