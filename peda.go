package peda

import (
	"encoding/json"
	"net/http"
	"os"
)

func Authorization(publickeykatalogkemanan, mongoenvkatalogfilm, dbname, collname string, r *http.Request) string {
	var response CredentialUser
	var auth User
	response.Status = false

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}

	tokenname := DecodeGetName(os.Getenv(publickeykatalogkemanan), header)
	tokenusername := DecodeGetUsername(os.Getenv(publickeykatalogkemanan), header)
	tokenrole := DecodeGetRole(os.Getenv(publickeykatalogkemanan), header)

	auth.Username = tokenusername

	if tokenname == "" || tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenvkatalogfilm, dbname, auth) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	response.Message = "Berhasil decode token"
	response.Status = true
	response.Data.No_whatsapp = tokenname
	response.Data.Username = tokenusername
	response.Data.Role = tokenrole

	return GCFReturnStruct(response)
}

func Registrasi(mongoenvkatalogfilm, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenvkatalogfilm, dbname)
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	if UsernameExists(mongoenvkatalogfilm, dbname, user) {
		response.Message = "Username telah dipakai"
		return GCFReturnStruct(response)
	}

	hash, hashErr := HashPassword(user.Password)
	if hashErr != nil {
		response.Message = "Gagal hash password: " + hashErr.Error()
		return GCFReturnStruct(response)
	}

	user.Password = hash

	InsertUser(mconn, collname, user)
	response.Status = true
	response.Message = "Berhasil input data"

	return GCFReturnStruct(response)
}

func Login(privatekeykatalogkemanan, mongoenvkatalogfilm, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenvkatalogfilm, dbname)
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenvkatalogfilm, dbname, user) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !IsPasswordValid(mconn, collname, user) {
		response.Message = "Password Salah"
		return GCFReturnStruct(response)
	}

	auth := FindUser(mconn, collname, user)

	tokenstring, tokenerr := Encode(auth.No_whatsapp, auth.Username, auth.Role, os.Getenv(privatekeykatalogkemanan))
	if tokenerr != nil {
		response.Message = "Gagal encode token: " + tokenerr.Error()
		return GCFReturnStruct(response)
	}

	response.Status = true
	response.Message = "Berhasil login"
	response.Token = tokenstring

	return GCFReturnStruct(response)
}

func TambahForm(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var dataform FormInput
	err := json.NewDecoder(r.Body).Decode(&dataform)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}
	tokenname := DecodeGetName(os.Getenv(publickey), header)
	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" || tokenname == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" && tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	InsertForm(mconn, collname, dataform)
	response.Status = true
	response.Message = "Berhasil input data"

	return GCFReturnStruct(response)
}

func AmbilSemuaForm(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}

	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" && tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	dataform := GetAllForm(mconn, collname)
	return GCFReturnStruct(dataform)
}

func AmbilSatuForm(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var dataform FormInput
	err := json.NewDecoder(r.Body).Decode(&dataform)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}

	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" && tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	satuform := FindForm(mconn, collname, dataform)
	return GCFReturnStruct(satuform)
}

func EditForm(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var dataform FormInput
	err := json.NewDecoder(r.Body).Decode(&dataform)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}
	tokenname := DecodeGetName(os.Getenv(publickey), header)
	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" || tokenname == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" && tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}
	UpdateForm(mconn, collname, dataform)
	response.Status = true
	response.Message = "Berhasil update data"

	return GCFReturnStruct(response)
}

func HapusForm(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var dataform FormInput
	err := json.NewDecoder(r.Body).Decode(&dataform)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}
	tokenname := DecodeGetName(os.Getenv(publickey), header)

	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" || tokenname == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" && tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	DeleteForm(mconn, collname, dataform)
	response.Status = true
	response.Message = "Berhasil hapus data"

	return GCFReturnStruct(response)
}

func GetAllUserr(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false

	mconn := SetConnection(mongoenv, dbname)
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}

	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" && tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	satuform := GetAllUser(mconn, collname)
	return GCFReturnStruct(satuform)
}
