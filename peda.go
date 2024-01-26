package peda

import (
	"encoding/json"
	"net/http"
	"os"
)

func Authorization(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response CredentialUser
	var auth User
	response.Status = false

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}

	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)
	tokennik := DecodeGetNIK(os.Getenv(publickey), header)

	auth.Username = tokenusername

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, auth) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	response.Message = "Berhasil decode token"
	response.Status = true
	response.Data.Username = tokenusername
	response.Data.Role = tokenrole
	response.Data.NIK = tokennik

	return GCFReturnStruct(response)
}

func Registrasi(mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	if UsernameExists(mongoenv, dbname, user) {
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

func Login(privatekey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, user) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !IsPasswordValid(mconn, collname, user) {
		response.Message = "Password Salah"
		return GCFReturnStruct(response)
	}

	auth := FindUser(mconn, collname, user)

	tokenstring, tokenerr := Encode(auth.Username, auth.Role, auth.NIK, os.Getenv(privatekey))
	if tokenerr != nil {
		response.Message = "Gagal encode token: " + tokenerr.Error()
		return GCFReturnStruct(response)
	}

	response.Status = true
	response.Message = "Berhasil login"
	response.Token = tokenstring

	return GCFReturnStruct(response)
}

func AmbilSemuaAkun(publickey, mongoenv, dbname, collname string, r *http.Request) string {
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

	if tokenrole != "admin" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	dataform := GetAllUser(mconn, collname)
	return GCFReturnStruct(dataform)
}

func EditUserAdmin(publickey, mongoenv, dbname, collname string, r *http.Request) string {
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
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if !UsernameExists(mongoenv, dbname, user) {
		response.Message = "Username tidak ada"
		return GCFReturnStruct(response)
	}

	hash, hashErr := HashPassword(user.Password)
	if hashErr != nil {
		response.Message = "Gagal hash password: " + hashErr.Error()
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	oldakun := FindUser(mconn, collname, user)
	if user.Password == "" {
		user.Password = oldakun.Password
	} else {
		user.Password = hash
	}

	UpdateUser(mconn, collname, user)
	response.Status = true
	response.Message = "Berhasil edit data"

	return GCFReturnStruct(response)
}

func HapusUser(publickey, mongoenv, dbname, collname string, r *http.Request) string {
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
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if !UsernameExists(mongoenv, dbname, user) {
		response.Message = "Username tidak ada"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	DeleteUser(mconn, collname, user)
	response.Status = true
	response.Message = "Berhasil hapus data"

	return GCFReturnStruct(response)
}

func TambahFormDosen(publickey, mongoenv, dbname, collname string, r *http.Request) string {
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
	tokennik := DecodeGetNIK(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	dataform.NIK = tokennik
	if NIKExists(mongoenv, dbname, dataform) {
		response.Message = "Data dengan NIK yang digunakan telah dibuat, coba edit data yang ada"
		return GCFReturnStruct(response)
	}

	InsertForm(mconn, collname, dataform)
	response.Status = true
	response.Message = "Berhasil input data"

	return GCFReturnStruct(response)
}

func TambahFormAdmin(publickey, mongoenv, dbname, collname string, r *http.Request) string {
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

	if tokenrole != "admin" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	if NIKExists(mongoenv, dbname, dataform) {
		response.Message = "Data dengan NIK yang digunakan telah dibuat, coba edit data yang ada"
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

func AmbilSatuFormDosen(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var dataform FormInput

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}

	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)
	tokennik := DecodeGetNIK(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	dataform.NIK = tokennik
	satuform := FindForm(mconn, collname, dataform)
	return GCFReturnStruct(satuform)
}

func AmbilSatuFormAdmin(publickey, mongoenv, dbname, collname string, r *http.Request) string {
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

func EditFormDosen(publickey, mongoenv, dbname, collname string, r *http.Request) string {
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
	tokennik := DecodeGetNIK(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}
	dataform.NIK = tokennik
	UpdateForm(mconn, collname, dataform)
	response.Status = true
	response.Message = "Berhasil update data"

	return GCFReturnStruct(response)
}

func EditFormAdmin(publickey, mongoenv, dbname, collname string, r *http.Request) string {
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

	if tokenrole != "admin" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}
	UpdateForm(mconn, collname, dataform)
	response.Status = true
	response.Message = "Berhasil update data"

	return GCFReturnStruct(response)
}

func HapusFormDosen(publickey, mongoenv, dbname, collname string, r *http.Request) string {
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
	tokennik := DecodeGetRole(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	dataform.NIK = tokennik
	DeleteForm(mconn, collname, dataform)
	response.Status = true
	response.Message = "Berhasil hapus data"

	return GCFReturnStruct(response)
}

func HapusFormAdmin(publickey, mongoenv, dbname, collname string, r *http.Request) string {
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

	if tokenrole != "admin" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	DeleteForm(mconn, collname, dataform)
	response.Status = true
	response.Message = "Berhasil hapus data"

	return GCFReturnStruct(response)
}
