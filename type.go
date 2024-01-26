package peda

import (
	"time"
)

type Pesan struct {
	Status  bool        `json:"status" bson:"status"`
	Message string      `json:"message" bson:"message"`
	Data    interface{} `json:"data,omitempty" bson:"data,omitempty"`
	Token   string      `json:"token,omitempty" bson:"token,omitempty"`
}
type CredentialUser struct {
	Status bool `json:"status" bson:"status"`
	Data   struct {
		Username string `json:"username" bson:"username"`
		Role     string `json:"role" bson:"role"`
		NIK      string `json:"nik" bson:"nik"`
	} `json:"data" bson:"data"`
	Message string `json:"message,omitempty" bson:"message,omitempty"`
}

type User struct {
	Username    string `json:"username" bson:"username"`
	Password    string `json:"password" bson:"password,omitempty"`
	Role        string `json:"role,omitempty" bson:"role,omitempty"`
	Token       string `json:"token,omitempty" bson:"token,omitempty"`
	Private     string `json:"private,omitempty" bson:"private,omitempty"`
	Publick     string `json:"publick,omitempty" bson:"publick,omitempty"`
	No_whatsapp string `json:"no_whatsapp,omitempty" bson:"no_whatsapp,omitempty"`
	NIK         string `json:"nik" bson:"nik"`
}

type UserToken struct {
	Username User `json:"username" bson:"username"`
}

type Payload struct {
	NIK      string    `json:"nik"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
	Exp      time.Time `json:"exp"`
	Iat      time.Time `json:"iat"`
	Nbf      time.Time `json:"nbf"`
}

type Credential struct {
	Status   bool        `json:"status" bson:"status"`
	Token    string      `json:"token,omitempty" bson:"token,omitempty"`
	Message  string      `json:"message,omitempty" bson:"message,omitempty"`
	Username string      `json:"username,omitempty" bson:"username,omitempty"`
	Data     interface{} `json:"data,omitempty" bson:"data,omitempty"`
}

type Response struct {
	Status  bool        `json:"status" bson:"status"`
	Message string      `json:"message" bson:"message"`
	Data    interface{} `json:"data" bson:"data"`
}

type FormInput struct {
	NIK        string       `json:"nik" bson:"nik"`
	Akademis   Akademis     `json:"akademis" bson:"akademis"`
	Sertifikat []Sertifikat `json:"sertifikat" bson:"sertifikat"`
	SuratKerja []SuratKerja `json:"suratkerja" bson:"suratkerja"`
	Status     bool         `json:"status" bson:"status"`
}

type Akademis struct {
	Nama_Dosen        string `json:"nama_dosen" bson:"nama_dosen"`
	Pendidikan_Dosen  string `json:"pendidikan_dosen" bson:"pendidikan_dosen"`
	Gelar_Dosen       string `json:"gelar_dosen" bson:"gelar_dosen"`
	Kemampuan_Dosen   string `json:"kemampuan_dosen" bson:"kemampuan_dosen"`
	Penghargaan_Dosen string `json:"penghargaan_dosen" bson:"penghargaan_dosen"`
}

type Sertifikat struct {
	Judul_Sertifikat              string `json:"judul_sertifikat" bson:"judul_sertifikat"`
	Pemberi_Sertifikat            string `json:"pemberi_sertifikat" bson:"pemberi_sertifikat"`
	Penerima_Sertifikat           string `json:"penerima_sertifikat" bson:"penerima_sertifikat"`
	Tanggal_Penerbitan_Sertifikat string `json:"tanggal_penerbitan_sertifikat" bson:"tanggal_penerbitan_sertifikat"`
	Nomor_Sertifikat              string `json:"nomor_sertifikat" bson:"nomor_sertifikat"`
}

type SuratKerja struct {
	Penawaran_Kerja     string `json:"penawaran_kerja" bson:"penawaran_kerja"`
	Perjanjian_Kerja    string `json:"perjanjian_kerja" bson:"perjanjian_kerja"`
	Pemberhentian_Kerja string `json:"pemberhentian_kerja" bson:"pemberhentian_kerja"`
	Keterangan_Kerja    string `json:"keterangan_kerja" bson:"keterangan_kerja"`
	Kuasa_Kerja         string `json:"kuasa_kerja" bson:"kuasa_kerja"`
}
