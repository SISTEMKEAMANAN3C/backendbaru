package peda

import (
	"context"
	"encoding/json"
	"os"

	"github.com/aiteung/atdb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func SetConnection(MONGOCONNSTRINGENV, dbname string) *mongo.Database {
	var DBmongoinfo = atdb.DBInfo{
		DBString: os.Getenv(MONGOCONNSTRINGENV),
		DBName:   dbname,
	}
	return atdb.MongoConnect(DBmongoinfo)
}

func GCFReturnStruct(DataStuct any) string {
	jsondata, _ := json.Marshal(DataStuct)
	return string(jsondata)
}

// User --------------------------

func InsertUser(mongoconn *mongo.Database, collection string, datauser User) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, datauser)
}

func GetAllUser(mconn *mongo.Database, collname string) []User {
	user := atdb.GetAllDoc[[]User](mconn, collname)
	return user
}

func FindUser(mongoconn *mongo.Database, collection string, datauser User) User {
	filter := bson.M{"username": datauser.Username}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func UsernameExists(mongoenvkatalogfilm, dbname string, datauser User) bool {
	mconn := SetConnection(mongoenvkatalogfilm, dbname).Collection("user")
	filter := bson.M{"username": datauser.Username}

	var user User
	err := mconn.FindOne(context.Background(), filter).Decode(&user)
	return err == nil
}

func IsPasswordValid(mconn *mongo.Database, collname string, datauser User) bool {
	filter := bson.M{"username": datauser.Username}
	res := atdb.GetOneDoc[User](mconn, collname, filter)
	hashChecker := CheckPasswordHash(datauser.Password, res.Password)
	return hashChecker
}

func UpdateUser(mconn *mongo.Database, collname string, datauser User) interface{} {
	filter := bson.M{"username": datauser.Username}
	return atdb.ReplaceOneDoc(mconn, collname, filter, datauser)
}

// Form --------------------------

func InsertForm(mconn *mongo.Database, collname string, dataform FormInput) interface{} {
	return atdb.InsertOneDoc(mconn, collname, dataform)
}

func GetAllForm(mongoconn *mongo.Database, collection string) []FormInput {
	dataform := atdb.GetAllDoc[[]FormInput](mongoconn, collection)
	return dataform
}

func FindForm(mongoconn *mongo.Database, collection string, dataform FormInput) FormInput {
	filter := bson.M{"nik": dataform.NIK}
	return atdb.GetOneDoc[FormInput](mongoconn, collection, filter)
}

func NIKExists(mongoenvkatalogfilm, dbname string, dataform FormInput) bool {
	mconn := SetConnection(mongoenvkatalogfilm, dbname).Collection("form")
	filter := bson.M{"nik": dataform.NIK}

	var form FormInput
	err := mconn.FindOne(context.Background(), filter).Decode(&form)
	return err == nil
}

func UpdateForm(mconn *mongo.Database, collname string, dataform FormInput) interface{} {
	filter := bson.M{"nik": dataform.NIK}
	return atdb.ReplaceOneDoc(mconn, collname, filter, dataform)
}

func DeleteForm(mconn *mongo.Database, collname string, dataform FormInput) interface{} {
	filter := bson.M{"nik": dataform.NIK}
	return atdb.DeleteOneDoc(mconn, collname, filter)
}
