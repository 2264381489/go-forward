package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/kpango/glg"
)

func main() {
	router := httprouter.New()
	InitLog()
	// HTTP Server FORWARD  HTTP Request
	router.GET("/alert/wechat/api", ForwardHandler)
	// router panic handler
	router.PanicHandler = func(w http.ResponseWriter, r *http.Request, i interface{}) {
		glg.Errorf("panic: %+v", i)
	}
	// HTTP Server
	http.ListenAndServe(":8080", router)
}

func ForwardHandler(writer http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	u := &url.URL{
		Scheme: " https",
		Host:   "jarvis-alert.niulinkcloud.com",
		Path:   "/alert/wechat/api",
	}

	signature, timestamp, nonce := generateSign()
	u.Query().Set("signature", signature)
	u.Query().Set("timestamp", timestamp)
	u.Query().Set("nonce", nonce)
	u.Query().Set("echostr", "test")
	proxy := httputil.NewSingleHostReverseProxy(u)

	proxy.ServeHTTP(writer, request)
}

func InitLog() {

	infolog := glg.FileWriter("/tmp/info.log", 0666)

	errlog := glg.FileWriter("/tmp/error.log", 0666)
	glg.Get().AddLevelWriter(glg.INFO, infolog).AddLevelWriter(glg.ERR, errlog) // add info log file destination

}

func generateSign() (signature, timestamp, nonce string) {
	timestamp = strconv.FormatInt(time.Now().Unix(), 10)
	token := os.Getenv("TOKEN")
	nonce = "" // 随机数
	for i := 0; i < 20; i++ {
		result, _ := rand.Int(rand.Reader, big.NewInt(100))
		nonce += strconv.FormatInt(result.Int64(), 10)
	}
	//将token、timestamp、nonce三个参数进行字典序排序
	var tempArray = []string{token, timestamp, nonce}
	sort.Strings(tempArray)
	//将三个参数字符串拼接成一个字符串进行sha1加密
	var sha1String string = ""
	for _, v := range tempArray {
		sha1String += v
	}
	h := sha1.New()
	h.Write([]byte(sha1String))
	signature = hex.EncodeToString(h.Sum([]byte("")))
	return
}
