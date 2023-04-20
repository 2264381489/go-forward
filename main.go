package main

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/kpango/glg"
)

func main() {
	router := httprouter.New()
	InitLog()
	// HTTP Server FORWARD  HTTP Request
	router.GET("/alert/wechat/api", ForwardHandler)
	router.POST("/alert/wechat/api", ForwardHandler)
	// router panic handler
	router.PanicHandler = func(w http.ResponseWriter, r *http.Request, i interface{}) {
		glg.Errorf("stack :%s", string(debug.Stack()))
		glg.Errorf("panic: %+v", i)
	}
	// HTTP Server
	http.ListenAndServe(":8080", router)
}

type RoundTripperFunc func(*http.Request) (*http.Response, error)

func (fn RoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func ForwardHandler(writer http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	u := &url.URL{
		Scheme: "https",
		Host:   "jarvis-alert.niulinkcloud.com",
	}
	request.URL.Path = "/alert/wechat/api?"
	// 添加验签
	request.ParseForm()
	form := request.Form
	signature, timestamp, nonce := generateSign()
	form.Add("signature", signature)
	form.Add("timestamp", timestamp)
	form.Add("nonce", nonce)
	form.Add("echostr", "test")

	proxy := httputil.NewSingleHostReverseProxy(u)

	proxy.Transport = RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		// request
		s := req.URL.String()
		unescape, err := url.PathUnescape(s)
		if err != nil {
			panic(err)
		}
		Url := fmt.Sprintf("%s%s", unescape, req.Form.Encode())
		glg.Infof("Request URL: %s", Url)
		newRequest, err := http.NewRequest(req.Method, Url, req.Body)
		if err != nil {
			glg.Errorf("Request Error: %+v", err)
		}
		cli := &http.Client{
			Timeout: 60 * time.Second,
		}
		res, err := cli.Do(newRequest)
		return res, nil
	})
	proxy.ServeHTTP(writer, request)
}

func InitLog() {
	infolog := glg.FileWriter("./tmp/info.log", 0666)

	errlog := glg.FileWriter("./tmp/error.log", 0666)
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
	tmpArr := []string{token, timestamp, nonce}
	sort.Strings(tmpArr)

	signature = fmt.Sprintf("%x", sha1.Sum([]byte(strings.Join(tmpArr, ""))))
	return
}
