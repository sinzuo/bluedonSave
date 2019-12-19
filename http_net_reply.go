package main

import (
	"fmt"

	"database/sql"
	"net"
	"os"

	"strconv"

	"log"

	"time"

	"encoding/json"

	"github.com/garyburd/redigo/redis"

	_ "github.com/bmizerany/pq"
)

//poll是指针
var pool *redis.Pool

type MyJsonName struct {
	AppProto string `json:"AppProto"`
	Atts     []struct {
		FileID    string `json:"FileId"`
		FileName  string `json:"FileName"`
		FileSize  int    `json:"FileSize"`
		FileType  string `json:"FileType"`
		MD5       string `json:"MD5"`
		StorePath string `json:"StorePath"`
	} `json:"Atts"`
	Virus []struct {
		VirusAction       string `json:"VirusAction"`
		VirusDetectEngine string `json:"VirusDetectEngine"`
		VirusFileName     int    `json:"VirusFileName"`
		VirusFilePath     string `json:"VirusFilePath"`
		VirusLevel        string `json:"VirusLevel"`
		VirusName         string `json:"VirusName"`
		VirusType         string `json:"VirusType"`
		Virusprobability  string `json:"virusprobability"`
	} `json:"Virus"`
	Date      string `json:"Date"`
	DstIP     string `json:"DstIP"`
	DstMac    string `json:"DstMac"`
	DstPort   string `json:"DstPort"`
	From      string `json:"From"`
	SrcIP     string `json:"SrcIP"`
	SrcMac    string `json:"SrcMac"`
	SrcPort   string `json:"SrcPort"`
	TimeStamp int    `json:"TimeStamp"`
	To        string `json:"To"`
	Type      string `json:"Type"`
	URL       string `json:"Url"`
}

type VirEvent struct {
	EventName string      `json:"EventName"`
	EventData *MyJsonName `json:"EventDate"`
}

var REDIS_ADDR = "127.0.0.1"

//var REDIS_ADDR = "10.130.10.13"
var MESSAGE_KEY = "netlog_http"
var UDP_SEND_ADDR = "10.130.10.13"

var con net.Conn

func JiexiJson(data []byte) *MyJsonName {
	var feedsInfo MyJsonName
	//第二个参数必须是指针，否则无法接收解析后的数据
	if err := json.Unmarshal([]byte(data), &feedsInfo); err != nil {
		fmt.Printf("json.Unmarshal() failed, err=%v data=%s\n", err, data)
		return nil
	}
	return &feedsInfo

}

func UdpSend(out *MyJsonName) {
	var event VirEvent
	if con != nil {
		event.EventName = "病毒事件"
		event.EventData = out
		log.Println("ooooo")
		bsend, err := json.Marshal(event)
		if err != nil {
			log.Println("ooooo3333")
			return
		}
		log.Println("ooooo1")
		con.Write(bsend)
	}
}

func Custom() {
	c, err := redis.Dial("tcp", REDIS_ADDR+":6379")
	if err != nil {
		fmt.Println(err)
		return
	}

	defer c.Close()

	psc := redis.PubSubConn{c}
	psc.PSubscribe(MESSAGE_KEY)
	for {
		switch v := psc.Receive().(type) {
		case redis.Subscription:
			log.Printf("%s: %s %d\n", v.Channel, v.Kind, v.Count)
		case redis.Message: //单个订阅subscribe
			log.Printf("%s: message: %s\n", v.Channel, v.Data)
		case redis.PMessage: //模式订阅psubscribe
			log.Printf("PMessage: %s %s %s\n", v.Pattern, v.Channel, v.Data)
			shuju := JiexiJson(v.Data)
			if shuju != nil {

				insertUser(db, shuju)

				if len(shuju.Virus) > 0 {
					val, err := strconv.ParseFloat(shuju.Virus[0].Virusprobability, 64)
					if err != nil {
						return
					}
					if val > 0.5 {
						go UdpSend(shuju)
					}
				}

			}
		case error:
			return

		}

	}
}

func checkErr(err error) {
	if err != nil {
		log.Println(err)
	}
}

/*
	var str = `INSERT INTO t_siem_file_log(recordid ,general_id , filename , storepath , filesize , file_id , srcip , dstip , \
 			proto , storagetime , filetype , url , from , to , MD5) values('recordid' ,'general_id' , 'filename' , \
			'storepath' , 66 , 'file_id' , 'srcip' , 'dstip' , 'proto' , now() , 'filetype' , 'url' , 'from' , 'to' ,'MD5');`

*/

var inStr = `INSERT INTO t_siem_file_log(recordid ,general_id , filename , storepath , filesize , file_id , srcip , dstip , proto , storagetime , filetype , url , "from" , "to" , "MD5") values($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),$10,$11,$12,$13,$14);`

var inT1 = `insert into t_siem_file_log(recordid,general_id,filename) values($1,$2,$3)`

func insertUser(db *sql.DB, shuju *MyJsonName) {
	if len(shuju.Atts) == 0 {
		return
	}
	stmt, err := db.Prepare(inStr)
	if err != nil {
		log.Println(err)
	}

	log.Println("\n\n\n")
	log.Println("shujuku ok", shuju.AppProto, shuju.Date, shuju.DstIP, shuju.DstMac, shuju.DstPort, shuju.From, shuju.SrcIP,
		shuju.SrcMac, shuju.SrcPort, shuju.TimeStamp, shuju.To, shuju.Type, shuju.URL)
	if len(shuju.Atts) > 0 {
		log.Println(shuju.Atts[0].FileID, shuju.Atts[0].FileName, shuju.Atts[0].FileSize, shuju.Atts[0].FileType,
			shuju.Atts[0].MD5, shuju.Atts[0].StorePath)
	}

	index++
	_, err = stmt.Exec(index, index+60000, shuju.Atts[0].FileName, shuju.Atts[0].StorePath, shuju.Atts[0].FileSize, shuju.Atts[0].FileID,
		shuju.SrcIP, shuju.DstIP, shuju.AppProto, shuju.Atts[0].FileType, shuju.URL, shuju.From, shuju.To, shuju.Atts[0].MD5)
	//	_, err = stmt.Exec("recordid", "general_id", "filename")
	//	_, err = stmt.Exec(, "general_id", "filename")
	if err != nil {
		log.Println(err)
	} else {
		log.Println("insert into user_tbl success")
	}
}

var db *sql.DB

var index = 10000

func main() {

	if len(os.Args) > 2 {
		log.SetOutput(os.Stdout)
		UDP_SEND_ADDR = os.Args[1]
		var erru error
		con, erru = net.Dial("udp", UDP_SEND_ADDR+":514")
		if erru != nil {
			log.Println("udp error")
			return
		}
	} else if len(os.Args) == 2 {
		UDP_SEND_ADDR = os.Args[1]
		var erru error
		con, erru = net.Dial("udp", UDP_SEND_ADDR+":514")
		if erru != nil {
			log.Println("udp error")
			return
		}

	} else {
		con = nil
	}

	//
	var err error

	for {

		db, err = sql.Open("postgres", "host="+REDIS_ADDR+" user=postgres password=12345)(*^%RFVwsx dbname=NXSOC5 sslmode=disable")

		if err != nil {
			log.Println("postgres error")

		}
		Custom()
		log.Println("redis error")
		db.Close()
		time.Sleep(time.Second * 60 * 2)

	}
}
