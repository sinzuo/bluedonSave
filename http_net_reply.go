package main

import (
	"fmt"

	"net"
	"os"

	"strconv"

	"log"

	"time"

	"encoding/json"

	"github.com/Shopify/sarama"
	"github.com/garyburd/redigo/redis"

	_ "github.com/bmizerany/pq"
)

type configuration struct {
	RedisAddr   string  `json:"REDIS_ADDR"`
	UdpAddr     string  `json:"UDP_SEND_ADDR"`
	KafkaAddr   string  `json:"KAFKA_SEND_ADDR"`
	VirtulValue float64 `json:"VIRTULVALUE"`
}

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
		VirusFileName     string `json:"VirusFileName"`
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

var MESSAGE_KEY = "netlog_http"
var REDIS_ADDR = "127.0.0.1:6379"
var UDP_SEND_ADDR = "10.130.10.13"
var KAFKA_SEND_ADDR = "192.168.10.23:9092"

var con net.Conn

func JiexiJson(data []byte) *MyJsonName {
	var feedsInfo MyJsonName
	//第二个参数必须是指针，否则无法接收解析后的数据
	if err := json.Unmarshal([]byte(data), &feedsInfo); err != nil {
		log.Printf("json.Unmarshal() failed, err=%v data=%s\n", err, data)
		return nil
	}
	return &feedsInfo

}

func UdpSend(out *MyJsonName) {
	var event VirEvent
	if con != nil {
		event.EventName = "病毒事件"
		event.EventData = out

		bsend, err := json.Marshal(event)
		if err != nil {

			return
		}
		log.Println("udp send ok")
		con.Write(bsend)
	}
}

func Custom() {
	c, err := redis.Dial("tcp", REDIS_ADDR)
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

				go sendToKafka(shuju)

				if len(shuju.Virus) > 0 {
					val, err := strconv.ParseFloat(shuju.Virus[0].Virusprobability, 64)
					if err != nil {
						continue
					}
					if val > virtulValue {
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

var virtulValue = 0.5

var index = 10000

func sendToKafka(shuju *MyJsonName) {
	if len(shuju.Atts) == 0 {
		return
	}
	var value string

	value = fmt.Sprintf("file~%d~%s~%s~%s~%s~%s", time.Now().UnixNano()/ 1e3, shuju.SrcIP, shuju.SrcPort, shuju.DstIP, shuju.DstPort, shuju.Atts[0].FileName)
	//	log.Println("value = ", value)

	//将字符串转换为字节数组
	msg.Value = sarama.ByteEncoder(value)
	//fmt.Println(value)
	//SendMessage：该方法是生产者生产给定的消息
	//生产成功的时候返回该消息的分区和所在的偏移量
	//生产失败的时候返回error
	_, _, err := producer.SendMessage(msg)

	if err != nil {
		log.Println("Send kafka message Fail", err)
	}
	//log.Printf("Partition = %d, offset=%d\n", partition, offset)

}

var msg *sarama.ProducerMessage

var producer sarama.SyncProducer

func createKafka() {

	var err error
	producer, err = sarama.NewSyncProducer([]string{KAFKA_SEND_ADDR}, config)
	if err != nil {
		fmt.Println("Create kafka produce connect error,Please edit kafka address in httpreplyconf.json")

		os.Exit(1)
	}
}

var config *sarama.Config

func initKafka() {
	if producer != nil {
		fmt.Println("producer is nil")
		producer = nil
	}

	config := sarama.NewConfig()
	// 等待服务器所有副本都保存成功后的响应
	config.Producer.RequiredAcks = sarama.WaitForAll
	// 随机的分区类型：返回一个分区器，该分区器每次选择一个随机分区
	config.Producer.Partitioner = sarama.NewRandomPartitioner
	// 是否等待成功和失败后的响应
	config.Producer.Return.Successes = true

	// 使用给定代理地址和配置创建一个同步生产者

	//	defer producer.Close()

	//构建发送的消息，
	msg = &sarama.ProducerMessage{
		Topic:     "sensitive-word-topic",      //包含了消息的主题
		Partition: int32(10),                   //
		Key:       sarama.StringEncoder("key"), //
	}

}

var PEIZHI = `{
"REDIS_ADDR":"127.0.0.1:6379",
"UDP_SEND_ADDR":"127.0.0.1",
"KAFKA_SEND_ADDR":"127.0.0.1:9092",
"VIRTULVALUE":0.5
}`

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
		virtulValue, erru = strconv.ParseFloat(os.Args[2], 64)
		if erru != nil {
			log.Println("virtulValue error")
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
		file, errc := os.Open("httpreplyconf.json")
		if errc != nil {
			fd, _ := os.OpenFile("httpreplyconf.json", os.O_RDWR|os.O_CREATE, os.ModePerm)
			fd.Write([]byte(PEIZHI))
			fd.Close()

			fmt.Println("Created httpreplyconf.json file,Please edit httpreplyconf.json!")

			return

		}

		decoder := json.NewDecoder(file)
		conf := configuration{}
		err := decoder.Decode(&conf)
		if err != nil {
			fmt.Println("httpreplyconf.json Error:", err)
		}

		REDIS_ADDR = conf.RedisAddr
		UDP_SEND_ADDR = conf.UdpAddr
		KAFKA_SEND_ADDR = conf.KafkaAddr
		virtulValue = conf.VirtulValue

		var erru error
		con, erru = net.Dial("udp", UDP_SEND_ADDR+":514")
		if erru != nil {
			log.Println("udp error")
			return
		}
	}

	initKafka()
	createKafka()

	for {

		Custom()
		log.Println("redis error")
		producer.Close()
		time.Sleep(time.Second * 60 * 2)

	}
}
