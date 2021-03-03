package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/larspensjo/config"
	"go8583/up8583"
	"go8583/utils"
	"log"
	"os"
)

var (
	conFile        = flag.String("configfile", "/config.ini", "config file")
	Server  string = "127.0.0.1"
	Port    int    = 5050

	up  *up8583.Up8583
	Url string = ""
)

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
	}
}

func configUP() {

	//获取当前路径
	file, _ := os.Getwd()
	cfg, err := config.ReadDefault(file + *conFile)
	checkErr(err)

	//获取配置文件中的配置项
	Server, err = cfg.String("SERVERCONFIG", "Server")
	Port, err = cfg.Int("SERVERCONFIG", "Port")
	Url, _ = cfg.String("SERVERCONFIG", "Url")
	log.Printf("Server:%s\n", Server)
	log.Printf("Port:%d\n", Port)
	log.Printf("Url:%s\n", Url)

	manNum, _ := cfg.String("UPCONFIG", "ManNum")
	posNum, _ := cfg.String("UPCONFIG", "PosNum")
	mainKey, _ := cfg.String("UPCONFIG", "MainKey")
	tpdu, _ := cfg.String("UPCONFIG", "TPDU")

	up = up8583.NewUp8583()
	up.Setup(manNum, posNum, mainKey, tpdu)
}

/*
签到处理过程
*/
func QdProc() error {
	up.Frame8583QD()
	up.Ea.PrintFields(up.Ea.Field_S)

	log.Printf("connect:server=%s\n", Url)
	if Url == "" {
		return errors.New("error: Url must not null")
	}
	rxbuf, err := utils.UpHttpsPost(Url, up.Ea.Txbuf)
	rxlen := len(rxbuf)
	if err == nil {
		log.Printf("recv ok!len=%d\n", rxlen)
		if rxlen <= 0 {
			log.Printf("recv error!len=%d\n", rxlen)
			return errors.New("error: recv error,len is zero")
		}
		err = up.Ans8583QD(rxbuf, rxlen)
		if err == nil {
			log.Println("签到成功")
		} else {
			log.Println("签到失败")
			log.Println(err)
		}
	}
	return err

}

func QrcodeProc() error {

	if Url == "" {
		return errors.New("error: Url must not null")
	}
	//up8583.RecSn++ //交易流水加加
	qrcode := "6211111111111111111"
	money := 1 //1分
	recSn := 1
	up.Frame8583Qrcode(qrcode, money, recSn)
	up.Ea.PrintFields(up.Ea.Field_S)
	log.Printf("connect:server=%s\n", Url)
	rxbuf, err := utils.UpHttpsPost(Url, up.Ea.Txbuf)
	rxlen := len(rxbuf)
	if err == nil {
		log.Printf("recv ok!len=%d\n", rxlen)
		err = up.Ans8583Qrcode(rxbuf, rxlen)
		if err == nil {
			log.Println("交易成功")
		} else {
			log.Println("交易失败")
		}
	}
	return err
}

func main() {

	fmt.Println("test...")

	configUP()

	//up.Frame8583QD()

	//recvstr := "007960000001386131003111080810003800010AC0001450021122130107200800085500323231333031343931333239303039393939393930363030313433303137303131393939390011000005190030004046F161A743497B32EAC760DF5EA57DF5900ECCE3977731A7EA402DDF0000000000000000CFF1592A"

	//recv := byteutil.HexStringToBytes(recvstr)
	//ret := up.Ea.Ans8583Fields(recv, len(recv))
	//if ret == 0 {
	// 	fmt.Println("解析成功")
	// 	up.Ea.PrintFields(up.Ea.Field_R)
	// } else {
	// 	fmt.Println("解析失败")
	// }

	err := QdProc()
	checkErr(err)
	if err == nil {
		err = QrcodeProc()
		checkErr(err)
	}

}
