package main

import (
	"flag"
	"fmt"
	"github.com/larspensjo/config"
	"go8583/netutil"
	"go8583/up8583"
	"os"
)

var (
	conFile        = flag.String("configfile", "/config.ini", "config file")
	Server  string = "127.0.0.1"
	Port    int    = 5050

	up *up8583.Up8583
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
	fmt.Printf("Server:%s\n", Server)
	fmt.Printf("Port:%d\n", Port)

	up8583.ManNum, _ = cfg.String("UPCONFIG", "ManNum")
	up8583.PosNum, _ = cfg.String("UPCONFIG", "PosNum")
	up8583.MainKey, _ = cfg.String("UPCONFIG", "MainKey")
	up8583.TPDU, _ = cfg.String("UPCONFIG", "TPDU")

	up8583.RecSn, _ = cfg.Int("RECCONFIG", "RecSn") //记录流水

	up = up8583.NewUp8583()
}

/*
签到处理过程
*/
func QdProc() error {
	fmt.Printf("->connect:server=%s,port=%d\n", Server, Port)
	conn, err := netutil.Connect(Server, Port)
	if err == nil {
		fmt.Println("connect ok!")
	} else {
		fmt.Println("connect failed!")
		return err
	}
	defer netutil.DisConnect(conn)
	up.Frame8583QD()
	up.Ea.PrintFields(up.Ea.Field_S)
	_, err = netutil.TxData(conn, up.Ea.Txbuf)
	if err == nil {
		fmt.Println("send ok!")
	}
	rxbuf := make([]byte, 1024)
	rxlen := 0
	rxlen, err = netutil.RxData(conn, rxbuf)
	if err == nil {
		fmt.Printf("recv ok!len=%d\n", rxlen)
		err = up.Ans8583QD(rxbuf, rxlen)
		if err == nil {
			fmt.Println("签到成功")
		} else {
			fmt.Println("签到失败")
			fmt.Println(err)
		}
	}
	return err

}

func QrcodeProc() error {

	fmt.Printf("->connect:server=%s,port=%d\n", Server, Port)
	conn, err := netutil.Connect(Server, Port)
	if err == nil {
		fmt.Println("connect ok!")
	} else {
		fmt.Println("connect failed!")
		return err
	}
	defer netutil.DisConnect(conn)
	up.Frame8583Qrcode("6220485073630469936", 1)
	up.Ea.PrintFields(up.Ea.Field_S)
	_, err = netutil.TxData(conn, up.Ea.Txbuf)
	if err == nil {
		fmt.Println("send ok!")
	}
	rxbuf := make([]byte, 1024)
	rxlen := 0
	rxlen, err = netutil.RxData(conn, rxbuf)
	if err == nil {
		fmt.Printf("recv ok!len=%d\n", rxlen)
		up.Ea.Ans8583Fields(rxbuf, rxlen)
		up.Ea.PrintFields(up.Ea.Field_R)
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
