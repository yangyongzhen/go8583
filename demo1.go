package main

import (
	"errors"
	"go8583/utils"
	"go8583/ys8583"
	"log"
)

var (
	YSServer string = "XXX.XX.XX.XX"
	YSPort   int    = 555511
)

type YsPay struct {
	pay     *ys8583.Ys8583
	QdState bool //签到状态
}

func (ys *YsPay) ConfigYS(termid string) error {
	//获取当前路径
	ys.pay = ys8583.NewYs8583()
	ys.QdState = false
	//根据传来的termid查找对应的秘钥参数
	//加载参数,终端号－银商商户号－银商终端号－主控秘钥－主密钥-tpdu
	ys.pay.Setup("XXX000000XXX", "111111111110XXX", "22222XXX", "XX12345678901234****************", "XX3456789012345649f43db05eab9dcd", "6000270000")

	return nil
}

/*
签到处理过程,必须先签到一次，签到后后续交易无需签到
*/
func (ys *YsPay) YsQdProc() error {

	log.Printf("Tls connect:server=%s,port=%d\n", YSServer, YSPort)
	conn, err := utils.TlsConnect(YSServer, YSPort)
	if err != nil {
		return err
	}
	authbuf, err := ys.pay.FrameAuth()
	_, err = utils.TlsTxData(conn, authbuf)
	if err != nil {
		return err
	}
	rxbuf := make([]byte, 1024)
	rxlen, err := utils.TlsRxData(conn, rxbuf)
	if err != nil {
		log.Printf("Authentation ERROR!%s\n", err)
		return err
	}
	if rxbuf[2] != 0x30 || rxbuf[3] != 0x30 {
		log.Printf("YS Authentation ERROR!\n")
		return errors.New("YS Authentation ERROR")
	}
	log.Printf("YS Authentation OK!\n")
	ys.pay.Frame8583QD()
	ys.pay.Ea.PrintFields(ys.pay.Ea.Field_S)

	_, err = utils.TlsTxData(conn, ys.pay.Ea.Txbuf)
	if err != nil {
		return err
	}
	rxlen, err = utils.TlsRxData(conn, rxbuf)
	if err == nil {
		log.Printf("recv ok!len=%d\n", rxlen)
		//log.Printf("rxbuf=%s\n", utils.BytesToHexString(rxbuf))
		if rxlen <= 0 {
			log.Printf("recv error!len=%d\n", rxlen)
			return errors.New("error: recv error,len is zero")
		}
		err = ys.pay.Ans8583QD(rxbuf, rxlen)
		if err == nil {
			log.Printf("签到成功")
			ys.QdState = true
		} else {
			log.Printf("签到失败")
			//log.Printf(err)
		}
	}
	return err

}

/*
银商二维码聚合支付交易，支持微信付款码，支付宝付款码，云闪付付款码
*/
func (ys *YsPay) YsQrcodeProc(qrcode string, money int, recSn int, dealtime string) error {
	log.Printf("Tls connect:server=%s,port=%d\n", YSServer, YSPort)
	conn, err := utils.TlsConnect(YSServer, YSPort)
	if err != nil {
		return err
	}
	authbuf, err := ys.pay.FrameAuth()
	_, err = utils.TlsTxData(conn, authbuf)
	if err != nil {
		return err
	}
	rxbuf := make([]byte, 1024)
	rxlen, err := utils.TlsRxData(conn, rxbuf)
	if err != nil {
		log.Printf("Authentation ERROR!%s\n", err)
		return err
	}
	if rxbuf[2] != 0x30 || rxbuf[3] != 0x30 {
		log.Printf("YS Authentation ERROR!\n")
		return errors.New("YS Authentation ERROR")
	}
	log.Printf("YS Authentation OK!\n")
	ys.pay.Frame8583Qrcode(qrcode, money, recSn, dealtime)
	ys.pay.Ea.PrintFields(ys.pay.Ea.Field_S)
	log.Printf("send:%s\n", utils.BytesToHexString(ys.pay.Ea.Txbuf))
	_, err = utils.TlsTxData(conn, ys.pay.Ea.Txbuf)
	if err != nil {
		return err
	}
	rxlen, err = utils.TlsRxData(conn, rxbuf)
	if err == nil {
		log.Printf("recv ok!len=%d\n", rxlen)
		//log.Printf("rxbuf=%s\n", utils.BytesToHexString(rxbuf))
		if rxlen <= 0 {
			log.Printf("recv error!len=%d\n", rxlen)
			return errors.New("error: recv error,len is zero")
		}
		err = ys.pay.Ans8583Qrcode(rxbuf, rxlen)
		if err == nil {
			log.Printf("交易成功")
		} else {
			log.Printf("交易失败")
			//log.Printf(err)
		}
	}
	return err
}

func main() {

	log.Println("test yinshang pay...")
	retcode := "0"
	remsg := ""
	ys := YsPay{}
	ys.ConfigYS("12345678") //只需第一次调用一次,加载配置参数
	if ys.QdState == false {
		err := ys.YsQdProc()
		if err != nil {
			log.Println("签到失败")
		}
	}
	err := ys.YsQrcodeProc("6221234567890111111", 1, 1, "20210309121230")
	if err != nil {
		retcode = "401"
		remsg = "UnionPay-YS QrcodeDeal error"
		log.Println("交易失败")
	}
	log.Println(retcode)
	log.Println(remsg)
}
