/**
银商8583, tls socket交易方式
银商8583聚合支付交易,微信付款码、支付宝付款码和云闪付二维码
包含签到、云闪付二维码交易、银联卡小额免密交易
Author:yangyongzhen
QQ:534117529
*/
package ys8583

import (
	"errors"
	"fmt"
	"go8583/easy8583"
	"go8583/utils"
	"strconv"
	"strings"
)

type Ys8583 struct {
	Ea         *easy8583.Easy8583
	ManNum     string //商户号
	PosNum     string //终端号
	TPDU       string
	CommSn     int    //通讯流水
	RecSn      int    //售卡方系统跟踪号
	PiciNum    []byte //批次号
	LicenceNum []byte

	MID     string //型号
	SN      string //设备sn号
	MainKey string //主密钥
	TmkKey  string //主控秘钥
	MacKey  string //MACkey

	UpBinNum  string //银行卡卡号
	CardSnNum string //持卡序号
	CardDate  string //卡有效期
	Fd35Data  string //二磁道数据
}

// func memcpy(dst, src []byte, size int) {
// 	for i := 0; i < size; i++ {
// 		dst[i] = src[i]
// 	}
// 	return
// }

func memcpy(dst, src []byte, size int) {
	copy(dst, src[0:size])
	return
}

func equals(src1 []byte, src2 []byte) bool {

	if src1 == nil || src2 == nil {
		return false
	}
	le1 := len(src1)
	le2 := len(src2)
	if le1 != le2 {
		return false
	}
	for i := 0; i < le1; i++ {
		if src1[i] != src2[i] {
			return false
		}
	}
	return true
}

/**
银商认证报文头
*/

type header struct {
	lenth   []byte
	mactype []byte
	hwno    []byte
	seccode []byte
	randnum []byte
	check   byte
}

func checkXor(src []byte, size int) byte {
	check := src[0]
	for i := 1; i < size; i++ {
		check ^= src[i]
	}
	return check
}

/**
FrameAuth
银商认证报文组包
*/

func (up *Ys8583) FrameAuth() ([]byte, error) {

	hd := header{}
	hd.lenth = make([]byte, 2)
	hd.mactype = make([]byte, 20)
	hd.hwno = make([]byte, 38)
	hd.seccode = make([]byte, 24)
	hd.randnum = make([]byte, 16)

	hd.lenth[0] = 0x00
	hd.lenth[1] = 0x63

	mid := fmt.Sprintf("%-20s", up.MID)
	memcpy(hd.mactype, []byte(mid), 20)

	sn := fmt.Sprintf("%-38s", up.SN)
	memcpy(hd.hwno, []byte(sn), 38)
	fmt.Printf("auth sn=%s\n", sn)

	code := fmt.Sprintf("%-24s", up.MID)
	memcpy(hd.seccode, []byte(code), 24)

	tmkey := utils.HexStringToBytes(up.TmkKey)
	authkey, err := utils.Des3Encrypt(hd.randnum, tmkey)
	if err != nil {
		return nil, err
	}
	seccode, err := utils.Des3Encrypt(hd.seccode, authkey)
	if err != nil {
		return nil, err
	}
	memcpy(hd.seccode, seccode, 24)
	hd.check = checkXor(hd.randnum, 16)

	buf := make([]byte, 101)
	memcpy(buf[0:], hd.lenth, 2)
	memcpy(buf[2:], hd.mactype, 20)
	memcpy(buf[22:], hd.hwno, 38)
	memcpy(buf[60:], hd.seccode, 24)
	memcpy(buf[84:], hd.randnum, 16)
	buf[100] = hd.check
	//fmt.Printf("Authentation:%#v\n", up.Ea.Txbuf)
	return buf, nil
}

/*
8583签到组包
*/
func (up *Ys8583) Frame8583QD() {

	s := up.Ea
	field := up.Ea.Field_S

	s.Init8583Fields(field)

	//消息类型
	s.Msgtype[0] = 0x08
	s.Msgtype[1] = 0x00

	//11域，受卡方系统跟踪号BCD 通讯流水
	field[10].Ihave = true
	field[10].Len = 3
	sn := fmt.Sprintf("%06d", up.CommSn)

	field[10].Data = utils.HexStringToBytes(sn)

	//41域，终端号
	field[40].Ihave = true
	field[40].Len = 8
	field[40].Data = []byte(up.PosNum)
	//42域，商户号
	field[41].Ihave = true
	field[41].Len = 15
	field[41].Data = []byte(up.ManNum)
	//60域
	field[59].Ihave = true
	field[59].Len = 0x11
	field[59].Data = make([]byte, 6)
	field[59].Data[0] = 0x00
	memcpy(field[59].Data[1:], up.PiciNum, 3)
	field[59].Data[4] = 0x00
	field[59].Data[5] = 0x30
	//62域
	field[61].Ihave = true
	field[61].Len = 0x25
	field[61].Data = make([]byte, 25)
	str := "Sequence No12"
	memcpy(field[61].Data, []byte(str), 13)
	memcpy(field[61].Data[13:], up.LicenceNum, 4)
	memcpy(field[61].Data[17:], []byte(up.PosNum), 8)

	//63域
	field[62].Ihave = true
	field[62].Len = 0x03
	field[62].Data = make([]byte, 3)
	field[62].Data[0] = 0x30
	field[62].Data[1] = 0x30
	field[62].Data[2] = 0x31
	/*报文组帧，自动组织这些域到Pack的TxBuffer中*/
	s.Pack8583Fields()

	up.CommSn++ //通讯流水每次加一

	//s.PrintFields(up.Ea.Field_S)

}

/**
8583签到应答报文解析
*/
func (up *Ys8583) Ans8583QD(rxbuf []byte, rxlen int) error {

	r := up.Ea
	fields := up.Ea.Field_S
	fieldr := up.Ea.Field_R

	ret := r.Ans8583Fields(rxbuf, rxlen)
	if ret == 0 {
		fmt.Println("解析成功")
		r.PrintFields(fieldr)
	} else {
		fmt.Println("解析失败")
		return errors.New("error,failed to ans..")
	}
	//消息类型判断
	if (r.Msgtype[0] != 0x08) || (r.Msgtype[1] != 0x10) {
		//Log.d(TAG,"消息类型错！");
		return errors.New("error,wrong Msgtype ")
	}
	//应答码判断
	if (fieldr[38].Data[0] != 0x30) || (fieldr[38].Data[1] != 0x30) {
		//Log.d(TAG,"应答码不正确！");
		return errors.New("error,wrong resp code:" + fmt.Sprintf("%02x%02x", fieldr[38].Data[0], fieldr[38].Data[1]))
	}
	//跟踪号比较
	//memcmp
	if !equals(fields[10].Data, fieldr[10].Data) {
		return errors.New("error,wrong comm no ")
	}

	//终端号比较
	if !equals(fields[40].Data, fieldr[40].Data) {
		return errors.New("error,posnum not equal ")
	}
	//商户号比较
	if !equals(fields[41].Data, fieldr[41].Data) {
		return errors.New("error,mannum not equal ")
	}
	//3DES解密PIN KEY
	data := make([]byte, 16)
	memcpy(data, fieldr[61].Data, 16)
	pinkey, err := utils.Des3Decrypt(data, utils.HexStringToBytes(up.MainKey))
	if err != nil {
		return errors.New("1" + err.Error())
	}
	//解密后的结果对8Byte全0做3DES加密运算
	tmp := make([]byte, 8)
	out, err := utils.Des3Encrypt(tmp, pinkey)
	if err != nil {
		return errors.New("2" + err.Error())
	}
	check := make([]byte, 4)
	pincheck := make([]byte, 4)
	memcpy(check, out, 4)
	memcpy(pincheck, fieldr[61].Data[16:], 4)
	if !equals(check, pincheck) {
		return errors.New("error,Er PIK")
	}
	//3DES解密MAC KEY
	memcpy(data, fieldr[61].Data[20:], 8)
	mackey, err := utils.Des3Decrypt(data, utils.HexStringToBytes(up.MainKey))
	if err != nil {
		return errors.New("3" + err.Error())
	}
	//fmt.Printf("mackey:%s\n", utils.BytesToHexString(mackey))
	out, err = utils.DesEncrypt(tmp, mackey[0:8])
	if err != nil {
		return errors.New("4" + err.Error())
	}
	maccheck := make([]byte, 4)
	memcpy(check, out, 4)
	memcpy(maccheck, fieldr[61].Data[28:], 4)
	if !equals(check, maccheck) {
		return errors.New("error,Er MAC")
	}
	memcpy(up.PiciNum, fieldr[59].Data[1:], 3)
	up.MacKey = utils.BytesToHexString(mackey[0:8])
	fmt.Printf("mackey:%s\n", up.MacKey)
	up.Ea.SetMacKey(up.MacKey)
	return nil
}

/*
银联8583 二维码交易组包
dealtime:格式为YYYYMMDDhhmmss
*/
func (up *Ys8583) Frame8583Qrcode(qrcode string, money int, recSn int, dealtime string) {

	s := up.Ea
	field := up.Ea.Field_S
	var isZfbWx bool

	s.Init8583Fields(field)

	if len(qrcode) == 18 {
		//支付宝或微信付款码长度为18
		isZfbWx = true
	}

	//消息类型
	s.Msgtype[0] = 0x02
	s.Msgtype[1] = 0x00

	//3域 交易处理码
	field[2].Ihave = true
	field[2].Len = 3
	field[2].Data = []byte{0x19, 0x00, 0x00}

	//4域 交易金额
	field[3].Ihave = true
	field[3].Len = 6
	field[3].Data = utils.HexStringToBytes(fmt.Sprintf("%012d", money))
	//11域，受卡方系统跟踪号BCD 通讯流水
	field[10].Ihave = true
	field[10].Len = 3
	sn := fmt.Sprintf("%06d", recSn)

	field[10].Data = utils.HexStringToBytes(sn)
	//22域
	field[21].Ihave = true
	field[21].Len = 2
	if isZfbWx {
		field[21].Data = []byte{0x92, 0x00}
	} else {
		field[21].Data = []byte{0x07, 0x20}
	}

	//25域
	field[24].Ihave = true
	field[24].Len = 1
	field[24].Data = []byte{0x91}

	//41域，终端号
	field[40].Ihave = true
	field[40].Len = 8
	field[40].Data = []byte(up.PosNum)
	//42域，商户号
	field[41].Ihave = true
	field[41].Len = 15
	field[41].Data = []byte(up.ManNum)

	//48域 行业特定信息
	field[47].Ihave = true
	field[47].Len = 0x66
	field[47].Data = make([]byte, 66)
	memcpy(field[47].Data[0:], []byte("PA570900000001"), 14)
	memcpy(field[47].Data[14:], []byte("\x1F\x51\x0224"), 5)         //1F51交易类型24,一次性消费
	memcpy(field[47].Data[19:], []byte("\x1F\x52\x0202"), 5)         //1F51接入渠道,02,POS通
	memcpy(field[47].Data[24:], []byte("\xFF\x57\x011"), 4)          //FF57进站站点
	memcpy(field[47].Data[28:], []byte("\xFF\x58\x0E"+dealtime), 17) //FF58进站时间
	memcpy(field[47].Data[45:], []byte("\xFF\x61\x0201"), 5)         //FF61公司
	memcpy(field[47].Data[50:], []byte("\xFF\x62\x0201"), 5)         //FF62线路
	memcpy(field[47].Data[55:], []byte("\xFF\x63\x0201"), 5)         //FF63车牌
	memcpy(field[47].Data[60:], []byte("\xFF\x64\x0201"), 5)         //FF64司机ID
	field[47].Data[65] = '#'                                         //结束符
	//49域 交易货币代码
	field[48].Ihave = true
	field[48].Len = 3
	field[48].Data = []byte{0x31, 0x35, 0x36}
	//57域 POS相关信息
	field[56].Ihave = true
	field[56].Len = 3

	if isZfbWx {
		field[56].Len = 0x0171
		field[56].Data = make([]byte, 171)
	} else {
		field[56].Len = 0x0172
		field[56].Data = make([]byte, 172)
	}
	memcpy(field[56].Data[0:], []byte("PB51A200000002"), 14)
	uno := fmt.Sprintf("%-50s", "")
	memcpy(field[56].Data[14:], []byte(uno), 50)     //系统用户号
	memcpy(field[56].Data[64:], []byte("000000"), 6) //交易月份
	if isZfbWx {
		memcpy(field[56].Data[70:], []byte("097"), 3) //附加子域长度
	} else {
		memcpy(field[56].Data[70:], []byte("098"), 3) //附加子域长度
	}
	memcpy(field[56].Data[73:], []byte("\x1F\x51\x03ODA"), 6)                             //1F51接入渠道ODA
	memcpy(field[56].Data[79:], []byte("\xFF\x57\x10\x00"+up.ManNum), 19)                 //FF57 “0”+15位商户号
	memcpy(field[56].Data[98:], []byte("\xFF\x58\x08"+up.PosNum), 11)                     //FF58 传统POS：送8位终端号
	memcpy(field[56].Data[109:], []byte("\xFF\x61\x01\x03"), 4)                           //FF61 支付方式 03扫码
	memcpy(field[56].Data[113:], []byte("\xFF\x42\x04\x46\x46\x46\x46"), 7)               //FF42
	memcpy(field[56].Data[120:], []byte("\xBF\x12\x1A"+"11111111111111111111111111"), 29) //BF12 担保号
	if isZfbWx {
		memcpy(field[56].Data[149:], []byte("\xFF\x55\x12"+qrcode), 21) //FF55 码数据
		field[56].Data[170] = '#'                                       //结束符
	} else {
		memcpy(field[56].Data[149:], []byte("\xFF\x55\x13"+qrcode), 22) //FF55 码数据
		field[56].Data[171] = '#'                                       //结束符
	}

	//60域
	field[59].Ihave = true
	field[59].Len = 0x14
	field[59].Data = make([]byte, 7)
	field[59].Data[0] = 0x22
	memcpy(field[59].Data[1:], up.PiciNum, 3)
	field[59].Data[4] = 0x00
	field[59].Data[5] = 0x06
	field[59].Data[6] = 0x00

	//MAC，64域
	field[63].Ihave = true
	field[63].Len = 0x08
	field[63].Data = make([]byte, 8)
	//这个域要求填MAC，只需按这样填，MAC的计算在pack8583Fields自动完成了
	/*报文组帧，自动组织这些域到Pack的TxBuffer中*/
	s.Pack8583Fields()

	//CommSn++ //通讯流水每次加一

	//s.PrintFields(up.Ea.Field_S)

}

/**
二维码交易应答报文解析
*/
func (up *Ys8583) Ans8583Qrcode(rxbuf []byte, rxlen int) error {
	r := up.Ea
	fields := up.Ea.Field_S
	fieldr := up.Ea.Field_R

	ret := r.Ans8583Fields(rxbuf, rxlen)
	if ret == 0 {
		fmt.Println("解析成功")
		r.PrintFields(fieldr)
	} else {
		fmt.Println("解析失败")
		return errors.New("error,failed to ans..")
	}
	//消息类型判断
	if (r.Msgtype[0] != 0x02) || (r.Msgtype[1] != 0x10) {
		//Log.d(TAG,"消息类型错！");
		return errors.New("error,wrong Msgtype ")
	}
	//应答码判断
	if (fieldr[38].Data[0] != 0x30) || (fieldr[38].Data[1] != 0x30) {
		//Log.d(TAG,"应答码不正确！");
		return errors.New("error,wrong resp code:" + fmt.Sprintf("%02x%02x", fieldr[38].Data[0], fieldr[38].Data[1]))
	}
	//跟踪号比较
	//memcmp
	if !equals(fields[10].Data, fieldr[10].Data) {
		return errors.New("error,wrong comm no ")
	}

	//终端号比较
	if !equals(fields[40].Data, fieldr[40].Data) {
		return errors.New("error,posnum not equal ")
	}
	//商户号比较
	if !equals(fields[41].Data, fieldr[41].Data) {
		return errors.New("error,mannum not equal ")
	}
	return nil
}

func NewYs8583() *Ys8583 {

	var up = new(Ys8583)
	up.Ea = easy8583.New8583()
	up.TPDU = "6000000001"
	up.ManNum = "000000000000000"
	up.PosNum = "00000000"
	up.MainKey = "00000000000000000000000000000000"
	up.TmkKey = "00000000000000000000000000000000"
	up.MID = "B503"
	up.SN = "000000000000"
	up.CommSn = 1
	up.RecSn = 1 //终端交易流水，连续，且不能重复
	up.PiciNum = make([]byte, 3)
	up.LicenceNum = []byte{0x33, 0x30, 0x36, 0x30}
	up.MacKey = "0000000000000000"
	up.Ea.Tpdu = utils.HexStringToBytes(up.TPDU)

	up.Ea.YsEnable = 1 //启用银商
	return up

}

/**
初始化，交易参数配置
sn:设备sn号
manNum:商户号
posNum:终端号
tmkkey:主控秘钥
mainKey:主密钥
*/
func (up *Ys8583) Setup(sn, manNum, posNum, tmkkey, mainKey, tpdu string) {
	up.SN = sn
	up.TPDU = tpdu
	up.ManNum = manNum
	up.PosNum = posNum
	up.TmkKey = tmkkey
	up.MainKey = mainKey
	up.Ea.Tpdu = utils.HexStringToBytes(up.TPDU)
}

/*
*银联双免组包
*输入参数：交易金额，日期时间 卡上GPO返回的数据
 */
func getfield55(in []byte, inlen int) []byte {
	return nil

}

func (up *Ys8583) Frame8583Quics(money int, dealtime string, field55 []byte) {
	s := up.Ea
	field := up.Ea.Field_S

	s.Init8583Fields(field)

	//消息类型
	s.Msgtype[0] = 0x02
	s.Msgtype[1] = 0x00
	//2域 卡号
	field[1].Ihave = true
	tmp := fmt.Sprintf("%02d", len(up.UpBinNum))
	t, _ := strconv.ParseInt(tmp, 16, 16)
	if len(up.UpBinNum)%2 != 0 {
		up.UpBinNum += "0"
	}
	field[1].Len = int(t)
	field[1].Data = utils.HexStringToBytes(up.UpBinNum)
	//3域 交易处理码
	field[2].Ihave = true
	field[2].Len = 3
	field[2].Data = make([]byte, 3)
	//4域 交易金额
	field[3].Ihave = true
	field[3].Len = 6
	field[3].Data = utils.HexStringToBytes(fmt.Sprintf("%012d", money))
	//11域，受卡方系统跟踪号BCD 通讯流水
	field[10].Ihave = true
	field[10].Len = 3
	sn := fmt.Sprintf("%06d", up.RecSn)

	field[10].Data = utils.HexStringToBytes(sn)

	//14域 卡有效期，能获取到时存在
	if len(up.CardDate) > 0 {
		field[13].Ihave = true
		field[13].Len = 2
		field[13].Data = utils.HexStringToBytes(up.CardDate)
	}

	//22域
	field[21].Ihave = true
	field[21].Len = 2
	field[21].Data = []byte{0x07, 0x20}
	//23域，卡序列号 能获取时存在
	if len(up.CardSnNum) > 0 {

		if strings.EqualFold(up.CardSnNum, "01") {
			field[22].Ihave = true
			field[22].Len = 2
			field[22].Data = make([]byte, 2)
			field[22].Data[1] = 0x01
		} else {
			field[22].Ihave = true
			field[22].Len = 2
			field[22].Data = make([]byte, 2)
			field[22].Data[1] = 0x00
		}

	}
	//25域
	field[24].Ihave = true
	field[24].Len = 1
	field[24].Data = make([]byte, 1)

	//35域 二磁道数据
	tmplen := len(up.Fd35Data)
	if tmplen > 0 {
		field[34].Ihave = true
		if strings.EqualFold(up.Fd35Data[tmplen-1:], "f") {
			st := fmt.Sprintf("%02d", tmplen)
			out, _ := strconv.ParseInt(st, 16, 16)
			tmplen = int(out)
			field[34].Len = tmplen - 1
		} else {
			st := fmt.Sprintf("%02d", tmplen)
			out, _ := strconv.ParseInt(st, 16, 16)
			tmplen = int(out)
			field[34].Len = tmplen
		}
		field[34].Data = utils.HexStringToBytes(up.Fd35Data)
	}
	//41域，终端号
	field[40].Ihave = true
	field[40].Len = 8
	field[40].Data = []byte(up.PosNum)
	//42域，商户号
	field[41].Ihave = true
	field[41].Len = 15
	field[41].Data = []byte(up.ManNum)

	//49域 交易货币代码
	field[48].Ihave = true
	field[48].Len = 3
	field[48].Data = []byte{0x31, 0x35, 0x36}

	//55域 IC卡数据域
	field[54].Ihave = true
	tmp = fmt.Sprintf("%04d", len(field55))
	b := utils.HexStringToBytes(tmp)
	field[54].Len = int(b[0])<<8 | int(b[1])
	field[54].Data = field55
	//60域
	field[59].Ihave = true
	field[59].Len = 0x13
	field[59].Data = make([]byte, 7)
	field[59].Data[0] = 0x22
	memcpy(field[59].Data[1:], up.PiciNum, 3)
	field[59].Data[4] = 0x00
	field[59].Data[5] = 0x06
	field[59].Data[6] = 0x00

	//MAC，64域
	field[63].Ihave = true
	field[63].Len = 0x08
	field[63].Data = make([]byte, 8)
	//这个域要求填MAC，只需按这样填，MAC的计算在pack8583Fields自动完成了
	/*报文组帧，自动组织这些域到Pack的TxBuffer中*/
	//s.PrintFields(field)

	s.Pack8583Fields()
}

func (up *Ys8583) Ans8583Quics(rxbuf []byte, rxlen int) error {

	r := up.Ea
	fields := up.Ea.Field_S
	fieldr := up.Ea.Field_R

	ret := r.Ans8583Fields(rxbuf, rxlen)
	if ret == 0 {
		fmt.Println("解析成功")
		r.PrintFields(fieldr)
	} else {
		fmt.Println("解析失败")
		r.PrintFields(fieldr)
		return errors.New("error,failed to ans..")
	}
	//消息类型判断
	if (r.Msgtype[0] != 0x02) || (r.Msgtype[1] != 0x10) {
		//Log.d(TAG,"消息类型错！");
		return errors.New("error,wrong Msgtype ")
	}
	//应答码判断
	if (fieldr[38].Data[0] != 0x30) || (fieldr[38].Data[1] != 0x30) {
		//Log.d(TAG,"应答码不正确！");
		return errors.New("error,wrong resp code:" + fmt.Sprintf("%02x%02x", fieldr[38].Data[0], fieldr[38].Data[1]))
	}
	//跟踪号比较
	//memcmp
	if !equals(fields[10].Data, fieldr[10].Data) {
		return errors.New("error,wrong comm no ")
	}

	//终端号比较
	if !equals(fields[40].Data, fieldr[40].Data) {
		return errors.New("error,posnum not equal ")
	}
	//商户号比较
	if !equals(fields[41].Data, fieldr[41].Data) {
		return errors.New("error,mannum not equal ")
	}
	//MAC验证
	mac, err := easy8583.UpGetMac(rxbuf[13:], rxlen-13-8, up.Ea.MacKey)
	if err != nil {
		fmt.Println(err)
		panic("calc mac error!")
	}
	if !equals(fieldr[63].Data, mac) {
		return errors.New("error,mac check err")
	}

	return nil
}

/*
func YsQdProc() error {
	log.Debugf("YS tls connect:server=%s,port=%d\n", YSServer, YSPort)
	conn, err := utils.TlsConnect(YSServer, YSPort)
	if err != nil {
		return err
	}
	authbuf, err := ys.FrameAuth()
	_, err = utils.TlsTxData(conn, authbuf)
	if err != nil {
		return err
	}
	rxbuf := make([]byte, 1024)
	rxlen, err := utils.TlsRxData(conn, rxbuf)
	if err != nil {
		log.Debug("Authentation ERROR!%s\n", err)
		return err
	}
	if rxbuf[2] != 0x30 || rxbuf[3] != 0x30 {
		log.Debug("YS Authentation ERROR!\n")
		return errors.New("YS Authentation ERROR")
	}
	log.Debug("YS Authentation OK!\n")
	ys.Frame8583QD()
	ys.Ea.PrintFields(ys.Ea.Field_S)

	_, err = utils.TlsTxData(conn, ys.Ea.Txbuf)
	if err != nil {
		return err
	}
	rxlen, err = utils.TlsRxData(conn, rxbuf)
	if err == nil {
		log.Debugf("recv ok!len=%d\n", rxlen)
		//log.Debugf("rxbuf=%s\n", utils.BytesToHexString(rxbuf))
		if rxlen <= 0 {
			log.Debug("recv error!len=%d\n", rxlen)
			return errors.New("error: recv error,len is zero")
		}
		err = ys.Ans8583QD(rxbuf, rxlen)
		if err == nil {
			log.Debug("签到成功")
		} else {
			log.Debug("签到失败")
			log.Debug(err)
		}
	}
	return err
}
*/
func main() {

	fmt.Println("test...")
	ys := NewYs8583()
	ys.Setup("xxxxxxxxxxxx", "888888888888888", "12345678", "1234567890b8adbcb94626247dd9a31", "1234567890123456789041575b5b5b0ec", "6000270000")
	//up.Frame8583QD()

	//recvstr := "007960000001386131003111080810003800010AC0001450021122130107200800085500323231333031343931333239303039393939393930363030313433303137303131393939390011000005190030004046F161A743497B32EAC760DF5EA57DF5900ECCE3977731A7EA402DDF0000000000000000CFF1592A"

	//recv := utils.HexStringToBytes(recvstr)
	//ret := up.Ea.Ans8583Fields(recv, len(recv))
	//if ret == 0 {
	// 	fmt.Println("解析成功")
	// 	up.Ea.PrintFields(up.Ea.Field_R)
	// } else {
	// 	fmt.Println("解析失败")
	// }

	ys.Frame8583QD()
	ys.Ea.PrintFields(ys.Ea.Field_S)
	//fmt.Println(utils.BytesToHexString(up.Ea.Txbuf))
	ys.Frame8583Qrcode("6220485073630469936", 1, 1, "20210303153630")
	ys.Ea.PrintFields(ys.Ea.Field_S)

	//YsQdProc()

}
