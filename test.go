package main

import (
	"fmt"
	"go8583/byteutil"
	_ "go8583/desutil"
	"go8583/easy8583"
)

var (
	ManNum  string = "898430441110012"
	PosNum  string = "34386013"
	MainKey string = "C28A798661AE49FD151C02385E97E938"
	TPDU    string = "6005010000"

	CommSn     int    = 1
	PiciNum    []byte = make([]byte, 3)
	LicenceNum        = []byte{0x33, 0x30, 0x36, 0x30}
)

type Up8583 struct {
	Ea *easy8583.Easy8583
}

func memcpy(dst, src []byte, size int) {
	for i := 0; i < size; i++ {
		dst[i] = src[i]
	}
	return
}

/*
银联8583签到组包
*/
func (up *Up8583) Frame8583QD() {

	s := up.Ea
	field := up.Ea.Field_S

	s.Init8583Fields(field)

	//消息类型
	s.Msgtype[0] = 0x08
	s.Msgtype[1] = 0x00

	//11域，受卡方系统跟踪号BCD 通讯流水
	field[10].Ihave = true
	field[10].Len = 3
	sn := fmt.Sprintf("%06d", CommSn)

	field[10].Data = byteutil.HexStringToBytes(sn)

	//41域，终端号
	field[40].Ihave = true
	field[40].Len = 8
	field[40].Data = []byte(PosNum)
	//42域，商户号
	field[41].Ihave = true
	field[41].Len = 15
	field[41].Data = []byte(ManNum)
	//60域
	field[59].Ihave = true
	field[59].Len = 0x11
	field[59].Data = make([]byte, 6)
	field[59].Data[0] = 0x00
	memcpy(field[59].Data[1:], PiciNum, 3)
	field[59].Data[4] = 0x00
	field[59].Data[5] = 0x30
	//62域
	field[61].Ihave = true
	field[61].Len = 0x25
	field[61].Data = make([]byte, 25)
	str := "Sequence No12"
	memcpy(field[61].Data, []byte(str), 13)
	memcpy(field[61].Data[13:], LicenceNum, 4)
	memcpy(field[61].Data[17:], []byte(PosNum), 8)

	//63域
	field[62].Ihave = true
	field[62].Len = 0x03
	field[62].Data = make([]byte, 3)
	field[62].Data[0] = 0x30
	field[62].Data[1] = 0x30
	field[62].Data[2] = 0x31
	/*报文组帧，自动组织这些域到Pack的TxBuffer中*/
	s.Pack8583Fields()

	CommSn++ //通讯流水每次加一

	//s.PrintFields(up.Ea.Field_S)

}

func NewUp8583() *Up8583 {

	var up = new(Up8583)
	up.Ea = easy8583.New8583()

	up.Ea.Tpdu = byteutil.HexStringToBytes(TPDU)
	return up

}
func main() {

	fmt.Println("test...")

	up := NewUp8583()
	//up.Frame8583QD()

	recvstr := "007960000001386131003111080810003800010AC0001450021122130107200800085500323231333031343931333239303039393939393930363030313433303137303131393939390011000005190030004046F161A743497B32EAC760DF5EA57DF5900ECCE3977731A7EA402DDF0000000000000000CFF1592A"

	recv := byteutil.HexStringToBytes(recvstr)
	ret := up.Ea.Ans8583Fields(recv, len(recv))
	if ret == 0 {
		fmt.Println("解析成功")
		up.Ea.PrintFields(up.Ea.Field_R)
	} else {
		fmt.Println("解析失败")
	}

	up.Frame8583QD()
	up.Ea.PrintFields(up.Ea.Field_S)
	fmt.Println(byteutil.BytesToHexString(up.Ea.Txbuf))

}
