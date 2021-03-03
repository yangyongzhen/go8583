/**
* Created by yangyongzhen
* QQ:534117529
* simple 8583 Protocol Analysis tool by Golang
 */

package easy8583

import (
	"bytes"
	"fmt"
	"go8583/utils"
	"strconv"
)

type Field struct {
	Ihave bool   //是否存在该域
	Ltype int    //长度类型 （NOVAR，LLVAR，LLLVAR）
	Dtype int    //数据类型 （BCD,ASCII）
	Len   int    //域的数据内容的长度
	Data  []byte //域的有效数据
}

type Easy8583 struct {
	Len     []byte
	Tpdu    []byte
	Head    []byte
	Msgtype []byte
	Bitmap  []byte

	Txbuf []byte

	Field_S []Field //发送的域
	Field_R []Field //接收的域

	MacKey []byte //工作秘钥

	YsEnable byte //是否启用银商通道
}

//定义枚举类型 长度类型定义
const (
	NOVAR  = iota //value = 0,定长,
	LLVAR         //value = 1，长度为1字节
	LLLVAR        //value = 2，长度为2字节

)

//定义枚举类型 数据类型定义
const (
	UN  = iota //value = 0, 未定义，定长的域无需关注类型
	BIN        //value = 1，BIN
	BCD        //value = 2，BCD
)

/*
设置工作秘钥,算MAC用
*/
func (ea *Easy8583) SetMacKey(strkey string) {
	ea.MacKey = hexStringToBytes(strkey)
}

func (ea *Easy8583) SetYsEnable(flag byte) {
	ea.YsEnable = flag
}

//各个域的初始配置
func (ea *Easy8583) Init8583Fields(fds []Field) {

	for i := 0; i < 64; i++ {
		fds[i].Ihave = false
	}

	toZero(ea.Bitmap)

	fds[0].Ltype = 0

	fds[1].Ltype = LLVAR //LLVAR
	fds[1].Dtype = BCD

	fds[2].Ltype = 0
	fds[2].Len = 3

	fds[3].Ltype = 0
	fds[3].Len = 6

	fds[10].Ltype = 0
	fds[10].Len = 3

	fds[11].Ltype = 0
	fds[11].Len = 3

	fds[12].Ltype = 0
	fds[12].Len = 2

	fds[13].Ltype = 0
	fds[13].Len = 2
	fds[14].Ltype = 0
	fds[14].Len = 2

	fds[21].Ltype = 0
	fds[21].Len = 2
	fds[22].Ltype = 0
	fds[22].Len = 2

	fds[24].Ltype = 0
	fds[24].Len = 1
	fds[25].Ltype = 0
	fds[25].Len = 1

	fds[31].Ltype = LLVAR //LLVAR
	fds[31].Dtype = BCD
	fds[34].Ltype = LLVAR //LLVAR
	fds[34].Dtype = BCD

	fds[36].Ltype = 0
	fds[36].Len = 12

	fds[37].Ltype = 0
	fds[37].Len = 6
	fds[38].Ltype = 0
	fds[38].Len = 2

	fds[39].Ltype = LLVAR

	fds[40].Ltype = 0
	fds[40].Len = 8
	fds[41].Ltype = 0
	fds[41].Len = 15

	fds[43].Ltype = LLVAR

	fds[47].Ltype = LLLVAR
	fds[47].Dtype = BCD

	fds[48].Ltype = 0
	fds[48].Len = 3
	fds[51].Ltype = 0
	fds[51].Len = 8
	fds[52].Ltype = 0
	fds[52].Len = 8

	fds[54].Ltype = LLLVAR //LLLVAR
	fds[58].Ltype = LLLVAR

	fds[59].Ltype = LLLVAR
	fds[59].Dtype = BCD

	fds[60].Ltype = LLLVAR
	fds[60].Dtype = BCD

	fds[61].Ltype = LLLVAR
	fds[62].Ltype = LLLVAR

	fds[63].Ltype = 0
	fds[63].Len = 8

}

/*
构造函数，初始化
*/

func New8583() *Easy8583 {

	var ea = new(Easy8583)
	ea.Txbuf = make([]byte, 0, 1024)
	ea.Txbuf = ea.Txbuf[0:23]

	ea.Len = []byte{0x00, 0x00}
	ea.Tpdu = []byte{0x60, 0x05, 0x01, 0x00, 0x00}
	ea.Head = []byte{0x61, 0x31, 0x00, 0x31, 0x11, 0x08}

	ea.Msgtype = []byte{0x08, 0x00}

	ea.Bitmap = make([]byte, 8)

	ea.Field_S = make([]Field, 64)
	ea.Field_R = make([]Field, 64)

	ea.Init8583Fields(ea.Field_S)
	ea.Init8583Fields(ea.Field_R)

	return ea
}

func memcpy(dst, src []byte, size int) {
	for i := 0; i < size; i++ {
		dst[i] = src[i]
	}
	return
}

func bytesToHexStr(data []byte, lenth int) string {
	buf := data[0:lenth]
	hexStr := fmt.Sprintf("%x", buf)
	//fmt.Println(hexStr)
	return hexStr

}

// bytes to hex string
func bytesToHexString(b []byte) string {
	var buf bytes.Buffer
	for _, v := range b {
		t := strconv.FormatInt(int64(v), 16)
		if len(t) > 1 {
			buf.WriteString(t)
		} else {
			buf.WriteString("0" + t)
		}
	}
	return buf.String()
}

// hex string to bytes
func hexStringToBytes(s string) []byte {
	bs := make([]byte, 0)
	for i := 0; i < len(s); i = i + 2 {
		b, _ := strconv.ParseInt(s[i:i+2], 16, 16)
		bs = append(bs, byte(b))
	}
	return bs
}

//例：0x19 --> 19, 0x0119 -> 119
func bcdToInt(data []byte, lenth int) int {
	buf := data[0:lenth]
	hexStr := fmt.Sprintf("%x", buf)
	out, _ := strconv.ParseInt(hexStr, 10, 32)
	return int(out)

}
func toZero(p []byte) {
	for i := range p {
		p[i] = 0
	}
}

/*
计算银联8583通信MAC
*/
func dataXor1(src []byte, dest []byte, size int) {
	for i := 0; i < size; i++ {
		dest[i] ^= src[i]
	}

}

func dataXor(src []byte, dest []byte, size int, out []byte) {
	for i := 0; i < size; i++ {
		out[i] = dest[i] ^ src[i]
	}

}

func UpGetMac(buf []byte, bufsize int, mackey []byte) ([]byte, error) {

	block := make([]byte, 1024)
	val := make([]byte, 8)
	memcpy(block, buf, bufsize)

	x := bufsize / 8 //计算有多少个完整的块
	n := bufsize % 8

	if n != 0 {
		x += 1 //将补上的这一块加上去
	}
	j := 0
	for i := 0; i < x; i++ {
		dataXor1(block[j:], val, 8)
		j += 8
	}

	Bbuf := fmt.Sprintf("%02X%02X%02X%02X%02X%02X%02X%02X", val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7])
	//fmt.Printf("Bbuf:%s\n",Bbuf)
	Abuf := make([]byte, 8)
	//fmt.Println(bytesToHexString( []byte(Bbuf[0:8]) ))
	mac, err := utils.DesEncrypt([]byte(Bbuf[0:8]), mackey)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("mac1:%x\n",mac)
	dataXor(mac, []byte(Bbuf[8:]), 8, Abuf)
	mac, err = utils.DesEncrypt(Abuf, mackey)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("mac2:%x\n",mac)
	outmac := fmt.Sprintf("%02X%02X%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7])
	//fmt.Printf("outmac:%s\n",outmac)
	return []byte(outmac[0:8]), nil

}

func Ansi99XGetMac(buf []byte, bufsize int, mackey []byte) ([]byte, error) {
	block := make([]byte, 1024)
	val := make([]byte, 8)
	xor := make([]byte, 8)
	memcpy(block, buf, bufsize)

	x := bufsize / 8 //计算有多少个完整的块
	n := bufsize % 8

	if n != 0 {
		x += 1 //将补上的这一块加上去
	}
	j := 0
	for i := 0; i < x; i++ {
		dataXor(val, block[j:], 8, xor)
		val, _ = utils.DesEncrypt(xor, mackey)
		j += 8
	}
	mac := make([]byte, 8)
	memcpy(mac, val, 8)
	return mac, nil
}

/*
8583报文打包,args传入个工作秘钥
*/
func (ea *Easy8583) Pack8583Fields() int {
	fmt.Printf("pack 8583 fields\n")
	//ea.Txbuf[]
	ea.Txbuf = ea.Txbuf[0:23]
	toZero(ea.Txbuf)

	j := 0
	len := 23
	tmplen := 0
	seat := 0x80
	for i := 0; i < 64; i++ {
		seat = (seat >> 1)
		if (i % 8) == 0 {
			j++
			seat = 0x80
		}
		if ea.Field_S[i].Ihave {
			ea.Bitmap[j-1] |= byte(seat)
			if ea.Field_S[i].Ltype == NOVAR {
				//fmt.Printf("i =%d,len=%d,Field_S=%d\n", i, len, ea.Field_S[i].Len)
				ea.Txbuf = ea.Txbuf[0 : len+ea.Field_S[i].Len]
				memcpy(ea.Txbuf[len:], ea.Field_S[i].Data, ea.Field_S[i].Len)
				len += ea.Field_S[i].Len

			} else if ea.Field_S[i].Ltype == LLVAR {
				ea.Txbuf = ea.Txbuf[0 : len+1]
				ea.Txbuf[len] = byte(ea.Field_S[i].Len)

				tmplen = bcdToInt(ea.Txbuf[len:], 1)
				if ea.Field_S[i].Dtype == BCD {
					tmplen = ((tmplen / 2) + (tmplen % 2))
				}
				len += 1
				ea.Txbuf = ea.Txbuf[0 : len+tmplen]
				memcpy(ea.Txbuf[len:], ea.Field_S[i].Data, tmplen)
				len += tmplen

			} else if ea.Field_S[i].Ltype == LLLVAR {
				ea.Txbuf = ea.Txbuf[0 : len+2]
				ea.Txbuf[len] = byte(ea.Field_S[i].Len >> 8)
				ea.Txbuf[len+1] = byte(ea.Field_S[i].Len)

				tmplen = bcdToInt(ea.Txbuf[len:], 2)
				if ea.Field_S[i].Dtype == BCD {
					tmplen = ((tmplen / 2) + (tmplen % 2))
				}
				len += 2
				ea.Txbuf = ea.Txbuf[0 : len+tmplen]
				memcpy(ea.Txbuf[len:], ea.Field_S[i].Data, tmplen)
				len += tmplen

			}

		}

	}

	//报文总长度
	ea.Txbuf[0] = byte((len - 2) >> 8)
	ea.Txbuf[1] = byte((len - 2))
	memcpy(ea.Len, ea.Txbuf, 2)
	memcpy(ea.Txbuf[2:], ea.Tpdu, 5)
	memcpy(ea.Txbuf[7:], ea.Head, 6)
	memcpy(ea.Txbuf[13:], ea.Msgtype, 2)
	memcpy(ea.Txbuf[15:], ea.Bitmap, 8)
	//如果64域存在，自动计算MAC并填充
	if ea.Field_S[63].Ihave {
		//txbuf := []byte{0x00,0x69,0x60,0x01,0x38,0x00,0x00,0x61,0x31,0x00,0x31,0x11,0x08,0x02,0x00,0x30,0x20,0x04,0x80,0x00,0xc0,0x80,0x31,0x00,0x00,0x00,0x30,0x30,0x30,0x30,0x30,0x30,0x00,0x00,0x02,0x03,0x20,0x00,0x33,0x34,0x33,0x38,0x36,0x30,0x31,0x33,0x38,0x39,0x38,0x34,0x33,0x30,0x34,0x34,0x31,0x31,0x31,0x30,0x30,0x31,0x32,0x31,0x35,0x36,0x00,0x24,0x41,0x33,0x30,0x31,0x39,0x36,0x32,0x32,0x32,0x36,0x37,0x35,0x32,0x38,0x31,0x34,0x36,0x34,0x32,0x39,0x38,0x36,0x33,0x34,0x00,0x13,0x22,0x00,0x00,0x80,0x00,0x06,0x00}
		mac, err := UpGetMac(ea.Txbuf[13:], len-13-8, ea.MacKey)
		if err != nil {
			fmt.Println(err)
			panic("calc mac error!")
		}
		//fmt.Printf("mac:%x", mac)
		memcpy(ea.Field_S[63].Data, mac, 8)
		memcpy(ea.Txbuf[len-8:], mac, 8)
	}

	return 0
}

/*
8583报文解包
*/
func (ea *Easy8583) Ans8583Fields(rxbuf []byte, rxlen int) int {
	fmt.Printf("ans 8583 fields\n")
	ea.Init8583Fields(ea.Field_R)

	len := 0
	tmplen := 0
	bitMap := make([]byte, 8)
	var seat, buf uint64 = 1, 0

	memcpy(bitMap, rxbuf[15:], 8)

	memcpy(ea.Len, rxbuf[0:], 2)
	//memcpy(ea.Tpdu,rxbuf[2:],5)
	memcpy(ea.Head, rxbuf[7:], 6)
	memcpy(ea.Msgtype, rxbuf[13:], 2)
	memcpy(ea.Bitmap, rxbuf[15:], 8)

	len += 23

	for i := 0; i < 8; i++ {
		buf = ((buf << 8) | uint64(bitMap[i]))
	}

	for i := 0; i < 64; i++ {
		if (buf & (seat << uint(63-i))) > 0 {
			ea.Field_R[i].Ihave = true
			if ea.Field_R[i].Ltype == NOVAR {
				ea.Field_R[i].Data = make([]byte, ea.Field_R[i].Len)
				memcpy(ea.Field_R[i].Data, rxbuf[len:], ea.Field_R[i].Len)
				len += ea.Field_R[i].Len

			} else if ea.Field_R[i].Ltype == LLVAR {

				ea.Field_R[i].Len = int(rxbuf[len])

				tmplen = bcdToInt(rxbuf[len:], 1)
				if ea.Field_R[i].Dtype == BCD {
					tmplen = ((tmplen / 2) + (tmplen % 2))
				}
				len += 1
				ea.Field_R[i].Data = make([]byte, tmplen)
				memcpy(ea.Field_R[i].Data, rxbuf[len:], tmplen)
				len += tmplen

			} else if ea.Field_R[i].Ltype == LLLVAR {

				ea.Field_R[i].Len = ((int(rxbuf[len]) << 8) | int(rxbuf[len+1]))

				tmplen = bcdToInt(rxbuf[len:], 2)
				if ea.Field_R[i].Dtype == BCD {
					tmplen = ((tmplen / 2) + (tmplen % 2))
				}

				if ea.YsEnable == 1 {
					//如果启用了银商通道
					if i == 47 {
						tmplen = bcdToInt(rxbuf[len:], 2)
					}
					if i == 61 {
						tmplen = bcdToInt(rxbuf[len:], 2)
						tmplen = tmplen / 2
					}
				}

				len += 2
				ea.Field_R[i].Data = make([]byte, tmplen)
				memcpy(ea.Field_R[i].Data, rxbuf[len:], tmplen)
				len += tmplen

			}

		}

	}

	if len > rxlen {
		return 1
	}

	return 0
}

/*
打印信息，调试用
*/
func (ea *Easy8583) PrintFields(fds []Field) {
	fmt.Println("Print fields...")
	fmt.Printf("\n==========================================\n")
	fmt.Printf("Len:\t%s\n", bytesToHexString(ea.Len))
	fmt.Printf("Tpdu:\t%s\n", bytesToHexString(ea.Tpdu))
	fmt.Printf("Head:\t%s\n", bytesToHexString(ea.Head))
	fmt.Printf("Msge:\t%s\n", bytesToHexString(ea.Msgtype))
	fmt.Printf("Bitmap:\t%s\n", bytesToHexString(ea.Bitmap))
	fmt.Printf("\n==========================================\n")
	for i := 0; i < 64; i++ {
		if fds[i].Ihave {
			fmt.Printf("[field:%d] ", i+1)
			if fds[i].Ltype == LLVAR {
				fmt.Printf("[len:%02x] ", fds[i].Len)
			} else if fds[i].Ltype == LLLVAR {
				fmt.Printf("[len:%04x] ", fds[i].Len)
			}

			fmt.Printf("[%s]\n", bytesToHexString(fds[i].Data))
			fmt.Printf("\n------------------------------\n")

		}
	}
}

func main() {

	fmt.Println("test...")
}
