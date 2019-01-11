/**
 * Created by yangyongzhen on 2019/01/11
 * simple 8583 Protocol Analysis
 */

package easy8583

import (
	"bytes"
	"fmt"
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

	Txbuf   []byte

	Field_S []Field //发送的域
	Field_R []Field //接收的域
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

//各个域的初始配置
func (ea *Easy8583) Init8583Fields(fds []Field) {

	 for i := 0; i < 64;i++ {
	 	fds[i].Ihave = false
	 }

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

	ea.Len  = []byte{0x00, 0x00}
	ea.Tpdu = []byte{0x60, 0x05, 0x01, 0x00, 0x00}
	ea.Head = []byte{0x61, 0x31, 0x00, 0x31, 0x11, 0x08}

	ea.Msgtype = []byte{0x08, 0x00}

	ea.Bitmap = make([]byte, 8)

	ea.Field_S = make([]Field,64)
	ea.Field_R = make([]Field,64)

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
8583报文打包
*/
func (ea *Easy8583) Pack8583Fields() int {
	fmt.Printf("pack 8583 fields\n")
	//ea.Txbuf[]
	ea.Txbuf = ea.Txbuf[0:23]
	toZero(ea.Txbuf)

	memcpy(ea.Txbuf[2:], ea.Tpdu, 5)
	memcpy(ea.Txbuf[7:], ea.Head, 6)
	memcpy(ea.Txbuf[13:], ea.Msgtype, 2)
	memcpy(ea.Txbuf[15:], ea.Bitmap, 8)

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
				ea.Txbuf = ea.Txbuf[0 : len+ea.Field_S[i].Len]
				memcpy(ea.Txbuf[len:], ea.Field_S[i].Data, ea.Field_S[i].Len)
				len += ea.Field_S[i].Len

			} else if ea.Field_S[i].Ltype == LLVAR {
				ea.Txbuf = ea.Txbuf[0 : len+1]
				ea.Txbuf[len] = byte(ea.Field_S[i].Len)

				tmplen = bcdToInt(ea.Txbuf[len:],1)
				if ea.Field_S[i].Dtype == BCD {
					tmplen = ((tmplen/2) + (tmplen%2))
				}
				len += 1
				ea.Txbuf = ea.Txbuf[0 : len+tmplen]
				memcpy(ea.Txbuf[len:], ea.Field_S[i].Data, tmplen)
				len += tmplen

			} else if ea.Field_S[i].Ltype == LLLVAR {
				ea.Txbuf = ea.Txbuf[0 : len+2]
				ea.Txbuf[len] =   byte(ea.Field_S[i].Len>>8)
				ea.Txbuf[len+1] = byte(ea.Field_S[i].Len)

				tmplen = bcdToInt(ea.Txbuf[len:],2)
				if ea.Field_S[i].Dtype == BCD {
					tmplen = ((tmplen/2) + (tmplen%2))
				}
				len += 2
				ea.Txbuf = ea.Txbuf[0 : len+tmplen]
				memcpy(ea.Txbuf[len:], ea.Field_S[i].Data, tmplen)
				len += tmplen

			}

		}
		//报文总长度
		ea.Txbuf[0] = byte((len-2)>>8)
		ea.Txbuf[1] = byte((len-2))
		memcpy(ea.Len,ea.Txbuf,2)

	}

	return 0
}


/*
8583报文解包
*/
func (ea *Easy8583) Ans8583Fields( rxbuf []byte,rxlen int) int {
	fmt.Printf("ans 8583 fields\n")
	ea.Init8583Fields(ea.Field_R)

	len := 0
	tmplen := 0
	bitMap := make([]byte,8)
	var seat,buf uint64 = 1,0

	memcpy(bitMap,rxbuf[15:],8)

	memcpy(ea.Len,rxbuf[0:],2)
	//memcpy(ea.Tpdu,rxbuf[2:],5)
	memcpy(ea.Head,rxbuf[7:],6)
	memcpy(ea.Msgtype,rxbuf[13:],2)
	memcpy(ea.Bitmap,rxbuf[15:],8)

	len += 23

	for i := 0;i < 8;i++ {
        buf = ((buf<<8) | uint64(bitMap[i]))
	}

	for i := 0; i < 64; i++ {
		if  (buf & (seat << uint(63 - i))) > 0 {
			ea.Field_R[i].Ihave = true
			if ea.Field_R[i].Ltype == NOVAR {
				ea.Field_R[i].Data = make([]byte,ea.Field_R[i].Len)
				memcpy(ea.Field_R[i].Data, rxbuf[len:], ea.Field_R[i].Len)
				len += ea.Field_R[i].Len

			} else if ea.Field_R[i].Ltype == LLVAR {
			
				ea.Field_R[i].Len = int(rxbuf[len])

				tmplen = bcdToInt(rxbuf[len:],1)
				if ea.Field_R[i].Dtype == BCD {
					tmplen = ((tmplen/2) + (tmplen%2))
				}
				len += 1
				ea.Field_R[i].Data = make([]byte,tmplen)
				memcpy(ea.Field_R[i].Data, rxbuf[len:], tmplen)
				len += tmplen

			} else if ea.Field_R[i].Ltype == LLLVAR {

				ea.Field_R[i].Len = ( ( int(rxbuf[len])<<8 ) | int(rxbuf[len+1] ) )

				tmplen = bcdToInt(rxbuf[len:],2)
				if ea.Field_R[i].Dtype == BCD {
					tmplen = ((tmplen/2) + (tmplen%2))
				}
				len += 2
				ea.Field_R[i].Data = make([]byte,tmplen)
				memcpy(ea.Field_R[i].Data, rxbuf[len:], tmplen)
				len += tmplen

			}

		}

	}

	if(len > rxlen){
        return 1;
	}
	
	return 0
}

/*
打印信息，调试用
*/
func (ea *Easy8583) PrintFields(fds []Field){
	fmt.Println("Print fields...")
	fmt.Printf("\n==========================================\n")
	fmt.Printf("Len:\t%s\n", bytesToHexString(ea.Len))
	fmt.Printf("Tpdu:\t%s\n", bytesToHexString(ea.Tpdu))
	fmt.Printf("Head:\t%s\n", bytesToHexString(ea.Head))
	fmt.Printf("Msge:\t%s\n", bytesToHexString(ea.Msgtype))
	fmt.Printf("Bitmap:\t%s\n", bytesToHexString(ea.Bitmap))
	fmt.Printf("\n==========================================\n")
	for i:=0; i < 64; i++{
		if fds[i].Ihave {
			fmt.Printf("[field:%d] ",i+1)
			if fds[i].Ltype == LLVAR{
				fmt.Printf("[len:%02x] ",fds[i].Len)
			}else if fds[i].Ltype == LLLVAR{
				fmt.Printf("[len:%04x] ",fds[i].Len)
			}
			
			fmt.Printf("[%s]\n",bytesToHexString(fds[i].Data))
			fmt.Printf("\n------------------------------\n")
		
		}
	}
}

func main() {

	fmt.Println("test...")
}
