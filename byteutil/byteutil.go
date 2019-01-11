package byteutil

import (
	"bytes"
	"fmt"
	"strconv"
)


func BytesToHexStr(data []byte, lenth int) string {
	buf := data[0:lenth]
	hexStr := fmt.Sprintf("%x", buf)
	//fmt.Println(hexStr)
	return hexStr

}

// bytes to hex string
func BytesToHexString(b []byte) string {
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
func HexStringToBytes(s string) []byte {
	bs := make([]byte, 0)
	for i := 0; i < len(s); i = i + 2 {
		b, _ := strconv.ParseInt(s[i:i+2], 16, 16)
		bs = append(bs, byte(b))
	}
	return bs
}

//例：0x19 --> 19, 0x0119 -> 119
func BcdToInt(data []byte, lenth int) int {
	buf := data[0:lenth]
	hexStr := fmt.Sprintf("%x", buf)
	out, _ := strconv.ParseInt(hexStr, 10, 32)
	return int(out)

}


func main() {

	fmt.Println("test...")

}
