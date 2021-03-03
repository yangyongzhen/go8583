package utils

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
	}
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
func Connect(ip string, port int) (net.Conn, error) {

	service := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", service, 5*time.Second)
	return conn, err
}

func TxData(c net.Conn, data []byte) (int, error) {

	c.SetWriteDeadline(time.Now().Add(time.Duration(5) * time.Second))
	fmt.Println("->send:")
	fmt.Println(bytesToHexString(data))
	n, err := c.Write(data)
	checkErr(err)
	return n, err

}
func RxData(c net.Conn, data []byte) (int, error) {

	c.SetReadDeadline(time.Now().Add(time.Duration(10) * time.Second))

	n, err := c.Read(data[0:])
	checkErr(err)
	if err == nil {
		fmt.Println("<-recv:")
		fmt.Println(bytesToHexStr(data, n))
	}
	return n, err

}

func DisConnect(c net.Conn) {
	if c != nil {
		c.Close()
	}

}

func main() {
	//var buf [512]byte
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s host:port ", os.Args[0])
		os.Exit(1)
	}
	service := os.Args[1]

	conn, err := net.DialTimeout("tcp", service, 5*time.Second)
	checkErr(err)

	_, err = TxData(conn, []byte("Hello server!"))
	if err == nil {
		fmt.Println("send ok!")
	}
	rxbuf := make([]byte, 1024)
	rxlen := 0
	rxlen, err = RxData(conn, rxbuf)
	if err == nil {
		fmt.Printf("rx ok!,len=%d\n", rxlen)
	}
	DisConnect(conn)
	//fmt.Println("Reply from server ", rAddr.String(), string(buf[0:n]))
	os.Exit(0)
}
