package utils

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"
)

func TlsConnect(ip string, port int) (net.Conn, error) {

	service := fmt.Sprintf("%s:%d", ip, port)
	conn, err := tls.Dial("tcp", service, &tls.Config{InsecureSkipVerify: true})
	//status := conn.ConnectionState()
	//fmt.Printf("%#v\n", status)

	return conn, err
}

func TlsTxData(c net.Conn, data []byte) (int, error) {

	c.SetWriteDeadline(time.Now().Add(time.Duration(5) * time.Second))
	fmt.Println("->send:")
	fmt.Println(bytesToHexString(data))
	n, err := c.Write(data)
	checkErr(err)
	return n, err

}
func TlsRxData(c net.Conn, data []byte) (int, error) {

	c.SetReadDeadline(time.Now().Add(time.Duration(10) * time.Second))

	n, err := c.Read(data[0:])
	checkErr(err)
	if err == nil {
		fmt.Println("<-recv:")
		fmt.Println(bytesToHexStr(data, n))
	}
	return n, err

}

func TlsDisConnect(c net.Conn) {
	if c != nil {
		c.Close()
	}

}

func main1() {
	//var buf [512]byte

	conn, err := TlsConnect("120.27.248.12", 10004)
	checkErr(err)
	if err != nil {
		return
	}

	_, err = TlsTxData(conn, []byte("Hello server!"))
	if err == nil {
		fmt.Println("send ok!")
	}
	rxbuf := make([]byte, 1024)
	rxlen := 0
	rxlen, err = TlsRxData(conn, rxbuf)
	if err == nil {
		fmt.Printf("rx ok!,len=%d\n", rxlen)
	}
	TlsDisConnect(conn)
	//fmt.Println("Reply from server ", rAddr.String(), string(buf[0:n]))
	os.Exit(0)
}
