package utils

import (
	"bytes"
	"crypto/des"
	"errors"
)

/*
func main() {
	data := []byte("1234567812345678")
	key := []byte("12345678")
	result, err := DesEncrypt(data, key)
	if err != nil {
		fmt.Println(err)
	}
	a := hex.EncodeToString(result)
	fmt.Println(a)
	out, _ := hex.DecodeString(a)
	result, err = DesDecrypt(out, key)
	if err != nil {
		fmt.Println(err)
	}
	a = hex.EncodeToString(result)
	fmt.Println(a)

	data = []byte("1234567812345678")
	key = []byte("1234567812345678")

	result, err = Des3Encrypt(data, key)
	if err != nil {
		fmt.Println(err)
	}
	a = hex.EncodeToString(result)
	fmt.Println(a)

}
*/

//DES算法，ECB模式
func DesEncrypt(data, key []byte) ([]byte, error) {
	//NewCipher创建一个新的加密块
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()
	//data = Pkcs5Padding(data, bs)
	//if len(data)%bs != 0 {
	//	return nil, errors.New("need a multiple of the blocksize")
	//}

	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		//Encrypt加密第一个块，将其结果保存到dst
		block.Encrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

func DesDecrypt(data, key []byte) ([]byte, error) {
	//NewCipher创建一个新的加密块
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()
	//data = Pkcs5Padding(data, bs)
	//if len(data)%bs != 0 {
	//  return nil, errors.New("need a multiple of the blocksize")
	//}

	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		//Encrypt加密第一个块，将其结果保存到dst
		block.Decrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

//[golang ECB 3DES Encrypt]
//3DES双倍长算法
func Des3Encrypt(origData, key []byte) ([]byte, error) {

	if (len(key) != 16) || (len(origData)%8 != 0) {
		return nil, errors.New("error,lenth is not right!")
	}
	tkey := make([]byte, 16, 16)
	copy(tkey, key)
	k1 := tkey[:8]
	k2 := tkey[8:16]

	//bs := block.BlockSize()
	//origData = PKCS5Padding(origData, bs)

	buf1, err := DesEncrypt(origData, k1)
	if err != nil {
		return nil, err
	}
	buf2, err := DesDecrypt(buf1, k2)
	if err != nil {
		return nil, err
	}
	out, err := DesEncrypt(buf2, k1)
	if err != nil {
		return nil, err
	}
	return out, nil
}

//[golang ECB 3DES Decrypt]
//3DES双倍长算法
func Des3Decrypt(crypted, key []byte) ([]byte, error) {

	tkey := make([]byte, 16, 16)
	copy(tkey, key)
	k1 := tkey[:8]
	k2 := tkey[8:16]
	buf1, err := DesDecrypt(crypted, k1)
	if err != nil {
		return nil, err
	}
	buf2, err := DesEncrypt(buf1, k2)
	if err != nil {
		return nil, err
	}
	out, err := DesDecrypt(buf2, k1)
	if err != nil {
		return nil, err
	}
	//out = PKCS5Unpadding(out)
	return out, nil
}

func Pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
