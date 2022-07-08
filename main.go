package main

//$ env GOOS=linux GOARCH=arm64 go build -o prepnode_arm64
//prend en flag hash, salt, wordlist
//loop over every line of the wordlist file
//test if md5(salt + line de wordlist) == passwd hash -> then cracked

import (
	"bufio"
	"crypto/md5"
	"embed"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
)

//go:embed wordlist.txt
var f embed.FS

func main() {

	//flags
	hash := flag.String("p", "c21f969b5f03d33d43e04f8f136e7682", "The password hash.") //default hash is default
	salt := flag.String("s", "", "The password salt.")
	wordlist := flag.String("w", "wordlist.txt", "Wordlist to crack the password. e.g. rockyou.txt")
	flag.Parse()

	//open the wordlist
	file, err := f.Open(*wordlist)
	if err != nil {
		file, err = os.Open(*wordlist)
		if err != nil {
			log.Fatal(err)
		}
	}
	defer file.Close()

	//read the lines of the wordlist
	scanner := bufio.NewScanner(file)
	var password string
	//loop trough the lines of the wordlist
	for scanner.Scan() {
		line := scanner.Text()

		//if salt then prepend it to the password plaintext
		if *salt != "" {
			line = *salt + line
		}

		//md5 hash the plaintext
		md5hash := md5.Sum([]byte(line))

		//test if plaintext hashed equ the hash flag
		if hex.EncodeToString(md5hash[:]) == *hash {
			password = scanner.Text()
			break
		}

	}

	if password != "" {
		fmt.Printf("Password is %v\n", password)
	} else {
		fmt.Println("No password found")
	}

}
