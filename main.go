package main

import (
	"bufio"
	"crypto/sha1"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/valyala/fastjson"
)

// cat ffuf-json-output | jklean -f status,words,lines
// cat httpx-json-output | jklean -f hash.body_sha256,words,lines

var (
	// limit          int
	selectedFields string
	toCSV          bool
)

func main() {
	// cli aguments
	flag.StringVar(&selectedFields, "f", "status,words,lines", "Select fields to generate the hash")
	flag.BoolVar(&toCSV, "csv", false, "Output the data to CSV format")
	// flag.IntVar(&limit, "l", 100, "Limit length of path item (default 100)")
	flag.Parse()

	// this help to reduce the memory usage in case we parse a big file
	dataMapping, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init map")
		os.Exit(1)
	}
	defer dataMapping.Close()

	var fields []string
	var p fastjson.Parser

	// get the fields in JSON file
	if strings.Contains(selectedFields, ",") {
		fields = strings.Split(selectedFields, ",")
	} else {
		fields = []string{selectedFields}
	}

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if sc.Err() != nil && raw == "" {
			continue
		}

		// check if the input is JSON or not
		v, err := p.Parse(raw)
		if err != nil {
			continue
		}

		var line []string
		for _, field := range fields {
			if strings.Contains(field, ".") {
				depthField := strings.Split(field, ".")
				line = append(line, v.Get(depthField...).String())
				continue
			}

			if value := v.Get(field); value != nil {
				line = append(line, value.String())
			}
		}

		hash := genHash(strings.Join(line, "-"))

		// // parsing the URL
		// u, err := url.Parse(raw)
		// if err != nil || u.Hostname() == "" {
		// 	continue
		// }

		if _, exist := dataMapping.Get(hash); !exist {
			dataMapping.Set(hash, []byte("0"))

			fmt.Println(raw)

		}

	}
}

// genHash gen SHA1 hash from string
func genHash(text string) string {
	h := sha1.New()
	h.Write([]byte(text))
	hashed := h.Sum(nil)
	return fmt.Sprintf("%v", hashed)
}
