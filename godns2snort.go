package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func writeLines(lines []string, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func main() {
	domains, _ := readLines("dns.txt")
	for _, domain := range domains {
		//Remove leading stops which often preceed TLDs.
		trimmed := strings.TrimPrefix(domain, ".")
		//Split domain into slice of segments.
		segments := strings.Split(trimmed, ".")
		i := 0
		rulefragment := ""
		for _, s := range segments {
			shex := fmt.Sprintf("%02X", len(s))
			rulefragment += shex + "|" + s + "|"
			i++
		}

		fmt.Printf("alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:\"BLACKLIST DNS domain %s\"; flow:to_server; byte_test:1,!&,0xF8,2; content:\"|%s00|\"; fast_pattern:only; metadata:service dns;  sid:; rev:1;)\n", domain, rulefragment)

	}
}
