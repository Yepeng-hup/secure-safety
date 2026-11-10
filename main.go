package main

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// go build -ldflags "-X main.Version=v1.0.1 -X main.SourceURL=xxxx" -o secure-safety-linux-amd64 .

var (
	Version   = "v1.0.0"
	SourceURL = "https://github.com/Yepeng-hup/secure-safety"
)

var ipRe = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// show login fail user
var userRe = regexp.MustCompile(
	`Failed (?:password|publickey) for (?:invalid user )?(\S+) from|` +
		`Invalid user (\S+) from|` +
		`authentication failure.*ruser=(\S+)`,
)

// if ssh login fail
var failPatterns = []string{
	"Failed password",
	"Failed publickey",
	"Invalid user",
	"authentication failure",
	"POSSIBLE BREAK-IN ATTEMPT",
	"maximum authentication attempts exceeded",
}

type IPStat struct {
	IP          string
	Count       int
	FirstSeen   time.Time
	LastSeen    time.Time
	FailCount   int
	FailedUsers map[string]int
}

type Summary struct {
	TotalLines int
	TotalFails int
}

func newIPStat(ip string) *IPStat {
	return &IPStat{IP: ip, FailedUsers: map[string]int{}}
}

func monthIndex(s string) int {
	switch s {
	case "Jan":
		return 1
	case "Feb":
		return 2
	case "Mar":
		return 3
	case "Apr":
		return 4
	case "May":
		return 5
	case "Jun":
		return 6
	case "Jul":
		return 7
	case "Aug":
		return 8
	case "Sep":
		return 9
	case "Oct":
		return 10
	case "Nov":
		return 11
	case "Dec":
		return 12
	}
	return 0
}

func atoiTrim(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func parseTime(line string, now time.Time) (time.Time, bool) {
	if len(line) < 15 {
		return time.Time{}, false
	}
	mon := monthIndex(line[0:3])
	if mon == 0 {
		return time.Time{}, false
	}
	day := atoiTrim(line[4:6])
	if day < 1 || day > 31 {
		return time.Time{}, false
	}
	t := line[7:15]
	if t[2] != ':' || t[5] != ':' {
		return time.Time{}, false
	}
	hh, mm, ss := atoiTrim(t[0:2]), atoiTrim(t[3:5]), atoiTrim(t[6:8])
	if hh > 23 || mm > 59 || ss > 59 {
		return time.Time{}, false
	}
	year := now.Year()
	tt := time.Date(year, time.Month(mon), day, hh, mm, ss, 0, time.Local)
	if tt.After(now) {
		tt = time.Date(year-1, time.Month(mon), day, hh, mm, ss, 0, time.Local)
	}
	return tt, true
}

func isSSHFailure(line string) bool {
	for _, p := range failPatterns {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}

func extractUser(line string) string {
	m := userRe.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	for _, g := range m[1:] {
		if g != "" {
			return g
		}
	}
	return ""
}

func openReader(path string) (io.Reader, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		return gz, func() { gz.Close(); f.Close() }, nil
	}
	return f, func() { f.Close() }, nil
}

// ---- core ----
func processFile(path string, now time.Time) (map[string]*IPStat, Summary, error) {
	stats := map[string]*IPStat{}
	sum := Summary{}

	r, closeFn, err := openReader(path)
	if err != nil {
		return nil, sum, err
	}
	defer closeFn()

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		sum.TotalLines++
		t, ok := parseTime(line, now)
		if !ok {
			continue
		}
		ips := ipRe.FindAllString(line, -1)
		if len(ips) == 0 {
			continue
		}
		isFail := isSSHFailure(line)
		u := ""
		if isFail {
			u = extractUser(line)
			sum.TotalFails++
		}
		for _, ip := range ips {
			s := stats[ip]
			if s == nil {
				s = newIPStat(ip)
				stats[ip] = s
			}
			s.Count++
			if s.FirstSeen.IsZero() || t.Before(s.FirstSeen) {
				s.FirstSeen = t
			}
			if t.After(s.LastSeen) {
				s.LastSeen = t
			}
			if isFail {
				s.FailCount++
				if u != "" {
					s.FailedUsers[u]++
				}
			}
		}
	}
	return stats, sum, scanner.Err()
}

func mergeStat(g, ls *IPStat) {
	g.Count += ls.Count
	g.FailCount += ls.FailCount
	if g.FirstSeen.IsZero() || ls.FirstSeen.Before(g.FirstSeen) {
		g.FirstSeen = ls.FirstSeen
	}
	if g.LastSeen.IsZero() || ls.LastSeen.After(g.LastSeen) {
		g.LastSeen = ls.LastSeen
	}
	for u, c := range ls.FailedUsers {
		g.FailedUsers[u] += c
	}
}

func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func printTable(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, c := range row {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	line := func(cells []string) {
		parts := make([]string, len(cells))
		for i, c := range cells {
			parts[i] = pad(c, widths[i])
		}
		fmt.Println(strings.Join(parts, "  "))
	}
	line(headers)
	sep := make([]string, len(headers))
	for i, w := range widths {
		sep[i] = strings.Repeat("-", w)
	}
	line(sep)
	for _, row := range rows {
		line(row)
	}
}

func topUsers(users map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range users {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
	if len(arr) > n {
		arr = arr[:n]
	}
	parts := make([]string, len(arr))
	for i, kv := range arr {
		parts[i] = fmt.Sprintf("%s(%d)", kv.k, kv.v)
	}
	return strings.Join(parts, ", ")
}

func main() {
	top := flag.Int("top", 0, "IP Display the first N records (0 = all)")
	failTop := flag.Int("fail-top", 0, "SSH Display the first N failed records (0 = all)")
	concurrency := flag.Int("c", runtime.NumCPU(), "Number of goroutines used for concurrent file parsing (default = number of CPU cores)")
	showVersion := flag.Bool("version", false, "Display version number and source code URL")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] log_files...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Default: Automatically read all /var/log/secure* files (including .gz) and aggregate the results.\n")
		fmt.Fprintf(os.Stderr, "  Supports regular and .gz compressed files. Multiple files can be specified simultaneously, including wildcard paths.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("secure-safety %s\ngithub: %s\n", Version, SourceURL)
		return
	}
	flag.Parse()

	start := time.Now()
	now := start

	var files []string
	if flag.NArg() == 0 {
		matches, _ := filepath.Glob("/var/log/secure*")
		if len(matches) > 0 {
			files = matches
		} else {
			files = []string{"/var/log/secure"}
		}
	} else {
		for _, a := range flag.Args() {
			matches, err := filepath.Glob(a)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Wildcard resolution failed %s: %v\n", a, err)
				os.Exit(1)
			}
			if len(matches) == 0 {
				matches = []string{a}
			}
			files = append(files, matches...)
		}
	}

	n := *concurrency
	if n < 1 {
		n = 1
	}
	if n > len(files) {
		n = len(files)
	}

	jobs := make(chan string, len(files))
	for _, f := range files {
		jobs <- f
	}
	close(jobs)

	type fileResult struct {
		stats map[string]*IPStat
		sum   Summary
		err   error
	}
	results := make(chan fileResult, len(files))

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				local, s, err := processFile(f, now)
				results <- fileResult{local, s, err}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	stats := map[string]*IPStat{}
	sum := &Summary{}
	for r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "Error processing file: %v\n", r.err)
			continue
		}
		sum.TotalLines += r.sum.TotalLines
		sum.TotalFails += r.sum.TotalFails
		for ip, ls := range r.stats {
			g := stats[ip]
			if g == nil {
				stats[ip] = ls
				continue
			}
			mergeStat(g, ls)
		}
	}

	all := make([]*IPStat, 0, len(stats))
	for _, s := range stats {
		all = append(all, s)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Count > all[j].Count })

	fmt.Printf("\n====== Statistics Summary ======\n")
	fmt.Printf("Number of Log Files : %d\n", len(files))
	fmt.Printf("Scanned log lines : %d\n", sum.TotalLines)
	fmt.Printf("Unique IPs        : %d\n", len(all))
	fmt.Printf("Total SSH failures: %d\n", sum.TotalFails)
	fmt.Printf("Statistics time   : %s\n\n", now.Format("2006-01-02 15:04:05"))

	ipRows := make([][]string, 0, len(all))
	for _, s := range all {
		ipRows = append(ipRows, []string{
			s.IP,
			fmt.Sprintf("%d", s.Count),
			s.FirstSeen.Format("2006-01-02 15:04:05"),
			s.LastSeen.Format("2006-01-02 15:04:05"),
			fmt.Sprintf("%d", s.FailCount),
		})
	}
	if *top > 0 && *top < len(ipRows) {
		ipRows = ipRows[:*top]
	}
	printTable(
		[]string{"IP Address", "Occurrence Count", "First Seen", "Last Seen", "SSH Failure Count"},
		ipRows,
	)

	fails := make([]*IPStat, 0, len(all))
	for _, s := range all {
		if s.FailCount > 0 {
			fails = append(fails, s)
		}
	}
	sort.Slice(fails, func(i, j int) bool { return fails[i].FailCount > fails[j].FailCount })

	fmt.Printf("\n====== SSH Login Failure Statistics (Sorted by Failure Count in Descending Order) ======\n")
	failRows := make([][]string, 0, len(fails))
	for _, s := range fails {
		failRows = append(failRows, []string{
			s.IP,
			fmt.Sprintf("%d", s.FailCount),
			s.FirstSeen.Format("2006-01-02 15:04:05"),
			s.LastSeen.Format("2006-01-02 15:04:05"),
			topUsers(s.FailedUsers, 5),
		})
	}
	if *failTop > 0 && *failTop < len(failRows) {
		failRows = failRows[:*failTop]
	}
	printTable(
		[]string{"IP Address", "Failure Count", "First Failure", "Last Failure", "Attempted Usernames (Failure Count)"},
		failRows,
	)

	fmt.Printf("\nExecution Time: %s\n", time.Since(start))
}
