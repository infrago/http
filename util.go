package http

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
)

type TOMLBuilder struct {
	mutex sync.RWMutex
	forms map[string][]string
	files map[string][]TOMLFile
	exp   *regexp.Regexp
}
type TOMLFile struct {
	Name   string
	MIME   string
	Buffer io.ReadSeekCloser
}
type TOMLBuffer struct {
	data *bytes.Reader
}

func (buf *TOMLBuffer) Read(p []byte) (n int, err error) {
	return buf.data.Read(p)
}
func (buf *TOMLBuffer) Seek(offset int64, whence int) (int64, error) {
	return buf.data.Seek(offset, whence)
}
func (buf *TOMLBuffer) Close() error {
	return nil
}

func NewTOMLBuilder() *TOMLBuilder {
	this := &TOMLBuilder{
		forms: make(map[string][]string, 0),
		files: make(map[string][]TOMLFile, 0),
		exp:   regexp.MustCompile(`data\:(.*)\;base64,(.*)`),
	}
	return this
}

func (this *TOMLBuilder) Append(key string, vals ...string) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	if _, ok := this.forms[key]; ok == false {
		this.forms[key] = make([]string, 0)
	}

	for _, val := range vals {
		if val != "" {
			if this.fileHandle(key, val) == false {
				this.forms[key] = append(this.forms[key], val)
			}
		}
	}
}
func (this *TOMLBuilder) fileHandle(key string, val string) bool {
	arr := this.exp.FindStringSubmatch(val)
	if len(arr) != 3 {
		return false
	}

	data, err := base64.StdEncoding.DecodeString(arr[2])
	if err != nil {
		return false
	}

	buf := bytes.NewReader(data)
	this.Store(key, "", arr[1], &TOMLBuffer{buf})

	return true
}
func (this *TOMLBuilder) Store(key, name, mime string, buf io.ReadSeekCloser) {
	if _, ok := this.files[key]; ok == false {
		this.files[key] = make([]TOMLFile, 0)
	}
	this.files[key] = append(this.files[key], TOMLFile{name, mime, buf})
}

func (this *TOMLBuilder) Forms() map[string][]string {
	return this.forms
}
func (this *TOMLBuilder) Files() map[string][]TOMLFile {
	return this.files
}

func (this *TOMLBuilder) Build() string {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	// 要记住所有titles的顺序，要不然字段就是乱序就不对了
	titles := []string{""}
	exists := map[string]bool{"": true}

	// data = map[title]map[field][]string{}
	datas := map[string]map[string][]string{}

	lines := make([]string, 0)

	for name, values := range this.forms {
		if len(values) == 0 {
			continue
		}

		name = this.safeTitle(name)

		var title, field string
		if strings.Contains(name, ".") {
			i := strings.LastIndex(name, ".")
			title = name[:i]
			field = name[i+1:]
		} else {
			field = name
		}

		//记录title的顺序
		if _, ok := exists[title]; ok == false {
			exists[title] = true
			titles = append(titles, title)
		}

		if _, ok := datas[title]; ok == false {
			datas[title] = make(map[string][]string, 0)
		}
		if _, ok := datas[title][field]; ok == false {
			datas[title][field] = make([]string, 0)
		}

		//safe value
		for i, value := range values {
			values[i] = this.safeValue(value)
		}

		datas[title][field] = append(datas[title][field], values...)

	}

	for _, title := range titles {
		lines = append(lines, "\n")
		if title != "" {
			lines = append(lines, fmt.Sprintf("[%s]", title))
		}

		fields := datas[title]
		for field, values := range fields {
			var line string
			if len(values) == 1 {
				line = fmt.Sprintf(`%s = "%s"`, field, values[0])
			} else {
				value := strings.Join(values, `", "`)
				line = fmt.Sprintf(`%s = ["%s"]`, field, value)
			}
			lines = append(lines, line)
		}
	}

	return strings.Join(lines, "\n")
}
func (this *TOMLBuilder) safeTitle(title string) string {
	title = strings.Replace(title, "\r", "", -1)
	title = strings.Replace(title, "\n", "", -1)
	title = strings.Replace(title, "[", "", -1)
	title = strings.Replace(title, "]", "", -1)
	return title
}

func (this *TOMLBuilder) safeValue(val string) string {
	val = strings.Replace(val, "\r", "", -1)
	val = strings.Replace(val, "\n", "\\n", -1)
	val = strings.Replace(val, `"`, `\"`, -1)
	return val
}
