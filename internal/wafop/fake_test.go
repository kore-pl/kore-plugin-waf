package wafop

import (
	"bytes"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// fakeEnv 是内存文件系统 + 可编程命令执行环境，用于在不起真实引擎的前提下
// 覆盖检测、规则统计、日志解析、降级与提权拒绝路径。
type fakeEnv struct {
	files    map[string][]byte
	dirs     map[string]bool
	entries  map[string][]DirEntry
	lookPath map[string]string
	run      func(name string, args ...string) (CommandResult, error)
	euid     int
	now      time.Time
}

// newFakeEnv 构造空环境：root 身份、固定时间、无任何命令。
func newFakeEnv() *fakeEnv {
	return &fakeEnv{
		files:    map[string][]byte{},
		dirs:     map[string]bool{},
		entries:  map[string][]DirEntry{},
		lookPath: map[string]string{},
		euid:     0,
		now:      time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC),
	}
}

// addFile 写入文件并自动登记父目录链。
func (f *fakeEnv) addFile(filePath, content string) {
	f.files[filePath] = []byte(content)
	f.ensureDir(path.Dir(filePath))
	f.addEntry(path.Dir(filePath), DirEntry{Name: path.Base(filePath), IsDir: false})
}

// addDir 创建目录并自动登记父目录链。
func (f *fakeEnv) addDir(dir string) {
	f.dirs[dir] = true
	parent := path.Dir(dir)
	if parent != "/" && parent != "." {
		f.ensureDir(parent)
		f.addEntry(parent, DirEntry{Name: path.Base(dir), IsDir: true})
	}
}

// ensureDir 递归创建目录（不产生重复目录项）。
func (f *fakeEnv) ensureDir(dir string) {
	if dir == "/" || dir == "." || dir == "" || f.dirs[dir] {
		return
	}
	f.dirs[dir] = true
	parent := path.Dir(dir)
	if parent != "/" && parent != "." {
		f.ensureDir(parent)
		f.addEntry(parent, DirEntry{Name: path.Base(dir), IsDir: true})
	}
}

// addEntry 去重登记目录项。
func (f *fakeEnv) addEntry(dir string, entry DirEntry) {
	for _, existing := range f.entries[dir] {
		if existing.Name == entry.Name && existing.IsDir == entry.IsDir {
			return
		}
	}
	f.entries[dir] = append(f.entries[dir], entry)
}

// setCommand 注册命令（LookPath 命中后 Run 用给定函数）。
func (f *fakeEnv) setCommand(name string, run func(args ...string) (CommandResult, error)) {
	f.lookPath[name] = "/usr/bin/" + name
	if f.run == nil {
		f.run = func(_ string, args ...string) (CommandResult, error) { return run(args...) }
		return
	}
	previous := f.run
	f.run = func(cmd string, args ...string) (CommandResult, error) {
		if cmd == name {
			return run(args...)
		}
		return previous(cmd, args...)
	}
}

// env 返回接入类型环境的视图。
func (f *fakeEnv) env() Environment {
	return Environment{
		Stat: func(p string) (FileMeta, error) {
			if data, ok := f.files[p]; ok {
				return FileMeta{Path: p, IsDir: false, Size: int64(len(data)), Mode: 0o644}, nil
			}
			if f.dirs[p] {
				return FileMeta{Path: p, IsDir: true, Mode: fs.ModeDir | 0o755}, nil
			}
			return FileMeta{}, fs.ErrNotExist
		},
		ReadDir: func(dir string) ([]DirEntry, error) {
			entries, ok := f.entries[dir]
			if !ok {
				if f.dirs[dir] {
					return []DirEntry{}, nil
				}
				return nil, fs.ErrNotExist
			}
			out := append([]DirEntry{}, entries...)
			sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
			return out, nil
		},
		ReadFile: func(p string) ([]byte, error) {
			data, ok := f.files[p]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return append([]byte{}, data...), nil
		},
		Tail: func(p string, maxBytes int64) ([]byte, bool, error) {
			data, ok := f.files[p]
			if !ok {
				return nil, false, fs.ErrNotExist
			}
			if int64(len(data)) <= maxBytes {
				return append([]byte{}, data...), false, nil
			}
			tail := data[int64(len(data))-maxBytes:]
			if index := bytes.IndexByte(tail, '\n'); index >= 0 && index+1 < len(tail) {
				tail = tail[index+1:]
			}
			return append([]byte{}, tail...), true, nil
		},
		LookPath: func(name string) (string, bool) {
			p, ok := f.lookPath[name]
			return p, ok
		},
		Run: func(name string, args ...string) (CommandResult, error) {
			if f.run != nil {
				return f.run(name, args...)
			}
			return CommandResult{ExitCode: 127}, nil
		},
		Euid: func() int { return f.euid },
		Now:  func() time.Time { return f.now },
	}
}

// fakeRoot 记录 root-action 调用并返回预设结果。
type fakeRoot struct {
	calls  []string
	handle func(actionID string, args []string) ([]byte, int, error)
}

func (f *fakeRoot) Call(actionID string, args []string) ([]byte, int, error) {
	f.calls = append(f.calls, actionID+" "+strings.Join(args, " "))
	if f.handle != nil {
		return f.handle(actionID, args)
	}
	return nil, 0, nil
}
