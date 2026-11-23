package wafop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"time"
)

// commandTimeout 是单次外部命令的执行上限（dpkg-query / cscli / nginx -V 都很短）。
const commandTimeout = 15 * time.Second

// FileMeta 是探测所需的最小文件元信息（不把 os.FileInfo 泄进方法面，便于 mock）。
type FileMeta struct {
	Path  string
	IsDir bool
	Size  int64
	Mode  fs.FileMode
}

// DirEntry 是目录项的最小形状（名字 + 是否目录）。
type DirEntry struct {
	Name  string
	IsDir bool
}

// CommandResult 是外部命令的执行结果。
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Environment 是插件访问宿主环境的唯一入口：所有探测、读取、命令执行都经它。
// 测试注入假实现即可在不碰真实文件系统的前提下覆盖检测/解析/降级路径。
type Environment struct {
	Stat     func(path string) (FileMeta, error)
	ReadDir  func(dir string) ([]DirEntry, error)
	ReadFile func(path string) ([]byte, error)
	// Tail 只读文件尾部 maxBytes 字节；truncated 表示是否发生过截断。
	Tail     func(path string, maxBytes int64) (data []byte, truncated bool, err error)
	LookPath func(name string) (string, bool)
	Run      func(name string, args ...string) (CommandResult, error)
	Euid     func() int
	Now      func() time.Time
}

// OSEnvironment 返回真实宿主环境实现。
func OSEnvironment() Environment {
	return Environment{
		Stat:     osStat,
		ReadDir:  osReadDir,
		ReadFile: os.ReadFile,
		Tail:     osTail,
		LookPath: func(name string) (string, bool) {
			path, err := exec.LookPath(name)
			if err != nil {
				return "", false
			}
			return path, true
		},
		Run:  osRun,
		Euid: os.Geteuid,
		Now:  time.Now,
	}
}

// defaultEnvironment 为 nil 字段补真实实现，避免测试只覆盖部分字段时 panic。
func defaultEnvironment(env Environment) Environment {
	base := OSEnvironment()
	if env.Stat == nil {
		env.Stat = base.Stat
	}
	if env.ReadDir == nil {
		env.ReadDir = base.ReadDir
	}
	if env.ReadFile == nil {
		env.ReadFile = base.ReadFile
	}
	if env.Tail == nil {
		env.Tail = base.Tail
	}
	if env.LookPath == nil {
		env.LookPath = base.LookPath
	}
	if env.Run == nil {
		env.Run = base.Run
	}
	if env.Euid == nil {
		env.Euid = base.Euid
	}
	if env.Now == nil {
		env.Now = base.Now
	}
	return env
}

// osStat 读取文件元信息。
func osStat(path string) (FileMeta, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileMeta{}, err
	}
	return FileMeta{Path: path, IsDir: info.IsDir(), Size: info.Size(), Mode: info.Mode()}, nil
}

// osReadDir 读取目录项（os.ReadDir 已按文件名排序）。
func osReadDir(dir string) ([]DirEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]DirEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, DirEntry{Name: entry.Name(), IsDir: entry.IsDir()})
	}
	return out, nil
}

// osTail 只读文件尾部：文件大于 maxBytes 时 seek 到 size-max 并丢弃首个残行。
func osTail(path string, maxBytes int64) ([]byte, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if info.IsDir() {
		return nil, false, NewOpError(OpFailed, path+" 是目录，不是日志文件")
	}
	truncated := false
	if info.Size() > maxBytes {
		if _, err := file.Seek(info.Size()-maxBytes, io.SeekStart); err != nil {
			return nil, false, err
		}
		truncated = true
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if truncated {
		if index := bytes.IndexByte(data, '\n'); index >= 0 && index+1 < len(data) {
			data = data[index+1:]
		}
	}
	return data, truncated, nil
}

// osRun 执行外部命令：不经 shell；启动失败与超时映射为 OpError。
func osRun(name string, args ...string) (CommandResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := CommandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err == nil {
		return result, nil
	}
	if ctx.Err() != nil {
		return result, NewOpError(OpTimeout, fmt.Sprintf("%s 超过 %s 未完成", name, commandTimeout))
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil // 非零退出码由调用方按语义判断，不当异常
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
		return result, NewOpError(OpNotFound, name+" 不存在")
	}
	if errors.Is(err, fs.ErrPermission) {
		return result, NewOpError(OpPermission, "无权执行 "+name)
	}
	return result, NewOpError(OpFailed, "执行 "+name+" 失败: "+err.Error())
}

// isFault 报告错误是否来自测试注入；注入故障必须冒泡到协议错误，不能被降级吞掉。
func isFault(err error) bool {
	var fault *FaultError
	return errors.As(err, &fault)
}

// isNotExist 报告文件/目录不存在（降级路径的正常分支，不是错误）。
func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist)
}

// isPermission 报告权限类错误（决定是否给 E_NEED_ROOT 提示）。
func isPermission(err error) bool {
	if errors.Is(err, fs.ErrPermission) {
		return true
	}
	var opErr *OpError
	return errors.As(err, &opErr) && opErr.Kind == OpPermission
}

// readSmallFile 读取小文件并设上限，防止把超大日志/规则当配置读。
func readSmallFile(env Environment, path string, limit int64) ([]byte, error) {
	meta, err := env.Stat(path)
	if err != nil {
		return nil, err
	}
	if meta.IsDir {
		return nil, NewOpError(OpFailed, path+" 是目录")
	}
	if meta.Size > limit {
		return nil, NewOpError(OpFailed, fmt.Sprintf("%s 大小 %d 超过上限 %d", path, meta.Size, limit))
	}
	return env.ReadFile(path)
}

// trimLine 把外部输出收敛成单行短文本（错误提示用，不把整段 stderr 塞进结果）。
func trimLine(data []byte, max int) string {
	text := strings.TrimSpace(string(data))
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		text = strings.TrimSpace(text[:index])
	}
	if len(text) > max {
		text = text[:max] + "…"
	}
	return text
}
