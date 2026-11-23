package wafop

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// 引擎探测顺序：modsecurity 信号最明确（文件 + 模块 + nginx -V 三重证据），
// 其后是 naxsi / coraza / crowdsec。auto 模式下取第一个命中的引擎。
var autoEngineOrder = []string{EngineModSecurity, EngineNaxsi, EngineCoraza, EngineCrowdSec}

// 模块文件候选：不同发行版/安装方式落点不同，全部作为证据而不是硬依赖。
var (
	modsecModulePaths = []string{
		"/usr/lib/nginx/modules/ngx_http_modsecurity_module.so",
		"/usr/lib/nginx/modules/ngx_http_modsecurity.so",
		"/usr/lib/apache2/modules/mod_security2.so",
		"/usr/local/modsecurity/lib/libmodsecurity.so",
	}
	naxsiModulePaths = []string{
		"/usr/lib/nginx/modules/ngx_http_naxsi_module.so",
		"/etc/nginx/modules-enabled/50-mod-http-naxsi.conf",
	}
	corazaModulePaths = []string{
		"/usr/lib/nginx/modules/ngx_http_coraza_module.so",
		"/usr/lib/coraza/libcoraza.so",
	}
)

// secRuleEngineRe 匹配 ModSecurity / Coraza 的引擎模式指令（行首允许缩进）。
var secRuleEngineRe = regexp.MustCompile(`(?m)^[ \t]*SecRuleEngine[ \t]+([A-Za-z]+)`)

// naxsiLearningRe / naxsiEnabledRe 匹配 Naxsi 的两种运行模式指令。
var (
	naxsiLearningRe = regexp.MustCompile(`(?m)^[ \t]*LearningMode[ \t]*;`)
	naxsiEnabledRe  = regexp.MustCompile(`(?m)^[ \t]*SecRulesEnabled[ \t]*;`)
)

// crowdsecVersionRe 从 cscli version 输出里抽版本号。
var crowdsecVersionRe = regexp.MustCompile(`(?i)version:[ \t]*v?([0-9][0-9A-Za-z.\-+_]*)`)

// Detect 探测可用引擎。返回 error 只用于测试注入的故障；真实环境缺失一律降级为
// Found=false 的证据，不报错。
func Detect(env Environment, settings Settings) (Detection, error) {
	env = defaultEnvironment(env)
	s := settings.normalized()
	nginxEvidence, err := nginxVersionEvidence(env)
	if err != nil {
		return Detection{}, err
	}
	candidates := autoEngineOrder
	if s.Engine != "auto" {
		candidates = []string{s.Engine}
	}
	probes := make([]Probe, 0, len(candidates))
	for _, engine := range candidates {
		detection, probe, err := detectOne(env, s, engine, nginxEvidence)
		if err != nil {
			return Detection{}, err
		}
		probes = append(probes, probe)
		if detection.Found {
			detection.Probed = probes
			return detection, nil
		}
		if s.Engine != "auto" && engine != EngineCrowdSec {
			// 显式选择引擎且配置了存在的自定义目录/日志时，按「用户声明的安装路径」认定，
			// 用于非标准安装；evidence 会写清依据，不冒充默认路径探测成功。
			note, ok, err := configuredEvidence(env, s)
			if err != nil {
				return Detection{}, err
			}
			if ok {
				mode, modeSource, err := configuredMode(env, s, engine)
				if err != nil {
					return Detection{}, err
				}
				detection.Found = true
				detection.Mode = mode
				detection.ModeSource = modeSource
				probes[len(probes)-1].Found = true
				probes[len(probes)-1].Evidence = note
				detection.Probed = probes
				return detection, nil
			}
		}
	}
	return Detection{Engine: EngineNone, Mode: ModeOff, ModeSource: "default", Probed: probes}, nil
}

// detectOne 探测单个引擎；未命中时返回 Found=false 与证据说明。
func detectOne(env Environment, s Settings, engine, nginxEvidence string) (Detection, Probe, error) {
	switch engine {
	case EngineModSecurity:
		return detectModSecurity(env, s, nginxEvidence)
	case EngineNaxsi:
		return detectNaxsi(env, s, nginxEvidence)
	case EngineCoraza:
		return detectCoraza(env, s, nginxEvidence)
	case EngineCrowdSec:
		return detectCrowdSec(env)
	}
	return Detection{Engine: EngineNone, Mode: ModeOff}, Probe{Engine: engine, Evidence: "未知引擎"}, nil
}

// nginxVersionEvidence 执行 `nginx -V`（输出在 stderr），返回小写合并文本。
//
// nginx -V 是只读命令；nginx 不存在或执行失败时返回空串（不是错误），
// 但测试注入的故障必须冒泡。
func nginxVersionEvidence(env Environment) (string, error) {
	if _, ok := env.LookPath("nginx"); !ok {
		return "", nil
	}
	result, err := env.Run("nginx", "-V")
	if err != nil {
		if isFault(err) {
			return "", err
		}
		return "", nil
	}
	combined := string(result.Stdout) + string(result.Stderr)
	return strings.ToLower(combined), nil
}

// detectModSecurity 探测 modsecurity：配置目录 / 模块文件 / nginx -V 三重证据。
func detectModSecurity(env Environment, s Settings, nginxEvidence string) (Detection, Probe, error) {
	evidence := make([]string, 0, 3)
	for _, path := range []string{"/etc/modsecurity", "/etc/nginx/modsecurity.conf"} {
		found, note, err := probePath(env, path)
		if err != nil {
			return Detection{}, Probe{}, err
		}
		if found {
			evidence = append(evidence, note)
		}
	}
	for _, path := range modsecModulePaths {
		found, note, err := probePath(env, path)
		if err != nil {
			return Detection{}, Probe{}, err
		}
		if found {
			evidence = append(evidence, note)
		}
	}
	if strings.Contains(nginxEvidence, "modsecurity") {
		evidence = append(evidence, "nginx -V 输出含 modsecurity 模块")
	}
	if len(evidence) == 0 {
		return Detection{Engine: EngineModSecurity, Mode: ModeOff}, Probe{
			Engine: EngineModSecurity, Evidence: "未发现 /etc/modsecurity、modsecurity 模块文件或 nginx modsecurity 模块",
		}, nil
	}
	version, versionSource, err := packageVersion(env, "libmodsecurity3", "libmodsecurity")
	if err != nil {
		return Detection{}, Probe{}, err
	}
	mode, modeSource, err := scanSecRuleEngine(env, modsecConfFiles(env, s))
	if err != nil {
		return Detection{}, Probe{}, err
	}
	return Detection{
		Engine:        EngineModSecurity,
		Found:         true,
		Version:       version,
		VersionSource: versionSource,
		Mode:          mode,
		ModeSource:    modeSource,
		CRSVersion:    crsVersion(env),
	}, Probe{Engine: EngineModSecurity, Found: true, Evidence: strings.Join(evidence, "；")}, nil
}

// detectNaxsi 探测 naxsi：nginx 模块文件或 nginx -V 里出现 naxsi。
func detectNaxsi(env Environment, s Settings, nginxEvidence string) (Detection, Probe, error) {
	evidence := make([]string, 0, 3)
	for _, path := range []string{"/etc/nginx/naxsi.rules", "/etc/nginx/naxsi_core.rules"} {
		found, note, err := probePath(env, path)
		if err != nil {
			return Detection{}, Probe{}, err
		}
		if found {
			evidence = append(evidence, note)
		}
	}
	for _, path := range naxsiModulePaths {
		found, note, err := probePath(env, path)
		if err != nil {
			return Detection{}, Probe{}, err
		}
		if found {
			evidence = append(evidence, note)
		}
	}
	if strings.Contains(nginxEvidence, "naxsi") {
		evidence = append(evidence, "nginx -V 输出含 naxsi 模块")
	}
	if len(evidence) == 0 {
		return Detection{Engine: EngineNaxsi, Mode: ModeOff}, Probe{
			Engine: EngineNaxsi, Evidence: "未发现 naxsi 模块文件或 nginx -V 中的 naxsi 模块",
		}, nil
	}
	version, versionSource, err := packageVersion(env, "libnginx-mod-http-naxsi", "nginx-mod-http-naxsi")
	if err != nil {
		return Detection{}, Probe{}, err
	}
	mode, modeSource, err := scanNaxsiMode(env, nginxConfFiles(env))
	if err != nil {
		return Detection{}, Probe{}, err
	}
	return Detection{
		Engine: EngineNaxsi, Found: true, Version: version, VersionSource: versionSource,
		Mode: mode, ModeSource: modeSource,
	}, Probe{Engine: EngineNaxsi, Found: true, Evidence: strings.Join(evidence, "；")}, nil
}

// detectCoraza 探测 coraza：独立二进制、nginx 模块或配置目录。
func detectCoraza(env Environment, s Settings, nginxEvidence string) (Detection, Probe, error) {
	evidence := make([]string, 0, 3)
	corazaBinary := ""
	for _, name := range []string{"coraza", "coraza-caddy"} {
		if path, ok := env.LookPath(name); ok {
			corazaBinary = path
			evidence = append(evidence, "找到可执行文件 "+path)
			break
		}
	}
	found, note, err := probePath(env, "/etc/coraza")
	if err != nil {
		return Detection{}, Probe{}, err
	}
	if found {
		evidence = append(evidence, note)
	}
	for _, path := range corazaModulePaths {
		found, note, err := probePath(env, path)
		if err != nil {
			return Detection{}, Probe{}, err
		}
		if found {
			evidence = append(evidence, note)
		}
	}
	if strings.Contains(nginxEvidence, "coraza") {
		evidence = append(evidence, "nginx -V 输出含 coraza 模块")
	}
	if len(evidence) == 0 {
		return Detection{Engine: EngineCoraza, Mode: ModeOff}, Probe{
			Engine: EngineCoraza, Evidence: "未发现 coraza 二进制、模块文件或 /etc/coraza",
		}, nil
	}
	version, versionSource := "", "unknown"
	if corazaBinary != "" {
		version, versionSource, err = binaryVersion(env, corazaBinary, "version", "--version")
		if err != nil {
			return Detection{}, Probe{}, err
		}
	}
	mode, modeSource, err := scanSecRuleEngine(env, corazaConfFiles(env, s))
	if err != nil {
		return Detection{}, Probe{}, err
	}
	return Detection{
		Engine: EngineCoraza, Found: true, Version: version, VersionSource: versionSource,
		Mode: mode, ModeSource: modeSource,
	}, Probe{Engine: EngineCoraza, Found: true, Evidence: strings.Join(evidence, "；")}, nil
}

// detectCrowdSec 探测 crowdsec：cscli 存在且 `cscli version` 成功。
func detectCrowdSec(env Environment) (Detection, Probe, error) {
	path, ok := env.LookPath("cscli")
	if !ok {
		return Detection{Engine: EngineCrowdSec, Mode: ModeOff}, Probe{
			Engine: EngineCrowdSec, Evidence: "PATH 中未找到 cscli",
		}, nil
	}
	result, err := env.Run("cscli", "version")
	if err != nil {
		if isFault(err) {
			return Detection{}, Probe{}, err
		}
		return Detection{Engine: EngineCrowdSec, Mode: ModeOff}, Probe{
			Engine: EngineCrowdSec, Evidence: "cscli 存在但 `cscli version` 执行失败: " + err.Error(),
		}, nil
	}
	if result.ExitCode != 0 {
		return Detection{Engine: EngineCrowdSec, Mode: ModeOff}, Probe{
			Engine: EngineCrowdSec, Evidence: "cscli version 退出码 " + strconv.Itoa(result.ExitCode),
		}, nil
	}
	version := ""
	if match := crowdsecVersionRe.FindSubmatch(result.Stdout); len(match) > 1 {
		version = string(match[1])
	}
	mode := ModeDetection
	if bouncers, err := crowdsecBouncerCount(env); err != nil {
		if isFault(err) {
			return Detection{}, Probe{}, err
		}
	} else if bouncers > 0 {
		mode = ModeOn
	}
	return Detection{
		Engine: EngineCrowdSec, Found: true, Version: version,
		VersionSource: versionSourceFor(version), Mode: mode, ModeSource: "heuristic",
	}, Probe{Engine: EngineCrowdSec, Found: true, Evidence: "cscli 可用（" + path + "）"}, nil
}

// crowdsecBouncerCount 统计已注册 bouncer 数：有 bouncer 才真正执行拦截，
// 没有则只产生告警（detection）。
func crowdsecBouncerCount(env Environment) (int, error) {
	result, err := env.Run("cscli", "bouncers", "list", "-o", "json")
	if err != nil {
		return 0, err
	}
	if result.ExitCode != 0 {
		return 0, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(result.Stdout, &items); err != nil {
		return 0, nil // 输出格式变化不影响探测成立
	}
	return len(items), nil
}

// binaryVersion 依次尝试 `bin <arg>` 取版本；命令不存在/非零退出时返回 unknown。
func binaryVersion(env Environment, binary string, attempts ...string) (string, string, error) {
	for _, flag := range attempts {
		result, err := env.Run(binary, flag)
		if err != nil {
			if isFault(err) {
				return "", "", err
			}
			continue
		}
		if result.ExitCode != 0 {
			continue
		}
		line := trimLine(result.Stdout, 64)
		if line == "" {
			line = trimLine(result.Stderr, 64)
		}
		if line != "" {
			return line, "command", nil
		}
	}
	return "", "unknown", nil
}

// configuredMode 按引擎扫描模式指令，用于「配置目录声明安装路径」的识别分支。
func configuredMode(env Environment, s Settings, engine string) (string, string, error) {
	switch engine {
	case EngineNaxsi:
		return scanNaxsiMode(env, nginxConfFiles(env))
	case EngineCoraza:
		return scanSecRuleEngine(env, corazaConfFiles(env, s))
	default:
		return scanSecRuleEngine(env, modsecConfFiles(env, s))
	}
}

// configuredEvidence 检查配置里的规则目录/日志路径是否存在；用于非标准安装路径。
func configuredEvidence(env Environment, s Settings) (string, bool, error) {
	paths := make([]string, 0, len(s.RulesDirs)+len(s.LogPaths))
	paths = append(paths, s.RulesDirs...)
	paths = append(paths, s.LogPaths...)
	for _, path := range paths {
		found, note, err := probePath(env, path)
		if err != nil {
			return "", false, err
		}
		if found {
			return "配置声明的路径存在：" + note, true, nil
		}
	}
	return "", false, nil
}

// probePath 报告路径是否存在，并返回证据文本；真实错误吞成「未发现」，
// 注入故障必须冒泡。
func probePath(env Environment, path string) (bool, string, error) {
	meta, err := env.Stat(path)
	if err != nil {
		if isFault(err) {
			return false, "", err
		}
		if isNotExist(err) {
			return false, "", nil
		}
		if isPermission(err) {
			return true, path + "（存在但无读取权限）", nil
		}
		return false, "", nil
	}
	if meta.IsDir {
		return true, path + " 目录存在", nil
	}
	return true, path + " 存在", nil
}

// packageVersion 用 dpkg-query / rpm 查包版本；两者都没有或查不到返回 unknown。
func packageVersion(env Environment, packages ...string) (string, string, error) {
	if _, ok := env.LookPath("dpkg-query"); ok {
		for _, pkg := range packages {
			result, err := env.Run("dpkg-query", "-W", "-f=${Version}", pkg)
			if err != nil {
				if isFault(err) {
					return "", "", err
				}
				continue
			}
			if result.ExitCode == 0 {
				if version := trimLine(result.Stdout, 64); version != "" {
					return version, "command", nil
				}
			}
		}
	}
	if _, ok := env.LookPath("rpm"); ok {
		for _, pkg := range packages {
			result, err := env.Run("rpm", "-q", "--qf", "%{VERSION}", pkg)
			if err != nil {
				if isFault(err) {
					return "", "", err
				}
				continue
			}
			if result.ExitCode == 0 {
				if version := trimLine(result.Stdout, 64); version != "" {
					return version, "command", nil
				}
			}
		}
	}
	return "", "unknown", nil
}

// crsVersion 读 OWASP CRS 的 VERSION 文件；不存在返回空串。
func crsVersion(env Environment) string {
	data, err := readSmallFile(env, "/usr/share/modsecurity-crs/VERSION", 4096)
	if err != nil {
		return ""
	}
	return trimLine(data, 32)
}

// versionSourceFor 把「有没有版本号」映射为来源枚举。
func versionSourceFor(version string) string {
	if version == "" {
		return "unknown"
	}
	return "command"
}

// modsecConfFiles 返回参与模式判定的 ModSecurity 配置文件（后读的覆盖先读的）。
func modsecConfFiles(env Environment, s Settings) []string {
	files := []string{"/etc/modsecurity/modsecurity.conf"}
	files = append(files, listFiles(env, "/etc/modsecurity", ".conf")...)
	files = append(files, "/etc/nginx/modsecurity.conf")
	files = append(files, listFiles(env, "/etc/nginx/conf.d", ".conf")...)
	files = append(files, modeConfigPath(s, EngineModSecurity))
	return dedupe(files)
}

// corazaConfFiles 返回参与模式判定的 Coraza 配置文件。
func corazaConfFiles(env Environment, s Settings) []string {
	files := []string{"/etc/coraza/coraza.conf"}
	files = append(files, listFiles(env, "/etc/coraza", ".conf")...)
	files = append(files, modeConfigPath(s, EngineCoraza))
	return dedupe(files)
}

// nginxConfFiles 返回用于 Naxsi 模式判定的 nginx 配置。
func nginxConfFiles(env Environment) []string {
	files := []string{"/etc/nginx/nginx.conf"}
	files = append(files, listFiles(env, "/etc/nginx/conf.d", ".conf")...)
	files = append(files, listFiles(env, "/etc/nginx/sites-enabled", "")...)
	return dedupe(files)
}

// modeConfigPath 返回 kore 管理的模式包含文件；未配置时按引擎取缺省。
func modeConfigPath(s Settings, engine string) string {
	if s.ModeConfigPath != "" {
		return s.ModeConfigPath
	}
	if engine == EngineCoraza {
		return DefaultCorazaModeConfigPath
	}
	return DefaultModeConfigPath
}

// listFiles 列出目录下指定后缀的文件（非递归、按名排序）；目录不存在返回空。
// 真实错误一律视为空列表（探测降级），注入故障必须冒泡由调用方处理——
// 因此这里只返回文件名，错误在读取阶段冒泡。
func listFiles(env Environment, dir, suffix string) []string {
	entries, err := env.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir || strings.HasPrefix(entry.Name, ".") {
			continue
		}
		if suffix != "" && !strings.HasSuffix(entry.Name, suffix) {
			continue
		}
		names = append(names, entry.Name)
	}
	sort.Strings(names)
	files := make([]string, 0, len(names))
	for _, name := range names {
		files = append(files, strings.TrimSuffix(dir, "/")+"/"+name)
	}
	return files
}

// scanSecRuleEngine 读配置文件并返回最后一次出现的 SecRuleEngine 模式。
func scanSecRuleEngine(env Environment, files []string) (string, string, error) {
	mode := ModeOff
	source := "default"
	for _, path := range files {
		data, err := readSmallFile(env, path, 1<<20)
		if err != nil {
			if isFault(err) {
				return "", "", err
			}
			continue
		}
		for _, match := range secRuleEngineRe.FindAllSubmatch(data, -1) {
			switch strings.ToLower(string(match[1])) {
			case "on":
				mode = ModeOn
			case "off":
				mode = ModeOff
			case "detectiononly":
				mode = ModeDetection
			default:
				continue
			}
			source = path
		}
	}
	return mode, source, nil
}

// scanNaxsiMode 读 nginx 配置判定 Naxsi 模式：LearningMode 优先（只记录），
// 否则 SecRulesEnabled 视为拦截，都没有则关闭。
func scanNaxsiMode(env Environment, files []string) (string, string, error) {
	mode := ModeOff
	source := "default"
	for _, path := range files {
		data, err := readSmallFile(env, path, 1<<20)
		if err != nil {
			if isFault(err) {
				return "", "", err
			}
			continue
		}
		if naxsiLearningRe.Match(data) {
			mode = ModeDetection
			source = path
		} else if naxsiEnabledRe.Match(data) {
			mode = ModeOn
			source = path
		}
	}
	return mode, source, nil
}

// dedupe 保序去重（空串剔除）。
func dedupe(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
