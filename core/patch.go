package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/metacubex/mihomo/common/orderedmap"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/config"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
)

type PatchHost struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

type PatchRules struct {
	Override bool     `json:"override"`
	Rules    []string `json:"rules"`
}

type PatchParams struct {
	General            json.RawMessage `json:"general"`
	GeoXUrl            json.RawMessage `json:"geox-url"`
	Hosts              []PatchHost     `json:"hosts"`
	OverrideDns        bool            `json:"override-dns"`
	DnsNodeOverride    bool            `json:"dns-node-override"`
	Dns                json.RawMessage `json:"dns"`
	Ntp                json.RawMessage `json:"ntp"`
	Sniffer            json.RawMessage `json:"sniffer"`
	Experimental       json.RawMessage `json:"experimental"`
	Tunnels            json.RawMessage `json:"tunnels"`
	ProvidersPath      string          `json:"providers-path"`
	NodeExcludeFilter  string          `json:"node-exclude-filter"`
	HealthCheckTimeout int             `json:"health-check-timeout"`
	OverrideRules      *PatchRules     `json:"override-rules"`
	PrependRules       []string        `json:"prepend-rules"`
	DisabledGroups     []string        `json:"disabled-groups"`
	SelectGlobal       bool            `json:"select-global"`
}

const defaultHealthCheckTimeout = 5000

var patchForAndroid = runtime.GOOS == "android"

var protectedProxyNames = []string{"DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS"}

var commonDnsList = []string{
	"223.5.5.5", "223.6.6.6", "119.29.29.29", "1.12.12.12", "120.53.53.53",
	"114.114.114.114", "180.76.76.76", "1.2.4.8", "116.116.116.116",
	"101.226.4.6", "123.125.81.6", "180.184.1.1", "180.184.2.2",
	"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
	"208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
	"76.76.2.0", "76.76.10.0", "185.228.168.9", "185.228.169.9",
	"77.88.8.8", "77.88.8.1", "156.154.70.1", "156.154.71.1",
	"119.28.28.28", "101.6.6.6", "101.101.101.101", "101.102.103.104",
	"185.222.222.222", "45.11.45.11", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
	"9.9.9.10", "9.9.9.11", "149.112.112.10", "149.112.112.11",
	"2400:3200::1", "2400:3200:baba::1", "2402:4e00::", "2400:da00::6666",
	"2606:4700:4700::1111", "2606:4700:4700::1001",
	"2001:4860:4860::8888", "2001:4860:4860::8844",
	"2620:fe::fe", "2620:fe::9", "2620:119:35::35", "2620:119:53::53",
	"2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
	"2a0d:2a00:1::2", "2a0d:2a00:2::2", "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff",
	"2610:a1:1018::1", "2610:a1:1019::1",
	"alidns", "doh.pub", "dot.pub", "dns.pub", "dnspod", "dns.baidu",
	"dns.google", "dns.apple", "cloudflare", "one.one.one.one",
	"quad9", "opendns", "nextdns", "adguard",
	"dns.sb", "twnic", "mullvad", "controld", "cleanbrowsing", "yandex",
	"system",
}

var ruleActionsWithParams = map[string]bool{
	"GEOIP": true, "IP-ASN": true, "SRC-IP-ASN": true, "IP-CIDR": true,
	"IP-CIDR6": true, "IP-SUFFIX": true, "RULE-SET": true,
}

func isRuleActionWithParams(action string) bool {
	switch action {
	case "GEOIP", "IP-ASN", "SRC-IP-ASN", "IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "RULE-SET":
		return true
	default:
		return ruleActionsWithParams[action]
	}
}

func hasPatchValue(data json.RawMessage) bool {
	return len(data) > 0 && string(data) != "null"
}

func applyPatch(raw *config.RawConfig, params *PatchParams) (string, error) {
	defaults := config.DefaultRawConfig()
	if hasPatchValue(params.General) {
		if err := yaml.Unmarshal(params.General, raw); err != nil {
			return "", fmt.Errorf("patch general: %w", err)
		}
		var nullable struct {
			GlobalUA *string `json:"global-ua"`
		}
		if err := json.Unmarshal(params.General, &nullable); err == nil && nullable.GlobalUA == nil {
			raw.GlobalUA = defaults.GlobalUA
		}
	}
	if hasPatchValue(params.GeoXUrl) {
		raw.GeoXUrl = defaults.GeoXUrl
		if err := yaml.Unmarshal(params.GeoXUrl, &raw.GeoXUrl); err != nil {
			return "", fmt.Errorf("patch geox-url: %w", err)
		}
	}
	patchProviderPaths(raw.ProxyProvider, params.ProvidersPath, "proxies")
	patchProviderPaths(raw.RuleProvider, params.ProvidersPath, "rules")
	hostOrder := patchHosts(raw, params.Hosts)
	if err := patchDns(raw, params, defaults, hostOrder); err != nil {
		return "", err
	}
	if hasPatchValue(params.Ntp) {
		raw.NTP = defaults.NTP
		if err := yaml.Unmarshal(params.Ntp, &raw.NTP); err != nil {
			return "", fmt.Errorf("patch ntp: %w", err)
		}
	}
	if patchForAndroid {
		raw.NTP.WriteToSystem = false
	}
	if hasPatchValue(params.Sniffer) {
		raw.Sniffer = defaults.Sniffer
		if err := yaml.Unmarshal(params.Sniffer, &raw.Sniffer); err != nil {
			return "", fmt.Errorf("patch sniffer: %w", err)
		}
	}
	if hasPatchValue(params.Tunnels) {
		var tunnels []LC.Tunnel
		if err := yaml.Unmarshal(params.Tunnels, &tunnels); err != nil {
			return "", fmt.Errorf("patch tunnels: %w", err)
		}
		raw.Tunnels = append(raw.Tunnels, tunnels...)
	}
	if hasPatchValue(params.Experimental) {
		raw.Experimental = defaults.Experimental
		if err := yaml.Unmarshal(params.Experimental, &raw.Experimental); err != nil {
			return "", fmt.Errorf("patch experimental: %w", err)
		}
	}
	patchProxyGroups(raw, params)

	rules := raw.Rule
	hasOverride := params.OverrideRules != nil
	hasPrepend := len(params.PrependRules) > 0
	if hasOverride || hasPrepend {
		if hasOverride && params.OverrideRules.Override {
			total := len(params.PrependRules) + len(params.OverrideRules.Rules)
			merged := make([]string, 0, total)
			merged = append(merged, params.PrependRules...)
			merged = append(merged, params.OverrideRules.Rules...)
			rules = merged
		} else {
			var overrideSlice []string
			if hasOverride {
				overrideSlice = params.OverrideRules.Rules
			}
			total := len(params.PrependRules) + len(overrideSlice) + len(rules)
			merged := make([]string, 0, total)
			merged = append(merged, params.PrependRules...)
			merged = append(merged, overrideSlice...)
			merged = append(merged, rules...)
			rules = merged
		}
	}

	patchProxies(raw)

	if len(params.DisabledGroups) > 0 {
		disabled := make(map[string]bool, len(params.DisabledGroups)*2)
		for _, name := range params.DisabledGroups {
			disabled[name] = true
		}
		raw.ProxyGroup = disableGroups(raw.ProxyGroup, disabled)
		for i, rule := range rules {
			parsed := parseRule(rule)
			if parsed.hasTarget && disabled[parsed.target] {
				parsed.target = "PASS"
				rules[i] = parsed.String()
			}
		}
	}

	global := ""
	if params.SelectGlobal {
		global = selectGlobalTarget(raw.ProxyGroup, rules)
	}
	raw.ProxyGroup = filterGroups(raw.ProxyGroup, func(name string) bool {
		return name != "GLOBAL"
	})
	raw.Rule = rules
	return global, nil
}

func patchProviderPaths(providers map[string]map[string]any, base string, kind string) {
	if len(providers) == 0 {
		return
	}
	dir := filepath.Join(base, kind)
	for _, provider := range providers {
		if provider["type"] != "http" {
			continue
		}
		url, ok := provider["url"].(string)
		if !ok {
			continue
		}
		sum := md5.Sum([]byte(url))
		provider["path"] = filepath.Join(dir, hex.EncodeToString(sum[:]))
	}
}

func patchHosts(raw *config.RawConfig, hosts []PatchHost) []string {
	if raw.Hosts == nil {
		raw.Hosts = make(map[string]any, len(hosts))
	}
	order := make([]string, 0, len(raw.Hosts)+len(hosts))
	for key := range raw.Hosts {
		order = append(order, key)
	}
	sort.Strings(order)
	for _, host := range hosts {
		if _, exist := raw.Hosts[host.Key]; !exist {
			order = append(order, host.Key)
		}
		raw.Hosts[host.Key] = host.Value
	}
	return order
}

func patchDns(raw *config.RawConfig, params *PatchParams, defaults *config.RawConfig, hostOrder []string) error {
	enabled := raw.DNS.Enable
	if params.OverrideDns || !enabled {
		original := raw.DNS
		dns := defaults.DNS
		if hasPatchValue(params.Dns) {
			if err := yaml.Unmarshal(params.Dns, &dns); err != nil {
				return fmt.Errorf("patch dns: %w", err)
			}
		}
		if !enabled {
			ns := make([]string, len(dns.NameServer)+1)
			copy(ns, dns.NameServer)
			ns[len(dns.NameServer)] = "system://"
			dns.NameServer = ns
		}
		raw.DNS = dns
		if params.DnsNodeOverride {
			applyDnsNodeOverride(raw, &original, hostOrder)
		}
	}
	raw.DNS.FallbackFilter.GeoSite = []string{}

	if !patchForAndroid {
		return nil
	}
	listen := raw.DNS.Listen
	if strings.HasSuffix(listen, ":53") {
		raw.DNS.Listen = strings.ReplaceAll(listen, ":53", ":10053")
	}
	noProviders := raw.ProxyProvider == nil && raw.RuleProvider == nil
	hasLocalNameserver := false
	for _, nameserver := range raw.DNS.ProxyServerNameserver {
		if strings.HasPrefix(nameserver, "127.0.0.1") {
			hasLocalNameserver = true
			break
		}
	}
	if noProviders && hasLocalNameserver && strings.HasPrefix(listen, "0.0.0.0") {
		raw.DNS.Listen = "127.0.0.1" + strings.TrimPrefix(listen, "0.0.0.0")
	}
	return nil
}

type domainMatcher struct {
	domains      []string
	exactSet     map[string]struct{}
	dotSuffixSet map[string]struct{}
}

func newDomainMatcher(domains []string) domainMatcher {
	exactSet := make(map[string]struct{}, len(domains))
	dotSuffixSet := make(map[string]struct{}, len(domains)*2)
	for _, d := range domains {
		exactSet[d] = struct{}{}
		for i := 0; i < len(d); i++ {
			if d[i] == '.' {
				dotSuffixSet[d[i+1:]] = struct{}{}
			}
		}
	}
	return domainMatcher{
		domains:      domains,
		exactSet:     exactSet,
		dotSuffixSet: dotSuffixSet,
	}
}

func (m *domainMatcher) match(pattern string) bool {
	if len(m.domains) == 0 {
		return false
	}
	pattern = strings.ToLower(pattern)
	if strings.HasPrefix(pattern, "+.") {
		suffix := pattern[2:]
		if _, ok := m.exactSet[suffix]; ok {
			return true
		}
		_, ok := m.dotSuffixSet[suffix]
		return ok
	}
	if strings.HasPrefix(pattern, ".") {
		suffix := pattern[1:]
		_, ok := m.dotSuffixSet[suffix]
		return ok
	}
	if strings.IndexByte(pattern, '*') == -1 {
		_, ok := m.exactSet[pattern]
		return ok
	}
	patternParts := strings.Split(pattern, ".")
	for _, domain := range m.domains {
		if matchWildcardParts(patternParts, domain) {
			return true
		}
	}
	return false
}

func applyDnsNodeOverride(raw *config.RawConfig, original *config.RawDNS, hostOrder []string) {
	proxyServerNameservers := original.ProxyServerNameserver
	listen := original.Listen
	lowerListen := strings.ToLower(listen)
	rewriteByHosts := false
	if len(proxyServerNameservers) == 1 && listen != "" {
		nameserver := strings.ToLower(proxyServerNameservers[0])
		rewriteByHosts = strings.Contains(nameserver, lowerListen) ||
			(strings.Contains(listen, "0.0.0.0") && strings.Contains(nameserver, "127.0.0.1"))
	}

	seenDomains := make(map[string]bool, len(raw.Proxy))
	proxyDomains := make([]string, 0, len(raw.Proxy))
	collectServers := func() {
		for _, proxy := range raw.Proxy {
			server, ok := proxy["server"].(string)
			if !ok {
				continue
			}
			server = strings.ToLower(server)
			if !seenDomains[server] {
				seenDomains[server] = true
				proxyDomains = append(proxyDomains, server)
			}
		}
	}
	collectServers()
	if rewriteByHosts {
		applyHostsToProxies(raw.Proxy, raw.Hosts, hostOrder)
		collectServers()
	}

	isCommonDns := func(dns string) bool {
		dns = strings.ToLower(dns)
		if rewriteByHosts && strings.Contains(dns, lowerListen) {
			return true
		}
		for _, item := range commonDnsList {
			if strings.Contains(dns, item) {
				return true
			}
		}
		return false
	}

	candCap := len(original.NameServer)
	if !rewriteByHosts {
		candCap += len(proxyServerNameservers)
	}
	seenDns := make(map[string]bool, candCap)
	var privateDns []string
	collectPrivateDns := func(list []string) {
		for _, dns := range list {
			stripped := stripDnsSuffix(dns)
			if stripped == "" || seenDns[stripped] || isCommonDns(stripped) {
				continue
			}
			seenDns[stripped] = true
			privateDns = append(privateDns, stripped)
		}
	}
	collectPrivateDns(original.NameServer)
	if !rewriteByHosts {
		collectPrivateDns(proxyServerNameservers)
	}

	matcher := newDomainMatcher(proxyDomains)

	var originalPolicy *orderedmap.OrderedMap[string, any]
	switch {
	case original.NameServerPolicy == nil || original.NameServerPolicy.Len() == 0:
		originalPolicy = original.ProxyServerNameserverPolicy
	case original.ProxyServerNameserverPolicy == nil || original.ProxyServerNameserverPolicy.Len() == 0:
		originalPolicy = original.NameServerPolicy
	default:
		originalPolicy = orderedmap.New[string, any]()
		for pair := original.NameServerPolicy.Oldest(); pair != nil; pair = pair.Next() {
			originalPolicy.Set(pair.Key, pair.Value)
		}
		for pair := original.ProxyServerNameserverPolicy.Oldest(); pair != nil; pair = pair.Next() {
			originalPolicy.Set(pair.Key, pair.Value)
		}
	}

	proxyServerPolicy := orderedmap.New[string, any]()
	if originalPolicy != nil {
		for pair := originalPolicy.Oldest(); pair != nil; pair = pair.Next() {
			if !matcher.match(pair.Key) {
				continue
			}
			if list, ok := pair.Value.([]any); ok {
				stripped := make([]any, 0, len(list))
				for _, item := range list {
					var text string
					if s, ok := item.(string); ok {
						text = s
					} else {
						text = fmt.Sprint(item)
					}
					if value := stripDnsSuffix(text); value != "" {
						stripped = append(stripped, value)
					}
				}
				if len(stripped) == 0 {
					continue
				}
				proxyServerPolicy.Set(pair.Key, stripped)
				continue
			}
			if s, ok := pair.Value.(string); ok {
				proxyServerPolicy.Set(pair.Key, stripDnsSuffix(s))
			} else {
				proxyServerPolicy.Set(pair.Key, stripDnsSuffix(fmt.Sprint(pair.Value)))
			}
		}
	}

	var proxyFakeIpFilter []string
	for _, pattern := range original.FakeIPFilter {
		if matcher.match(pattern) {
			proxyFakeIpFilter = append(proxyFakeIpFilter, pattern)
		}
	}

	if len(privateDns) > 0 {
		raw.DNS.ProxyServerNameserver = privateDns
	}
	if proxyServerPolicy.Len() > 0 {
		raw.DNS.ProxyServerNameserverPolicy = proxyServerPolicy
	}
	if len(proxyFakeIpFilter) > 0 {
		merged := make([]string, len(raw.DNS.FakeIPFilter)+len(proxyFakeIpFilter))
		copy(merged, raw.DNS.FakeIPFilter)
		copy(merged[len(raw.DNS.FakeIPFilter):], proxyFakeIpFilter)
		raw.DNS.FakeIPFilter = merged
	}
	if rewriteByHosts || len(privateDns) > 0 || proxyServerPolicy.Len() > 0 || len(proxyFakeIpFilter) > 0 {
		log.Infoln("[APP] dns override: private dns %v, node policies %d, fake-ip filters %d, nodes rewritten by hosts: %t", privateDns, proxyServerPolicy.Len(), len(proxyFakeIpFilter), rewriteByHosts)
	}
}

func hostSpecificity(pattern string) int {
	if strings.HasPrefix(pattern, "+.") {
		return 2
	}
	if strings.HasPrefix(pattern, ".") {
		return 1
	}
	if strings.IndexByte(pattern, '*') != -1 {
		return 0
	}
	return 3
}

func hasDotSuffix(domain, suffix string) bool {
	return len(domain) > len(suffix) &&
		domain[len(domain)-len(suffix)-1] == '.' &&
		domain[len(domain)-len(suffix):] == suffix
}

func matchWildcardParts(patternParts []string, domain string) bool {
	start := 0
	for i, part := range patternParts {
		end := strings.IndexByte(domain[start:], '.')
		if i == len(patternParts)-1 {
			if end != -1 {
				return false
			}
			return part == "*" || part == domain[start:]
		}
		if end == -1 {
			return false
		}
		if part != "*" && part != domain[start:start+end] {
			return false
		}
		start += end + 1
	}
	return true
}

func matchDomainPattern(pattern string, domains []string) bool {
	if len(domains) == 0 {
		return false
	}
	pattern = strings.ToLower(pattern)
	if strings.HasPrefix(pattern, "+.") {
		suffix := pattern[2:]
		for _, domain := range domains {
			if domain == suffix || hasDotSuffix(domain, suffix) {
				return true
			}
		}
		return false
	}
	if strings.HasPrefix(pattern, ".") {
		suffix := pattern[1:]
		for _, domain := range domains {
			if hasDotSuffix(domain, suffix) {
				return true
			}
		}
		return false
	}
	if strings.IndexByte(pattern, '*') == -1 {
		for _, domain := range domains {
			if domain == pattern {
				return true
			}
		}
		return false
	}
	patternParts := strings.Split(pattern, ".")
	for _, domain := range domains {
		if matchWildcardParts(patternParts, domain) {
			return true
		}
	}
	return false
}

func stripDnsSuffix(dns string) string {
	index := strings.IndexByte(dns, '#')
	if index == -1 {
		return dns
	}
	suffix := strings.TrimSpace(strings.ToLower(dns[index+1:]))
	if suffix == "direct" || strings.HasPrefix(suffix, "direct&") {
		return dns
	}
	if strings.Contains(suffix, "direct") || strings.Contains(suffix, "直连") {
		return strings.TrimSpace(dns[:index]) + "#DIRECT"
	}
	return dns[:index]
}

func hostTarget(value any) string {
	if list, ok := value.([]any); ok {
		for _, item := range list {
			if text, ok := item.(string); ok && text != "" {
				return text
			}
		}
		return ""
	}
	text, _ := value.(string)
	return text
}

type compiledHostEntry struct {
	specificity int
	suffix      string
	parts       []string
	target      string
}

func (e *compiledHostEntry) matchSingle(domain string) bool {
	switch e.specificity {
	case 2:
		return domain == e.suffix || hasDotSuffix(domain, e.suffix)
	case 1:
		return hasDotSuffix(domain, e.suffix)
	case 0:
		return matchWildcardParts(e.parts, domain)
	default:
		return domain == e.suffix
	}
}

func applyHostsToProxies(proxies []map[string]any, hosts map[string]any, hostOrder []string) {
	if len(proxies) == 0 || len(hostOrder) == 0 {
		return
	}
	var exactHosts map[string]string
	var wildcardEntries []compiledHostEntry

	for _, key := range hostOrder {
		value := hosts[key]
		if list, ok := value.([]any); ok {
			if len(list) == 0 {
				continue
			}
		} else if text, ok := value.(string); !ok || text == "" {
			continue
		}
		target := hostTarget(value)
		spec := hostSpecificity(key)
		lowerKey := strings.ToLower(key)
		if spec == 3 {
			if exactHosts == nil {
				exactHosts = make(map[string]string, len(hostOrder))
			}
			if _, exists := exactHosts[lowerKey]; !exists {
				exactHosts[lowerKey] = target
			}
			continue
		}
		entry := compiledHostEntry{
			specificity: spec,
			target:      target,
		}
		switch spec {
		case 2:
			entry.suffix = lowerKey[2:]
		case 1:
			entry.suffix = lowerKey[1:]
		case 0:
			entry.parts = strings.Split(lowerKey, ".")
		}
		wildcardEntries = append(wildcardEntries, entry)
	}
	if len(exactHosts) == 0 && len(wildcardEntries) == 0 {
		return
	}
	if len(wildcardEntries) > 1 {
		sort.SliceStable(wildcardEntries, func(i, j int) bool {
			return wildcardEntries[i].specificity > wildcardEntries[j].specificity
		})
	}

	cache := make(map[string]string, 16)
	seen := make(map[string]bool, 8)
	resolve := func(server string) string {
		if cached, ok := cache[server]; ok {
			return cached
		}
		for k := range seen {
			delete(seen, k)
		}
		current := strings.ToLower(server)
		result := server
		for !seen[current] {
			seen[current] = true
			target := ""
			if exactHosts != nil {
				target = exactHosts[current]
			}
			if target == "" {
				for i := range wildcardEntries {
					if wildcardEntries[i].matchSingle(current) {
						target = wildcardEntries[i].target
						break
					}
				}
			}
			if target == "" {
				break
			}
			result = target
			current = strings.ToLower(target)
		}
		cache[server] = result
		return result
	}

	for _, proxy := range proxies {
		server, ok := proxy["server"].(string)
		if !ok {
			continue
		}
		if resolved := resolve(server); resolved != server {
			proxy["server"] = resolved
		}
	}
}

func groupName(group map[string]any) (string, bool) {
	name, ok := group["name"].(string)
	return name, ok
}

func filterGroups(groups []map[string]any, keep func(name string) bool) []map[string]any {
	filtered := groups[:0]
	for _, group := range groups {
		if name, ok := groupName(group); ok && !keep(name) {
			continue
		}
		filtered = append(filtered, group)
	}
	return filtered
}

func disableGroups(groups []map[string]any, disabled map[string]bool) []map[string]any {
	for changed := true; changed; {
		changed = false
		for _, group := range groups {
			name, ok := groupName(group)
			if !ok || disabled[name] {
				continue
			}
			proxies, ok := group["proxies"].([]any)
			if !ok || len(proxies) == 0 {
				continue
			}
			firstDisabled := -1
			for i, proxy := range proxies {
				if value, ok := proxy.(string); ok && disabled[value] {
					firstDisabled = i
					break
				}
			}
			if firstDisabled == -1 {
				continue
			}
			kept := make([]any, firstDisabled, len(proxies)-1)
			copy(kept, proxies[:firstDisabled])
			for _, proxy := range proxies[firstDisabled+1:] {
				if value, ok := proxy.(string); ok && disabled[value] {
					continue
				}
				kept = append(kept, proxy)
			}
			group["proxies"] = kept
			if len(kept) == 0 && !hasGroupSource(group) {
				disabled[name] = true
				changed = true
			}
		}
	}
	return filterGroups(groups, func(name string) bool {
		return !disabled[name]
	})
}

func hasGroupSource(group map[string]any) bool {
	if use, ok := group["use"].([]any); ok && len(use) > 0 {
		return true
	}
	if value, ok := group["include-all"].(bool); ok && value {
		return true
	}
	if value, ok := group["include-all-proxies"].(bool); ok && value {
		return true
	}
	if value, ok := group["include-all-providers"].(bool); ok && value {
		return true
	}
	return false
}

func combineExcludeFilter(target map[string]any, filter string) {
	if existing, ok := target["exclude-filter"].(string); ok && existing != "" {
		target["exclude-filter"] = existing + "|" + filter
		return
	}
	target["exclude-filter"] = filter
}

func patchProxyGroups(raw *config.RawConfig, params *PatchParams) {
	filter := params.NodeExcludeFilter
	if raw.ProxyGroup != nil && (filter != "" || params.HealthCheckTimeout != defaultHealthCheckTimeout) {
		var filterRegex *regexp2.Regexp
		if filter != "" {
			filterRegex, _ = regexp2.Compile(filter, regexp2.ECMAScript)
		}
		var protected map[string]bool
		var excluded map[string]bool
		if filterRegex != nil {
			protected = make(map[string]bool, len(protectedProxyNames)+len(raw.ProxyGroup))
			for _, name := range protectedProxyNames {
				protected[name] = true
			}
			for _, group := range raw.ProxyGroup {
				if name, ok := groupName(group); ok {
					protected[name] = true
				}
			}
			excluded = make(map[string]bool, len(raw.Proxy))
		}
		isExcluded := func(name string) bool {
			if result, exist := excluded[name]; exist {
				return result
			}
			matched, _ := filterRegex.MatchString(name)
			excluded[name] = matched
			return matched
		}
		for _, group := range raw.ProxyGroup {
			if group == nil {
				continue
			}
			use, hasUse := group["use"]
			hasUse = hasUse && use != nil
			if filterRegex != nil && hasUse {
				combineExcludeFilter(group, filter)
			}
			if proxies, ok := group["proxies"].([]any); ok && filterRegex != nil {
				firstExcluded := -1
				for i, item := range proxies {
					if name, isString := item.(string); isString && !protected[name] && isExcluded(name) {
						firstExcluded = i
						break
					}
				}
				var filtered []any
				if firstExcluded == -1 {
					filtered = proxies
				} else {
					filtered = make([]any, firstExcluded, len(proxies))
					copy(filtered, proxies[:firstExcluded])
					for _, item := range proxies[firstExcluded+1:] {
						if name, isString := item.(string); isString && !protected[name] && isExcluded(name) {
							continue
						}
						filtered = append(filtered, item)
					}
				}
				useList, useIsList := use.([]any)
				if len(filtered) == 0 && (!hasUse || (useIsList && len(useList) == 0)) {
					if filtered == nil || cap(filtered) == 0 {
						filtered = []any{"DIRECT"}
					} else {
						filtered = append(filtered[:0], "DIRECT")
					}
				}
				group["proxies"] = filtered
			}
			if params.HealthCheckTimeout != defaultHealthCheckTimeout {
				if timeout, exist := group["timeout"]; !exist || timeout == nil {
					group["timeout"] = params.HealthCheckTimeout
				}
			}
		}
		if filterRegex != nil {
			for _, provider := range raw.ProxyProvider {
				if provider == nil {
					continue
				}
				combineExcludeFilter(provider, filter)
			}
		}
	}

	for _, group := range raw.ProxyGroup {
		switch tolerance := group["tolerance"].(type) {
		case float64:
			group["tolerance"] = int(tolerance)
		case string:
			if value, err := strconv.Atoi(strings.TrimSpace(tolerance)); err == nil {
				group["tolerance"] = value
			}
		}
	}
}

func patchProxies(raw *config.RawConfig) {
	fingerprint := raw.GlobalClientFingerprint
	for _, proxy := range raw.Proxy {
		if proxy == nil {
			continue
		}
		proxyType := ""
		if value, exist := proxy["type"]; exist && value != nil {
			if s, ok := value.(string); ok {
				proxyType = s
			} else {
				proxyType = fmt.Sprint(value)
			}
		}
		isTls := proxy["tls"] == true
		supportFingerprint := strings.EqualFold(proxyType, "trojan") ||
			strings.EqualFold(proxyType, "anytls") ||
			(isTls && (strings.EqualFold(proxyType, "vmess") || strings.EqualFold(proxyType, "vless")))
		if supportFingerprint {
			if value, exist := proxy["client-fingerprint"]; !exist || value == nil {
				proxy["client-fingerprint"] = fingerprint
			}
		}
		realityOpts, ok := proxy["reality-opts"].(map[string]any)
		if !ok {
			continue
		}
		switch shortId := realityOpts["short-id"].(type) {
		case int:
			realityOpts["short-id"] = strconv.Itoa(shortId)
		case int64:
			realityOpts["short-id"] = strconv.FormatInt(shortId, 10)
		case uint64:
			realityOpts["short-id"] = strconv.FormatUint(shortId, 10)
		}
	}
}

func selectGlobalTarget(groups []map[string]any, rules []string) string {
	for _, group := range groups {
		name, ok := groupName(group)
		if ok && name != "GLOBAL" && name != "DIRECT" && name != "REJECT" {
			return name
		}
	}
	names := make(map[string]bool, len(groups))
	for _, group := range groups {
		value, exist := group["name"]
		if !exist || value == nil {
			continue
		}
		var name string
		if s, ok := value.(string); ok {
			name = s
		} else {
			name = fmt.Sprint(value)
		}
		if name != "GLOBAL" && name != "DIRECT" && name != "REJECT" {
			names[name] = true
		}
	}
	if len(names) == 0 {
		return ""
	}
	for _, rule := range rules {
		trimmed := strings.TrimSpace(rule)
		if !strings.HasPrefix(trimmed, "MATCH") {
			continue
		}
		parsed := parseRule(trimmed)
		if parsed.action == "MATCH" && parsed.hasTarget && parsed.target != "" &&
			parsed.target != "DIRECT" && parsed.target != "REJECT" && names[parsed.target] {
			return parsed.target
		}
	}
	return ""
}

type parsedRule struct {
	action    string
	content   string
	target    string
	hasTarget bool
	subRule   string
	noResolve bool
	src       bool
}

func parseRule(value string) parsedRule {
	raw := strings.TrimSpace(value)
	rule := parsedRule{}
	for {
		if strings.HasSuffix(raw, ",no-resolve") {
			rule.noResolve = true
			raw = strings.TrimSpace(raw[:len(raw)-len(",no-resolve")])
		} else if strings.HasSuffix(raw, ",src") {
			rule.src = true
			raw = strings.TrimSpace(raw[:len(raw)-len(",src")])
		} else {
			break
		}
	}
	firstComma := strings.IndexByte(raw, ',')
	if firstComma == -1 {
		rule.action = raw
		return rule
	}
	rule.action = strings.TrimSpace(raw[:firstComma])
	rest := strings.TrimSpace(raw[firstComma+1:])
	if rule.action == "MATCH" {
		rule.target = rest
		rule.hasTarget = true
		return rule
	}
	lastComma := strings.LastIndexByte(rest, ',')
	if lastComma == -1 {
		rule.content = rest
		return rule
	}
	rule.content = strings.TrimSpace(rest[:lastComma])
	target := strings.TrimSpace(rest[lastComma+1:])
	if rule.action == "SUB-RULE" {
		rule.subRule = target
	} else {
		rule.target = target
		rule.hasTarget = true
	}
	return rule
}

func (r parsedRule) String() string {
	if r.action == "MATCH" {
		if r.target != "" {
			return r.action + "," + r.target
		}
		return r.action
	}
	var parts [5]string
	n := 1
	parts[0] = r.action
	if r.content != "" {
		parts[n] = r.content
		n++
	}
	target := r.target
	if r.action == "SUB-RULE" {
		target = r.subRule
	}
	if target != "" {
		parts[n] = target
		n++
	}
	if isRuleActionWithParams(r.action) {
		if r.src {
			parts[n] = "src"
			n++
		}
		if r.noResolve {
			parts[n] = "no-resolve"
			n++
		}
	}
	return strings.Join(parts[:n], ",")
}