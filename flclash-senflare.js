/**
 * Senflare Link Lite → FlClash / Mihomo 覆写脚本
 * ============================================================================
 * 来源：_worker.js (Senflare Link Lite v4.5.2) 的 buildYamlSubConfig / YamlBase /
 *       RouteProviders / UserAdDomains / AiDomains / FakeIpFilter / DefaultDoh
 * 用法：FlClash → 配置 → 覆写 → 新建 → 类型选 "JavaScript"，粘贴本文件内容，
 *       然后在订阅上启用该覆写。脚本收到订阅解析后的 config，改完原样 return。
 *
 * 说明：
 *   1. 节点（config.proxies）完全不动，保留订阅原有节点。
 *   2. proxy-groups / rules / rule-providers / dns / sniffer / hosts 由本脚本接管，
 *      等价于原来 worker 自己吐出来的那份 clash 配置。
 *   3. 策略组用 include-all 自动纳入订阅里所有节点，不写死节点名，换机场不用改脚本。
 * ============================================================================
 */

// ==================== 可调参数 ====================

var CFG = {
  // 规则集主源：MetaCubeX meta-rules-dat 的 mrs，走 testingcf（jsDelivr 的 CF 加速域名，
  // 与 worker 源码里的 MetaCubeXMrs[1] 完全一致）。raw.githubusercontent.com 国内直连必超时，
  // 不要用。备选（同样实测可用）：
  //   https://ghproxy.net/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo
  //   https://gh-proxy.com/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo
  mrsBase: 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo',

  // ads 规则集原版走 DustinWin 的 mihomo-ruleset 分支（覆盖面比 geosite category-ads-all 大）
  adsUrl: 'https://testingcf.jsdelivr.net/gh/DustinWin/ruleset_geodata@mihomo-ruleset/ads.mrs',

  // 策略组图标
  iconBase: 'https://cdn.jsdmirror.com/gh/AIsouler/MyClash@main/Icons/svg/',

  // DoH：留空 = 自动双 DoH（阿里 + 腾讯），也可填单个 URL 强制指定
  doh: '',

  // 自定义分流（对应 worker 面板里的「直连规则 / 代理规则」两个输入框）
  directDomains: ['senflarelink.de5.net'],
  proxyDomains: ['z.ai'],

  // 是否生成 ⏱️ 最低延迟 / ⚖️ 负载均衡 / 🛟 故障转移 三张自动策略组
  autoGroups: true,

  // 是否开启 IPv6
  ipv6: true,

  // 是否强制接管 TUN（默认 false，交给客户端 UI 控制）
  forceTun: false,

  // include-all 时要剔除的节点名（机场信息节点 / 内建节点）
  excludeFilter: '直连|拦截|^DIRECT$|^REJECT$|剩余流量|套餐到期|距离下次|过期时间|官网|Expire|Traffic|重置',
};

// ==================== 规则数据（照搬 worker） ====================

/** [RULE-SET 引用名, mrs 相对路径, 目标, 分段] —— 分段 = 规则出现顺序 */
var ROUTE_PROVIDERS = [
  ['geoip-private', 'geoip/private.mrs', 'DIRECT,no-resolve', 'private'],
  ['geosite-private', 'geosite/private.mrs', 'DIRECT', 'private'],
  ['ads', 'ads.mrs', '🚫 广告拦截', 'ads'],
  ['geosite-category-ads-all', 'geosite/category-ads-all.mrs', '🚫 广告拦截', 'ads'],
  ['geosite-category-ai-!cn', 'geosite/category-ai-!cn.mrs', '🤖 AI 助手', 'ai'],
  ['geosite-github', 'geosite/github.mrs', '🚀 节点选择', 'proxy'],
  ['geosite-google', 'geosite/google.mrs', '🚀 节点选择', 'proxy'],
  ['geosite-category-games@cn', 'geosite/category-games@cn.mrs', 'DIRECT', 'direct'],
  ['geosite-epicgames', 'geosite/epicgames.mrs', 'DIRECT', 'direct'],
  ['geosite-nvidia@cn', 'geosite/nvidia@cn.mrs', 'DIRECT', 'direct'],
  ['geosite-cn', 'geosite/cn.mrs', 'DIRECT', 'direct'],
  ['geoip-cn', 'geoip/cn.mrs', 'DIRECT', 'direct'],
  ['geosite-apple-cn', 'geosite/apple-cn.mrs', 'DIRECT', 'direct'],
  ['geosite-microsoft', 'geosite/microsoft.mrs', 'DIRECT', 'direct'],
  ['douyin', 'geosite/douyin.mrs', '', 'douyin'],
  ['geolocation-cn', 'geosite/geolocation-cn.mrs', '', 'geolocation-cn'],
];

/** fake-ip 白名单：这些域名走真实解析 */
var FAKE_IP_FILTER = ['+.lan', '+.local', 'time.nist.gov', '+.pool.ntp.org', 'time.*.com', 'ntp.*.com', 'rule-set:geolocation-cn'];

/** 默认双 DoH */
var DEFAULT_DOH = ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'];

/** 追踪 / 包扫描 API 拦截 */
var USER_AD_DOMAINS = ['miav-cse.avlyun.com', 'miui-fxcse.avlyun.com', 'a0.app.xiaomi.com', 'api.installer.xiaomi.com'];

/** AI 域名（补漏 category-ai-!cn 覆盖不到的） */
var AI_DOMAINS = ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'anthropic.com', 'claude.ai', 'gemini.google.com', 'aistudio.google.com', 'ai.google.dev', 'perplexity.ai', 'copilot.microsoft.com', 'cursor.com', 'midjourney.com', 'poe.com', 'character.ai', 'x.ai', 'grok.com', 'mistral.ai', 'cohere.com', 'elevenlabs.io', 'huggingface.co'];

/** 分段 → RULE-SET 行 */
function segRules(seg) {
  return ROUTE_PROVIDERS
    .filter(function (r) { return r[3] === seg; })
    .map(function (r) { return 'RULE-SET,' + r[0] + ',' + r[2]; });
}

/** 宽松域名列表解析（同 worker 的 parseDomainList） */
function parseDomainList(raw) {
  var seen = {};
  return String(raw || '').split(/[\r\n,，、]+/).map(function (t) { return t.trim(); })
    .filter(function (t) { return /^[a-z0-9*-]+(\.[a-z0-9*-]+)+$/.test(t.toLowerCase()); })
    .filter(function (t) { if (seen[t]) return false; seen[t] = 1; return true; });
}

/** mrs 地址 */
function mrsUrl(file) {
  if (file === 'ads.mrs') return CFG.adsUrl;
  return CFG.mrsBase + '/' + file;
}

// ==================== 主入口 ====================

function main(config) {
  config = config || {};

  var icon = CFG.iconBase;
  var doh = String(CFG.doh || '').indexOf('://') > -1 ? [String(CFG.doh).trim()] : DEFAULT_DOH;
  var directDomains = parseDomainList(CFG.directDomains.join(','));
  var proxyDomains = parseDomainList(CFG.proxyDomains.join(','));

  // ---------- 基础配置 ----------
  config['mixed-port'] = 7890;
  config['allow-lan'] = false;
  config['unified-delay'] = true;
  config['tcp-concurrent'] = true;
  config['keep-alive-interval'] = 60;
  config['external-controller'] = '127.0.0.1:9090';
  config['mode'] = 'rule';
  config['log-level'] = 'warning';

  config['profile'] = { 'store-selected': true, 'store-fake-ip': true };

  // ---------- 流量嗅探 ----------
  config['sniffer'] = {
    enable: true,
    'override-destination': false,
    sniff: {
      QUIC: { ports: [443] },
      TLS: { ports: [443, 8443] },
      HTTP: { ports: [80, '8080-8880'], 'override-destination': true },
    },
    'force-domain': ['+.netflix.com', '+.nflxvideo.net', '+.media.dssott.com', '+.amazonaws.com', '+.tiktok.com'],
    'skip-domain': ['+.push.apple.com', 'dlg.io.mi.com', '+.mi.com', '+.xiaomi.com', '+.miwifi.com', '+.oray.com', '+.sunlogin.net'],
  };

  // ---------- TUN ----------
  config['tun'] = {
    enable: CFG.forceTun === true,
    stack: 'mixed',
    'endpoint-independent-nat': true,
    mtu: 1480,
    'dns-hijack': ['any:53', 'tcp://any:53'],
  };

  // ---------- 域名映射 ----------
  config['hosts'] = {
    'services.googleapis.cn': ['services.googleapis.com'],
    '+.mcdn.bilivideo.com': ['0.0.0.0'],
    '+.mcdn.bilivideo.cn': ['0.0.0.0'],
    '+.edge.mountaintoys.cn': ['0.0.0.0'],
    '+.h2.smtcdns.net': ['0.0.0.0'],
  };

  // ---------- DNS ----------
  config['dns'] = {
    enable: true,
    ipv6: CFG.ipv6 === true,
    'cache-algorithm': 'arc',
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'fake-ip-range6': 'fc00::/18',
    'fake-ip-filter': FAKE_IP_FILTER.slice(),
    'respect-rules': true,
    'default-nameserver': ['223.6.6.6', '119.29.29.29'],
    nameserver: doh.slice(),
    'direct-nameserver': DEFAULT_DOH.slice(),
    'direct-nameserver-follow-policy': true,
    'proxy-server-nameserver': DEFAULT_DOH.slice(),
    'nameserver-policy': {
      'rule-set:geosite-category-ads-all': 'rcode://success',
      'rule-set:douyin': ['system', '180.184.1.1', '180.184.2.2'],
    },
  };

  // ---------- 策略组 ----------
  var auto = CFG.autoGroups === true;
  var smart = icon;

  var groups = [];

  // 🚀 节点选择：自动组置顶 → 全部节点 → 全球直连
  var mainProxies = [];
  if (auto) mainProxies = ['⏱️ 最低延迟', '⚖️ 负载均衡', '🛟 故障转移'];
  mainProxies.push('🎯 全球直连');
  groups.push({
    name: '🚀 节点选择',
    type: 'select',
    'include-all': true,
    'exclude-filter': CFG.excludeFilter,
    proxies: mainProxies,
    icon: smart + 'Proxy.svg',
  });

  if (auto) {
    groups.push({
      name: '⏱️ 最低延迟', type: 'url-test',
      url: 'https://www.apple.com/library/test/success.html',
      interval: 600, tolerance: 50, lazy: true,
      'include-all': true, 'exclude-filter': CFG.excludeFilter,
      icon: smart + 'Auto.svg',
    });
    groups.push({
      name: '⚖️ 负载均衡', type: 'load-balance',
      strategy: 'consistent-hashing',
      url: 'https://www.apple.com/library/test/success.html',
      interval: 600, lazy: true,
      'include-all': true, 'exclude-filter': CFG.excludeFilter,
      icon: smart + 'RoundRobin.svg',
    });
    groups.push({
      name: '🛟 故障转移', type: 'fallback',
      url: 'https://www.apple.com/library/test/success.html',
      interval: 600, lazy: true,
      'include-all': true, 'exclude-filter': CFG.excludeFilter,
      icon: smart + 'Static.svg',
    });
  }

  groups.push({
    name: '🤖 AI 助手', type: 'select',
    'include-all': true, 'exclude-filter': CFG.excludeFilter,
    proxies: ['🚀 节点选择'],
    icon: smart + 'OpenAI.svg',
  });
  groups.push({ name: '🎯 全球直连', type: 'select', proxies: ['DIRECT'], icon: smart + 'China.svg' });
  groups.push({ name: '🚫 广告拦截', type: 'select', proxies: ['REJECT', 'DIRECT'], icon: smart + 'AdBlock.svg' });
  groups.push({ name: '🐟 漏网之鱼', type: 'select', proxies: ['🚀 节点选择', '🎯 全球直连'], icon: smart + 'Stack.svg' });

  config['proxy-groups'] = groups;

  // ---------- 规则集 ----------
  var providers = {};
  ROUTE_PROVIDERS.forEach(function (p) {
    var tag = p[0], file = p[1];
    providers[tag] = {
      type: 'http',
      behavior: tag.indexOf('geoip') === 0 ? 'ipcidr' : 'domain',
      format: 'mrs',
      interval: 86400,
      proxy: 'DIRECT',
      url: mrsUrl(file),
    };
  });
  config['rule-providers'] = providers;

  // ---------- 分流规则（顺序即优先级） ----------
  var rules = []
    // 1. 私有网络 / 局域网
    .concat(segRules('private'))
    // 2. 自定义直连
    .concat(directDomains.map(function (d) { return 'DOMAIN-SUFFIX,' + d + ',DIRECT'; }))
    // 3. 自定义代理
    .concat(proxyDomains.map(function (d) { return 'DOMAIN-SUFFIX,' + d + ',🚀 节点选择'; }))
    // 4. 广告拦截
    .concat(segRules('ads'))
    // 5. AI 分流
    .concat(segRules('ai'))
    // 6. 追踪 / 包扫描 API 拦截
    .concat(USER_AD_DOMAINS.map(function (d) { return 'DOMAIN-SUFFIX,' + d + ',REJECT'; }))
    // 7. 只拦国外 QUIC，国内放行
    .concat(['AND,((NETWORK,UDP),(DST-PORT,443),(NOT,((OR,((RULE-SET,geosite-cn),(RULE-SET,geoip-cn)))))),REJECT'])
    // 8. 强制代理（GitHub / Google）
    .concat(segRules('proxy'))
    // 9. 强制直连（国内 / 游戏 / 微软 / 苹果中国）
    .concat(segRules('direct'))
    // 10. 兜底
    .concat(['MATCH,🐟 漏网之鱼']);

  config['rules'] = rules;

  return config;
}
