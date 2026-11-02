function main(config) {
  config = config || {};

  // ===== 规则集源（testingcf 是 jsDelivr 的 CF 加速域名，国内可直连）=====
  var MRS = 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/';
  var ADS = 'https://testingcf.jsdelivr.net/gh/DustinWin/ruleset_geodata@mihomo-ruleset/ads.mrs';
  var ICON = 'https://cdn.jsdmirror.com/gh/AIsouler/MyClash@main/Icons/svg/';

  // [RULE-SET 名, mrs 路径, 目标, 分段]
  var P = [
    ['geoip-private', 'geoip/private.mrs', 'DIRECT,no-resolve', 'private'],
    ['geosite-private', 'geosite/private.mrs', 'DIRECT', 'private'],
    ['ads', null, '🚫 广告拦截', 'ads'],
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
    ['geolocation-cn', 'geosite/geolocation-cn.mrs', '', 'geolocation-cn']
  ];

  var DIRECT_DOMAINS = ['senflarelink.de5.net'];
  var PROXY_DOMAINS = ['z.ai'];
  var AD_DOMAINS = ['miav-cse.avlyun.com', 'miui-fxcse.avlyun.com', 'a0.app.xiaomi.com', 'api.installer.xiaomi.com'];
  var FAKE_IP_FILTER = ['+.lan', '+.local', 'time.nist.gov', '+.pool.ntp.org', 'time.*.com', 'ntp.*.com', 'rule-set:geolocation-cn'];
  var DOH = ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'];
  var EXCLUDE = '直连|拦截|^DIRECT$|^REJECT$|剩余流量|套餐到期|距离下次|过期时间|官网|Expire|Traffic|重置';

  var i, seg, row, rules = [], providers = {};

  function segRules(s) {
    var out = [], k;
    for (k = 0; k < P.length; k++) if (P[k][3] === s) out.push('RULE-SET,' + P[k][0] + ',' + P[k][2]);
    return out;
  }

  // ===== 基础 =====
  config['mixed-port'] = 7890;
  config['allow-lan'] = false;
  config['unified-delay'] = true;
  config['tcp-concurrent'] = true;
  config['keep-alive-interval'] = 60;
  config['external-controller'] = '127.0.0.1:9090';
  config['mode'] = 'rule';
  config['log-level'] = 'warning';
  config['profile'] = { 'store-selected': true, 'store-fake-ip': true };

  // ===== 嗅探 =====
  config['sniffer'] = {
    enable: true,
    'override-destination': false,
    sniff: {
      QUIC: { ports: [443] },
      TLS: { ports: [443, 8443] },
      HTTP: { ports: [80, '8080-8880'], 'override-destination': true }
    },
    'force-domain': ['+.netflix.com', '+.nflxvideo.net', '+.media.dssott.com', '+.amazonaws.com', '+.tiktok.com'],
    'skip-domain': ['+.push.apple.com', 'dlg.io.mi.com', '+.mi.com', '+.xiaomi.com', '+.miwifi.com', '+.oray.com', '+.sunlogin.net']
  };

  // ===== TUN（开关交给客户端 UI，这里只定参数）=====
  config['tun'] = {
    enable: false,
    stack: 'mixed',
    'endpoint-independent-nat': true,
    mtu: 1480,
    'dns-hijack': ['any:53', 'tcp://any:53']
  };

  // ===== hosts =====
  config['hosts'] = {
    'services.googleapis.cn': ['services.googleapis.com'],
    '+.mcdn.bilivideo.com': ['0.0.0.0'],
    '+.mcdn.bilivideo.cn': ['0.0.0.0'],
    '+.edge.mountaintoys.cn': ['0.0.0.0'],
    '+.h2.smtcdns.net': ['0.0.0.0']
  };

  // ===== DNS =====
  config['dns'] = {
    enable: true,
    ipv6: true,
    'cache-algorithm': 'arc',
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'fake-ip-range6': 'fc00::/18',
    'fake-ip-filter': FAKE_IP_FILTER,
    'respect-rules': true,
    'default-nameserver': ['223.6.6.6', '119.29.29.29'],
    nameserver: DOH,
    'direct-nameserver': DOH,
    'direct-nameserver-follow-policy': true,
    'proxy-server-nameserver': DOH,
    'nameserver-policy': {
      'rule-set:geosite-category-ads-all': 'rcode://success',
      'rule-set:douyin': ['system', '180.184.1.1', '180.184.2.2']
    }
  };

  // ===== 策略组（不含自动测速组）=====
  config['proxy-groups'] = [
    { name: '🚀 节点选择', type: 'select', 'include-all': true, 'exclude-filter': EXCLUDE, proxies: ['🎯 全球直连'], icon: ICON + 'Proxy.svg' },
    { name: '🤖 AI 助手', type: 'select', 'include-all': true, 'exclude-filter': EXCLUDE, proxies: ['🚀 节点选择'], icon: ICON + 'OpenAI.svg' },
    { name: '🎯 全球直连', type: 'select', proxies: ['DIRECT'], icon: ICON + 'China.svg' },
    { name: '🚫 广告拦截', type: 'select', proxies: ['REJECT', 'DIRECT'], icon: ICON + 'AdBlock.svg' },
    { name: '🐟 漏网之鱼', type: 'select', proxies: ['🚀 节点选择', '🎯 全球直连'], icon: ICON + 'Stack.svg' }
  ];

  // ===== 规则集 =====
  for (i = 0; i < P.length; i++) {
    providers[P[i][0]] = {
      type: 'http',
      behavior: P[i][0].indexOf('geoip') === 0 ? 'ipcidr' : 'domain',
      format: 'mrs',
      interval: 86400,
      proxy: 'DIRECT',
      url: P[i][1] === null ? ADS : MRS + P[i][1]
    };
  }
  config['rule-providers'] = providers;

  // ===== 分流规则 =====
  rules = rules.concat(segRules('private'));
  for (i = 0; i < DIRECT_DOMAINS.length; i++) rules.push('DOMAIN-SUFFIX,' + DIRECT_DOMAINS[i] + ',DIRECT');
  for (i = 0; i < PROXY_DOMAINS.length; i++) rules.push('DOMAIN-SUFFIX,' + PROXY_DOMAINS[i] + ',🚀 节点选择');
  rules = rules.concat(segRules('ads'));
  rules = rules.concat(segRules('ai'));
  for (i = 0; i < AD_DOMAINS.length; i++) rules.push('DOMAIN-SUFFIX,' + AD_DOMAINS[i] + ',REJECT');
  rules.push('AND,((NETWORK,UDP),(DST-PORT,443),(NOT,((OR,((RULE-SET,geosite-cn),(RULE-SET,geoip-cn)))))),REJECT');
  rules = rules.concat(segRules('proxy'));
  rules = rules.concat(segRules('direct'));
  rules.push('MATCH,🐟 漏网之鱼');
  config['rules'] = rules;

  return config;
}
