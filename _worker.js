import { connect } from "cloudflare:sockets";

// Configuration block
let 订阅路径 = "sub";
let 我的UUID = "550e8400-e29b-41d4-a716-446655440000";
let 默认节点名称 = "节点";

let 反代IP = "ip.sb";

let 伪装网页 = "";

// Web entry point
export default {
  async fetch(访问请求, env) {
    订阅路径 = env.SUB_PATH ?? 订阅路径;
    我的UUID = env.SUB_UUID ?? 我的UUID;
    默认节点名称 = env.SUB_NAME ?? 默认节点名称;
    反代IP = env.PROXY_IP ?? 反代IP;
    伪装网页 = env.FAKE_WEB ?? 伪装网页;

    const 读取我的请求标头 = 访问请求.headers.get("Upgrade");
    const url = new URL(访问请求.url);
    if (!读取我的请求标头 || 读取我的请求标头 !== "websocket") {
      const 最终订阅路径 = encodeURIComponent(订阅路径);
      switch (url.pathname) {
        case `/${最终订阅路径}`:
          const 用户代理 = 访问请求.headers.get("User-Agent").toLowerCase();
          const 配置生成器 = {
            v2ray: v2ray配置文件,
            default: 生成提示界面,
          };
          const 工具 = Object.keys(配置生成器).find((工具) => 用户代理.includes(工具));
          const 生成配置 = 配置生成器[工具 || "default"];
          return 生成配置(访问请求.headers.get("Host"));
        default:
          if (伪装网页) {
            url.hostname = 伪装网页;
            url.protocol = "https:";
            访问请求 = new Request(url, 访问请求);
            return fetch(访问请求);
          } else {
            return 生成项目介绍页面();
          }
      }
    } else if (读取我的请求标头 === "websocket") {
      return await 升级WS请求(访问请求);
    }
  },
};

// Core script architecture
async function 升级WS请求(访问请求) {
  const 创建WS接口 = new WebSocketPair();
  const [客户端, WS接口] = Object.values(创建WS接口);
  WS接口.accept();
  const 读取我的加密访问内容数据头 = 访问请求.headers.get("sec-websocket-protocol");
  const 解密数据 = 使用64位加解密(读取我的加密访问内容数据头);
  const { TCP接口, 写入初始数据 } = await 解析VL标头(解密数据);
  建立传输管道(WS接口, TCP接口, 写入初始数据);
  return new Response(null, { status: 101, webSocket: 客户端 });
}

function 使用64位加解密(还原混淆字符) {
  还原混淆字符 = 还原混淆字符.replace(/-/g, "+").replace(/_/g, "/");
  const 解密数据 = atob(还原混淆字符);
  const 解密 = Uint8Array.from(解密数据, (c) => c.charCodeAt(0));
  return 解密.buffer;
}

async function 解析VL标头(VL数据, TCP接口) {
  if (验证VL的密钥(new Uint8Array(VL数据.slice(1, 17))) !== 我的UUID) {
    return null;
  }
  const 获取数据定位 = new Uint8Array(VL数据)[17];
  const 提取端口索引 = 18 + 获取数据定位 + 1;
  const 建立端口缓存 = VL数据.slice(提取端口索引, 提取端口索引 + 2);
  const 访问端口 = new DataView(建立端口缓存).getUint16(0);
  const 提取地址索引 = 提取端口索引 + 2;
  const 建立地址缓存 = new Uint8Array(VL数据.slice(提取地址索引, 提取地址索引 + 1));
  const 识别地址类型 = 建立地址缓存[0];
  let 地址长度 = 0;
  let 访问地址 = "";
  let 地址信息索引 = 提取地址索引 + 1;
  switch (识别地址类型) {
    case 1:
      地址长度 = 4;
      访问地址 = new Uint8Array(VL数据.slice(地址信息索引, 地址信息索引 + 地址长度)).join(".");
      break;
    case 2:
      地址长度 = new Uint8Array(VL数据.slice(地址信息索引, 地址信息索引 + 1))[0];
      地址信息索引 += 1;
      访问地址 = new TextDecoder().decode(VL数据.slice(地址信息索引, 地址信息索引 + 地址长度));
      break;
    case 3:
      地址长度 = 16;
      const dataView = new DataView(VL数据.slice(地址信息索引, 地址信息索引 + 地址长度));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      访问地址 = ipv6.join(":");
      break;
  }
  const 写入初始数据 = VL数据.slice(地址信息索引 + 地址长度);
  
  let [反代IP地址, 反代IP端口] = 反代IP.split(":");
  TCP接口 = await connect({
    hostname: 反代IP地址,
    port: Number(反代IP端口) || 443,
  });
  
  return { TCP接口, 写入初始数据 };
}

function 验证VL的密钥(arr, offset = 0) {
  const uuid = (
    转换密钥格式[arr[offset + 0]] +
    转换密钥格式[arr[offset + 1]] +
    转换密钥格式[arr[offset + 2]] +
    转换密钥格式[arr[offset + 3]] +
    "-" +
    转换密钥格式[arr[offset + 4]] +
    转换密钥格式[arr[offset + 5]] +
    "-" +
    转换密钥格式[arr[offset + 6]] +
    转换密钥格式[arr[offset + 7]] +
    "-" +
    转换密钥格式[arr[offset + 8]] +
    转换密钥格式[arr[offset + 9]] +
    "-" +
    转换密钥格式[arr[offset + 10]] +
    转换密钥格式[arr[offset + 11]] +
    转换密钥格式[arr[offset + 12]] +
    转换密钥格式[arr[offset + 13]] +
    转换密钥格式[arr[offset + 14]] +
    转换密钥格式[arr[offset + 15]]
  ).toLowerCase();
  return uuid;
}

const 转换密钥格式 = [];
for (let i = 0; i < 256; ++i) {
  转换密钥格式.push((i + 256).toString(16).slice(1));
}

async function 建立传输管道(WS接口, TCP接口, 写入初始数据) {
  const 传输数据 = TCP接口.writable.getWriter();
  await WS接口.send(new Uint8Array([0, 0]).buffer);
  TCP接口.readable.pipeTo(
    new WritableStream({
      async write(VL数据) {
        await WS接口.send(VL数据);
      },
    })
  );
  const 数据流 = new ReadableStream({
    async start(控制器) {
      if (写入初始数据) {
        控制器.enqueue(写入初始数据);
        写入初始数据 = null;
      }
      WS接口.addEventListener("message", (event) => {
        控制器.enqueue(event.data);
      });
      WS接口.addEventListener("close", () => {
        控制器.close();
      });
      WS接口.addEventListener("error", () => {
        控制器.close();
      });
    },
  });
  数据流.pipeTo(
    new WritableStream({
      async write(VL数据) {
        await 传输数据.write(VL数据);
      },
    })
  );
}

function 生成项目介绍页面() {
  const 项目介绍 = `
<title>项目介绍</title>
<style>
  body {
    font-size: 25px;
  }
</style>
<pre>
<strong>edge-tunnel</strong>

这是一个基于CF平台的VLESS代理服务
默认使用 ip.sb 作为代理地址

vless://${我的UUID}@ip.sb:443?encryption=none&security=tls&sni=your-hostname&fp=chrome&type=ws&host=your-hostname&path=/?ed=9999#默认节点
</pre>
`;

  return new Response(项目介绍, {
    status: 200,
    headers: { "Content-Type": "text/html;charset=utf-8" },
  });
}

function 生成提示界面() {
  const 提示界面 = `
<title>订阅-${订阅路径}</title>
<style>
  body {
    font-size: 25px;
  }
</style>
<strong>请把链接导入v2ray客户端</strong>
`;
  return new Response(提示界面, {
    status: 200,
    headers: { "Content-Type": "text/html;charset=utf-8" },
  });
}

function v2ray配置文件(hostName) {
  const path = encodeURIComponent("/?ed=9999");
  const 配置内容 = `vless://${我的UUID}@${反代IP.split(":")[0]}:443?encryption=none&security=tls&sni=${hostName}&fp=chrome&type=ws&host=${hostName}&path=${path}#${默认节点名称}`;

  return new Response(配置内容, {
    status: 200,
    headers: { "Content-Type": "text/plain;charset=utf-8" },
  });
}
