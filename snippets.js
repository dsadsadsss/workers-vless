import {
	connect
} from 'cloudflare:sockets';

const te = new TextEncoder();
const td = new TextDecoder();
const UUID = '7888888-8888-4f73-8888-f2c15d3e332c';
const EXPECTED_UUID_BYTES = new Uint8Array(16);
{
	const uuidHex = UUID.replace(/-/g, '');
	for (let i = 0; i < 16; i++) {
		EXPECTED_UUID_BYTES[i] = parseInt(uuidHex.substring(i * 2, i * 2 + 2), 16);
	}
}

function verifyUUID(data) {
	if (data.byteLength < 17) return false;
	const uuidBytes = new Uint8Array(data, 1, 16);
	for (let i = 0; i < 16; i++) {
		if (uuidBytes[i] !== EXPECTED_UUID_BYTES[i]) {
			return false;
		}
	}
	return true;
}

export default {
	async fetch(req, env) {
		if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			const u = new URL(req.url);
			let mode = 'd';
			let configList = []; // 存储多个配置
			
			// 修复处理URL编码的查询参数
			if (u.pathname.includes('%3F')) {
				const decoded = decodeURIComponent(u.pathname);
				const queryIndex = decoded.indexOf('?');
				if (queryIndex !== -1) {
					u.search = decoded.substring(queryIndex);
					u.pathname = decoded.substring(0, queryIndex);
				}
			}
			
			// 解析参数，支持逗号分隔的多个值
			let sParam = u.pathname.split('/s=')[1];
			let pParam = u.pathname.split('/p=')[1];
			let hParam = u.pathname.split('/h=')[1];
			let ghParam = u.pathname.split('/gh=')[1];
			let gParam = u.pathname.split('/g=')[1];
			
			if (sParam) {
				mode = 's';
				configList = sParam.split(',').map(p => getSKJson(p.trim()));
			} else if (gParam) {
				mode = 'g';
				configList = gParam.split(',').map(p => getSKJson(p.trim()));
			} else if (pParam) {
				mode = 'p';
				configList = pParam.split(',').map(p => p.trim());
			} else if (hParam) {
				mode = 'h';
				configList = hParam.split(',').map(p => getSKJson(p.trim()));
			} else if (ghParam) {
				mode = 'gh';
				configList = ghParam.split(',').map(p => getSKJson(p.trim()));
			}
			
			const [client, ws] = Object.values(new WebSocketPair());
			ws.accept();

			let remote = null, udpWriter = null, isDNS = false;

			new ReadableStream({
				start(ctrl) {
					ws.addEventListener('message', e => ctrl.enqueue(e.data));
					ws.addEventListener('close', () => {
						remote?.close();
						ctrl.close();
					});
					ws.addEventListener('error', () => {
						remote?.close();
						ctrl.error();
					});

					const early = req.headers.get('sec-websocket-protocol');
					if (early) {
						try {
							ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')),
								c => c.charCodeAt(0)).buffer);
						} catch { }
					}
				}
			}, { highWaterMark: 65536 }).pipeTo(new WritableStream({
				async write(data) {
					if (isDNS) return udpWriter?.write(data);
					if (remote) {
						const w = remote.writable.getWriter();
						await w.write(data);
						w.releaseLock();
						return;
					}

					if (data.byteLength < 24) return;
					if (!verifyUUID(data)) return;

					const view = new DataView(data);
					const optLen = view.getUint8(17);
					const cmd = view.getUint8(18 + optLen);
					if (cmd !== 1 && cmd !== 2) return;

					let pos = 19 + optLen;
					const port = view.getUint16(pos);
					const type = view.getUint8(pos + 2);
					pos += 3;

					let addr = '';
					if (type === 1) {
						addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
						pos += 4;
					} else if (type === 2) {
						const len = view.getUint8(pos++);
						addr = td.decode(data.slice(pos, pos + len));
						pos += len;
					} else if (type === 3) {
						const ipv6 = [];
						for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos).toString(16));
						addr = ipv6.join(':');
					} else return;

					const header = new Uint8Array([data[0], 0]);
					const payload = data.slice(pos);

					// UDP DNS
					if (cmd === 2) {
						if (port !== 53) return;
						isDNS = true;
						let sent = false;
						const { readable, writable } = new TransformStream({
							transform(chunk, ctrl) {
								for (let i = 0; i < chunk.byteLength;) {
									const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
									ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
									i += 2 + len;
								}
							}
						});

						readable.pipeTo(new WritableStream({
							async write(query) {
								try {
									const resp = await fetch('https://1.1.1.1/dns-query', {
										method: 'POST',
										headers: { 'content-type': 'application/dns-message' },
										body: query
									});
									if (ws.readyState === 1) {
										const result = new Uint8Array(await resp.arrayBuffer());
										ws.send(new Uint8Array([...(sent ? [] : header), 
											result.length >> 8, result.length & 0xff, ...result]));
										sent = true;
									}
								} catch { }
							}
						}));
						udpWriter = writable.getWriter();
						return udpWriter.write(payload);
					}

					// TCP连接 - 轮询多个配置
					let sock = null;
					const methods = getOrder(mode);
					
					for (const method of methods) {
						// 对每个方法，轮询所有配置
						if (method === 'd') {
							try {
								sock = connect({ hostname: addr, port });
								await sock.opened;
								break;
							} catch { }
						} else if (method === 's' && configList.length > 0) {
							for (const skJson of configList) {
								try {
									sock = await sConnect(addr, port, skJson);
									break;
								} catch { }
							}
							if (sock) break;
						} else if (method === 'p' && configList.length > 0) {
							for (const pValue of configList) {
								try {
									const [ph, pp = port] = pValue.split(':');
									sock = connect({ hostname: ph, port: +pp || port });
									await sock.opened;
									break;
								} catch { }
							}
							if (sock) break;
						} else if (method === 'h' && configList.length > 0) {
							for (const skJson of configList) {
								try {
									sock = await httpConnect(addr, port, skJson);
									break;
								} catch { }
							}
							if (sock) break;
						}
					}

					if (!sock) return;

					remote = sock;
					const w = sock.writable.getWriter();
					await w.write(payload);
					w.releaseLock();

					const INITIAL_THRESHOLD = 6 * 1024 * 1024;
					let controlThreshold = INITIAL_THRESHOLD;
					let lastCount = 0;

					const reader = sock.readable.getReader();
					let totalBytes = 0;
					let sent = false;
					let writeQueue = Promise.resolve();

					(async () => {
						try {
							while (true) {
								const { done, value } = await reader.read();
								if (done) break;
								if (!value || !value.byteLength) continue;

								totalBytes += value.byteLength;

								writeQueue = writeQueue.then(() => {
									if (ws.readyState === 1) {
										if (!sent) {
											const combined = new Uint8Array(header.length + value.length);
											combined.set(header);
											combined.set(value, header.length);
											ws.send(combined);
											sent = true;
										} else {
											ws.send(value);
										}
									}
								});
								await writeQueue;

								const delta = totalBytes - lastCount;
								if (delta > controlThreshold) {
									controlThreshold = delta;
								} else if (delta > INITIAL_THRESHOLD) {
									await new Promise(r => setTimeout(r, 100 + Math.random() * 200));
									controlThreshold = controlThreshold - 2 * 1024 * 1024;
									if (controlThreshold < INITIAL_THRESHOLD) {
										controlThreshold = INITIAL_THRESHOLD;
									}
								}
								lastCount = totalBytes;
							}
						} catch (_) { }
						finally {
							try { reader.releaseLock(); } catch { }
							if (ws.readyState === 1) ws.close();
						}
					})();
				}
			})).catch(() => { });

			return new Response(null, { status: 101, webSocket: client });
		}

		return new Response("Hello World", { status: 200 });
	}
};

const SK_CACHE = new Map();

function getSKJson(path) {
	const cached = SK_CACHE.get(path);
	if (cached) return cached;

	const hasAuth = path.includes('@');
	const [cred, server] = hasAuth ? path.split('@') : [null, path];
	const [user = null, pass = null] = hasAuth ? cred.split(':') : [null, null];
	const [host, port = 443] = server.split(':');
	const result = { user, pass, host, port: +port };

	SK_CACHE.set(path, result);
	return result;
}

const orderCache = {
	'p': ['d', 'p'],
	's': ['d', 's'],
	'g': ['s'],
	'h': ['d', 'h'],
	'gh': ['h'],
	'default': ['d']
};

function getOrder(mode) {
	return orderCache[mode] || orderCache['default'];
}

async function sConnect(targetHost, targetPort, skJson) {
	const sock = connect({ hostname: skJson.host, port: skJson.port });
	await sock.opened;
	const w = sock.writable.getWriter();
	const r = sock.readable.getReader();
	await w.write(new Uint8Array([5, 2, 0, 2]));
	const auth = (await r.read()).value;
	if (auth[1] === 2 && skJson.user) {
		const user = te.encode(skJson.user);
		const pass = te.encode(skJson.pass);
		await w.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
		await r.read();
	}
	const domain = te.encode(targetHost);
	await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain, 
		targetPort >> 8, targetPort & 0xff]));
	await r.read();
	w.releaseLock();
	r.releaseLock();
	return sock;
}

async function httpConnect(addressRemote, portRemote, skJson) {
	const { user, pass, host, port } = skJson;
	const sock = await connect({ hostname: host, port: port });

	const connectRequest = buildConnectRequest(addressRemote, portRemote, user, pass);
	try {
		const writer = sock.writable.getWriter();
		await writer.write(te.encode(connectRequest));
		writer.releaseLock();
	} catch (err) {
		throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
	}

	const reader = sock.readable.getReader();
	let respText = '';
	let connected = false;
	let responseBuffer = new Uint8Array(0);

	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) throw new Error('HTTP代理连接中断');

			const newBuffer = new Uint8Array(responseBuffer.length + value.length);
			newBuffer.set(responseBuffer);
			newBuffer.set(value, responseBuffer.length);
			responseBuffer = newBuffer;

			respText = new TextDecoder().decode(responseBuffer);

			if (respText.includes('\r\n\r\n')) {
				const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
				const headers = respText.substring(0, headersEndPos);

				if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
					connected = true;

					if (headersEndPos < responseBuffer.length) {
						const remainingData = responseBuffer.slice(headersEndPos);
						const dataStream = new ReadableStream({
							start(controller) {
								controller.enqueue(remainingData);
							}
						});

						const { readable, writable } = new TransformStream();
						dataStream.pipeTo(writable).catch(() => {});
						sock.readable = readable;
					}
				} else {
					throw new Error(`HTTP代理连接失败: ${headers.split('\r\n')[0]}`);
				}
				break;
			}
		}
	} catch (err) {
		reader.releaseLock();
		throw new Error(`处理HTTP代理响应失败: ${err.message}`);
	}

	reader.releaseLock();
	if (!connected) throw new Error('HTTP代理连接失败: 未收到成功响应');
	return sock;
}

function buildConnectRequest(address, port, username, password) {
	const headers = [
		`CONNECT ${address}:${port} HTTP/1.1`,
		`Host: ${address}:${port}`
	];

	if (username && password) {
		const base64Auth = btoa(`${username}:${password}`);
		headers.push(`Proxy-Authorization: Basic ${base64Auth}`);
	}

	headers.push(
		'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
		'Proxy-Connection: Keep-Alive',
		'Connection: Keep-Alive',
		''
	);

	return headers.join('\r\n') + '\r\n';
}