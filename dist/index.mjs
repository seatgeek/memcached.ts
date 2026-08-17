import { Hashery } from "hashery";
import { Hookified } from "hookified";
import { createConnection } from "node:net";
import { connect } from "node:tls";
import { createHash } from "node:crypto";
/**
* Serialize a binary protocol header to a Buffer
* @param header - Partial header object with values to set
* @returns A 24-byte Buffer containing the binary header
*/
function serializeHeader(header) {
	const buf = Buffer.alloc(24);
	buf.writeUInt8(header.magic ?? 128, 0);
	buf.writeUInt8(header.opcode ?? 0, 1);
	buf.writeUInt16BE(header.keyLength ?? 0, 2);
	buf.writeUInt8(header.extrasLength ?? 0, 4);
	buf.writeUInt8(header.dataType ?? 0, 5);
	buf.writeUInt16BE(header.status ?? 0, 6);
	buf.writeUInt32BE(header.totalBodyLength ?? 0, 8);
	buf.writeUInt32BE(header.opaque ?? 0, 12);
	if (header.cas) header.cas.copy(buf, 16);
	return buf;
}
/**
* Deserialize a binary protocol header from a Buffer
* @param buf - Buffer containing at least 24 bytes of header data
* @returns Parsed BinaryHeader object
*/
function deserializeHeader(buf) {
	return {
		magic: buf.readUInt8(0),
		opcode: buf.readUInt8(1),
		keyLength: buf.readUInt16BE(2),
		extrasLength: buf.readUInt8(4),
		dataType: buf.readUInt8(5),
		status: buf.readUInt16BE(6),
		totalBodyLength: buf.readUInt32BE(8),
		opaque: buf.readUInt32BE(12),
		cas: buf.subarray(16, 24)
	};
}
/**
* Build a SASL PLAIN authentication request packet.
* SASL PLAIN format: \0username\0password
* @param username - The username for authentication
* @param password - The password for authentication
* @returns Buffer containing the complete binary request packet
*/
function buildSaslPlainRequest(username, password) {
	const mechanism = "PLAIN";
	const authData = `\x00${username}\x00${password}`;
	const keyBuf = Buffer.from(mechanism, "utf8");
	const valueBuf = Buffer.from(authData, "utf8");
	const header = serializeHeader({
		magic: 128,
		opcode: 33,
		keyLength: keyBuf.length,
		totalBodyLength: keyBuf.length + valueBuf.length
	});
	return Buffer.concat([
		header,
		keyBuf,
		valueBuf
	]);
}
/**
* Build a GET request packet
* @param key - The key to retrieve
* @returns Buffer containing the complete binary request packet
*/
function buildGetRequest(key) {
	const keyBuf = Buffer.from(key, "utf8");
	const header = serializeHeader({
		magic: 128,
		opcode: 0,
		keyLength: keyBuf.length,
		totalBodyLength: keyBuf.length
	});
	return Buffer.concat([header, keyBuf]);
}
/**
* Build a SET request packet
* @param key - The key to set
* @param value - The value to store
* @param flags - Optional flags (default: 0)
* @param exptime - Expiration time in seconds (default: 0)
* @returns Buffer containing the complete binary request packet
*/
function buildSetRequest(key, value, flags = 0, exptime = 0) {
	const keyBuf = Buffer.from(key, "utf8");
	/* v8 ignore next -- @preserve */
	const valueBuf = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
	const extras = Buffer.alloc(8);
	extras.writeUInt32BE(flags, 0);
	extras.writeUInt32BE(exptime, 4);
	const header = serializeHeader({
		magic: 128,
		opcode: 1,
		keyLength: keyBuf.length,
		extrasLength: 8,
		totalBodyLength: 8 + keyBuf.length + valueBuf.length
	});
	return Buffer.concat([
		header,
		extras,
		keyBuf,
		valueBuf
	]);
}
/**
* Build an ADD request packet (only stores if key doesn't exist)
*/
function buildAddRequest(key, value, flags = 0, exptime = 0) {
	const keyBuf = Buffer.from(key, "utf8");
	/* v8 ignore next -- @preserve */
	const valueBuf = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
	const extras = Buffer.alloc(8);
	extras.writeUInt32BE(flags, 0);
	extras.writeUInt32BE(exptime, 4);
	const header = serializeHeader({
		magic: 128,
		opcode: 2,
		keyLength: keyBuf.length,
		extrasLength: 8,
		totalBodyLength: 8 + keyBuf.length + valueBuf.length
	});
	return Buffer.concat([
		header,
		extras,
		keyBuf,
		valueBuf
	]);
}
/**
* Build a REPLACE request packet (only stores if key exists)
*/
function buildReplaceRequest(key, value, flags = 0, exptime = 0) {
	const keyBuf = Buffer.from(key, "utf8");
	/* v8 ignore next -- @preserve */
	const valueBuf = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
	const extras = Buffer.alloc(8);
	extras.writeUInt32BE(flags, 0);
	extras.writeUInt32BE(exptime, 4);
	const header = serializeHeader({
		magic: 128,
		opcode: 3,
		keyLength: keyBuf.length,
		extrasLength: 8,
		totalBodyLength: 8 + keyBuf.length + valueBuf.length
	});
	return Buffer.concat([
		header,
		extras,
		keyBuf,
		valueBuf
	]);
}
/**
* Build a DELETE request packet
* @param key - The key to delete
* @returns Buffer containing the complete binary request packet
*/
function buildDeleteRequest(key) {
	const keyBuf = Buffer.from(key, "utf8");
	const header = serializeHeader({
		magic: 128,
		opcode: 4,
		keyLength: keyBuf.length,
		totalBodyLength: keyBuf.length
	});
	return Buffer.concat([header, keyBuf]);
}
/**
* Build an INCREMENT request packet
* @param key - The key to increment
* @param delta - Amount to increment by
* @param initial - Initial value if key doesn't exist
* @param exptime - Expiration time
* @returns Buffer containing the complete binary request packet
*/
function buildIncrementRequest(key, delta = 1, initial = 0, exptime = 0) {
	const keyBuf = Buffer.from(key, "utf8");
	const extras = Buffer.alloc(20);
	extras.writeUInt32BE(Math.floor(delta / 4294967296), 0);
	extras.writeUInt32BE(delta >>> 0, 4);
	extras.writeUInt32BE(Math.floor(initial / 4294967296), 8);
	extras.writeUInt32BE(initial >>> 0, 12);
	extras.writeUInt32BE(exptime, 16);
	const header = serializeHeader({
		magic: 128,
		opcode: 5,
		keyLength: keyBuf.length,
		extrasLength: 20,
		totalBodyLength: 20 + keyBuf.length
	});
	return Buffer.concat([
		header,
		extras,
		keyBuf
	]);
}
/**
* Build a DECREMENT request packet
* @param key - The key to decrement
* @param delta - Amount to decrement by
* @param initial - Initial value if key doesn't exist
* @param exptime - Expiration time
* @returns Buffer containing the complete binary request packet
*/
function buildDecrementRequest(key, delta = 1, initial = 0, exptime = 0) {
	const keyBuf = Buffer.from(key, "utf8");
	const extras = Buffer.alloc(20);
	extras.writeUInt32BE(Math.floor(delta / 4294967296), 0);
	extras.writeUInt32BE(delta >>> 0, 4);
	extras.writeUInt32BE(Math.floor(initial / 4294967296), 8);
	extras.writeUInt32BE(initial >>> 0, 12);
	extras.writeUInt32BE(exptime, 16);
	const header = serializeHeader({
		magic: 128,
		opcode: 6,
		keyLength: keyBuf.length,
		extrasLength: 20,
		totalBodyLength: 20 + keyBuf.length
	});
	return Buffer.concat([
		header,
		extras,
		keyBuf
	]);
}
/**
* Build an APPEND request packet
*/
function buildAppendRequest(key, value) {
	const keyBuf = Buffer.from(key, "utf8");
	const valueBuf = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
	const header = serializeHeader({
		magic: 128,
		opcode: 14,
		keyLength: keyBuf.length,
		totalBodyLength: keyBuf.length + valueBuf.length
	});
	return Buffer.concat([
		header,
		keyBuf,
		valueBuf
	]);
}
/**
* Build a PREPEND request packet
*/
function buildPrependRequest(key, value) {
	const keyBuf = Buffer.from(key, "utf8");
	const valueBuf = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
	const header = serializeHeader({
		magic: 128,
		opcode: 15,
		keyLength: keyBuf.length,
		totalBodyLength: keyBuf.length + valueBuf.length
	});
	return Buffer.concat([
		header,
		keyBuf,
		valueBuf
	]);
}
/**
* Build a TOUCH request packet
*/
function buildTouchRequest(key, exptime) {
	const keyBuf = Buffer.from(key, "utf8");
	const extras = Buffer.alloc(4);
	extras.writeUInt32BE(exptime, 0);
	const header = serializeHeader({
		magic: 128,
		opcode: 28,
		keyLength: keyBuf.length,
		extrasLength: 4,
		totalBodyLength: 4 + keyBuf.length
	});
	return Buffer.concat([
		header,
		extras,
		keyBuf
	]);
}
/**
* Build a FLUSH request packet
*/
function buildFlushRequest(exptime = 0) {
	const extras = Buffer.alloc(4);
	extras.writeUInt32BE(exptime, 0);
	const header = serializeHeader({
		magic: 128,
		opcode: 8,
		extrasLength: 4,
		totalBodyLength: 4
	});
	return Buffer.concat([header, extras]);
}
/**
* Build a VERSION request packet
*/
function buildVersionRequest() {
	return serializeHeader({
		magic: 128,
		opcode: 11
	});
}
/**
* Build a STAT request packet
*/
function buildStatRequest(key) {
	if (key) {
		const keyBuf = Buffer.from(key, "utf8");
		const header = serializeHeader({
			magic: 128,
			opcode: 16,
			keyLength: keyBuf.length,
			totalBodyLength: keyBuf.length
		});
		return Buffer.concat([header, keyBuf]);
	}
	return serializeHeader({
		magic: 128,
		opcode: 16
	});
}
/**
* Build a QUIT request packet
*/
function buildQuitRequest() {
	return serializeHeader({
		magic: 128,
		opcode: 7
	});
}
/**
* Parse a binary response and extract the value
*/
function parseGetResponse(buf) {
	const header = deserializeHeader(buf);
	if (header.status !== 0) return {
		header,
		value: void 0,
		key: void 0
	};
	const extrasEnd = 24 + header.extrasLength;
	const keyEnd = extrasEnd + header.keyLength;
	const valueEnd = 24 + header.totalBodyLength;
	/* v8 ignore next -- @preserve */
	const key = header.keyLength > 0 ? buf.subarray(extrasEnd, keyEnd).toString("utf8") : void 0;
	return {
		header,
		value: valueEnd > keyEnd ? buf.subarray(keyEnd, valueEnd) : void 0,
		key
	};
}
/**
* Parse an increment/decrement response
*/
function parseIncrDecrResponse(buf) {
	const header = deserializeHeader(buf);
	if (header.status !== 0 || header.totalBodyLength < 8) return {
		header,
		value: void 0
	};
	const high = buf.readUInt32BE(24);
	const low = buf.readUInt32BE(28);
	return {
		header,
		value: high * 4294967296 + low
	};
}
//#endregion
//#region src/node.ts
/**
* MemcacheNode represents a single memcache server connection.
* It handles the socket connection, command queue, and protocol parsing for one node.
*/
var MemcacheNode = class extends Hookified {
	_host;
	_port;
	_socket = void 0;
	_timeout;
	_keepAlive;
	_keepAliveDelay;
	_weight;
	_connected = false;
	_commandQueue = [];
	_buffer = Buffer.alloc(0);
	_currentCommand = void 0;
	_multilineData = [];
	_pendingValueBytes = 0;
	_sasl;
	_tls;
	_authenticated = false;
	_binaryBuffer = Buffer.alloc(0);
	constructor(host, port, options) {
		super({ throwOnEmptyListeners: false });
		this._host = host;
		this._port = port;
		this._timeout = options?.timeout || 5e3;
		this._keepAlive = options?.keepAlive !== false;
		this._keepAliveDelay = options?.keepAliveDelay || 1e3;
		this._weight = options?.weight || 1;
		this._sasl = options?.sasl;
		this._tls = options?.tls;
	}
	/**
	* Get the host of this node
	*/
	get host() {
		return this._host;
	}
	/**
	* Get the port of this node
	*/
	get port() {
		return this._port;
	}
	/**
	* Get the unique identifier for this node (host:port format)
	*/
	get id() {
		if (this._port === 0) return this._host;
		return `${this._host.includes(":") ? `[${this._host}]` : this._host}:${this._port}`;
	}
	/**
	* Get the full uri like memcache://localhost:11211
	*/
	get uri() {
		return `memcache://${this.id}`;
	}
	/**
	* Get the socket connection
	*/
	get socket() {
		return this._socket;
	}
	/**
	* Get the weight of this node (used for consistent hashing distribution)
	*/
	get weight() {
		return this._weight;
	}
	/**
	* Set the weight of this node (used for consistent hashing distribution)
	*/
	set weight(value) {
		this._weight = value;
	}
	/**
	* Get the keepAlive setting for this node
	*/
	get keepAlive() {
		return this._keepAlive;
	}
	/**
	* Set the keepAlive setting for this node
	*/
	set keepAlive(value) {
		this._keepAlive = value;
	}
	/**
	* Get the keepAliveDelay setting for this node
	*/
	get keepAliveDelay() {
		return this._keepAliveDelay;
	}
	/**
	* Set the keepAliveDelay setting for this node
	*/
	set keepAliveDelay(value) {
		this._keepAliveDelay = value;
	}
	/**
	* Get the command queue
	*/
	get commandQueue() {
		return this._commandQueue;
	}
	/**
	* Get whether SASL authentication is configured
	*/
	get hasSaslCredentials() {
		return !!this._sasl?.username && !!this._sasl?.password;
	}
	/**
	* Get whether the node is authenticated (only relevant if SASL is configured)
	*/
	get isAuthenticated() {
		return this._authenticated;
	}
	/**
	* Connect to the memcache server
	*/
	async connect() {
		return new Promise((resolve, reject) => {
			if (this._connected) {
				resolve();
				return;
			}
			if (this._tls) this._socket = connect({
				host: this._host,
				port: this._port,
				keepAlive: this._keepAlive,
				keepAliveInitialDelay: this._keepAliveDelay,
				...this._tls === true ? {} : this._tls
			});
			else this._socket = createConnection({
				host: this._host,
				port: this._port,
				keepAlive: this._keepAlive,
				keepAliveInitialDelay: this._keepAliveDelay
			});
			this._socket.setTimeout(this._timeout);
			this._socket.setNoDelay(true);
			const readyEvent = this._tls ? "secureConnect" : "connect";
			this._socket.on(readyEvent, async () => {
				this._connected = true;
				if (this._sasl) try {
					await this.performSaslAuth();
					this.emit("connect");
					resolve();
				} catch (error) {
					this._socket?.destroy();
					this._connected = false;
					this._authenticated = false;
					reject(error);
				}
				else {
					this.emit("connect");
					resolve();
				}
			});
			this._socket.on("data", (data) => {
				if (!this._sasl) this.handleData(data);
			});
			this._socket.on("error", (error) => {
				this.emit("error", error);
				if (!this._connected)
 /* v8 ignore next -- @preserve */
				reject(error);
			});
			this._socket.on("close", () => {
				this._connected = false;
				this._authenticated = false;
				this.emit("close");
				this.rejectPendingCommands(/* @__PURE__ */ new Error("Connection closed"));
			});
			this._socket.on("timeout", () => {
				this.emit("timeout");
				this._socket?.destroy();
				reject(/* @__PURE__ */ new Error("Connection timeout"));
			});
		});
	}
	/**
	* Disconnect from the memcache server
	*/
	async disconnect() {
		/* v8 ignore next -- @preserve */
		if (this._socket) {
			this._socket.destroy();
			this._socket = void 0;
			this._connected = false;
		}
	}
	/**
	* Reconnect to the memcache server by disconnecting and connecting again
	*/
	async reconnect() {
		if (this._connected || this._socket) {
			await this.disconnect();
			this.rejectPendingCommands(/* @__PURE__ */ new Error("Connection reset for reconnection"));
			this._buffer = Buffer.alloc(0);
			this._currentCommand = void 0;
			this._multilineData = [];
			this._pendingValueBytes = 0;
			this._authenticated = false;
			this._binaryBuffer = Buffer.alloc(0);
		}
		await this.connect();
	}
	/**
	* Perform SASL PLAIN authentication using the binary protocol
	*/
	async performSaslAuth() {
		/* v8 ignore next 3 -- @preserve */
		if (!this._sasl || !this._socket) throw new Error("SASL credentials not configured");
		const socket = this._socket;
		const sasl = this._sasl;
		return new Promise((resolve, reject) => {
			this._binaryBuffer = Buffer.alloc(0);
			const authPacket = buildSaslPlainRequest(sasl.username, sasl.password);
			const chunks = [];
			let chunksLen = 0;
			const binaryHandler = (data) => {
				chunks.push(data);
				chunksLen += data.length;
				/* v8 ignore next 3 -- @preserve */
				if (chunksLen < 24) return;
				/* v8 ignore next 2 -- @preserve */
				this._binaryBuffer = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, chunksLen);
				const header = deserializeHeader(this._binaryBuffer);
				const totalLength = 24 + header.totalBodyLength;
				/* v8 ignore next 3 -- @preserve */
				if (chunksLen < totalLength) return;
				socket.removeListener("data", binaryHandler);
				/* v8 ignore next -- @preserve */
				if (header.status === 0) {
					this._authenticated = true;
					this.emit("authenticated");
					resolve();
				} else if (header.status === 32) {
					const body = this._binaryBuffer.subarray(24, totalLength);
					reject(/* @__PURE__ */ new Error(`SASL authentication failed: ${body.toString() || "Invalid credentials"}`));
				} else reject(/* @__PURE__ */ new Error(`SASL authentication failed with status: 0x${header.status.toString(16)}`));
			};
			socket.on("data", binaryHandler);
			socket.write(authPacket);
		});
	}
	/**
	* Send a binary protocol request and wait for response.
	* Used internally for SASL-authenticated connections.
	*/
	async binaryRequest(packet) {
		/* v8 ignore next 3 -- @preserve */
		if (!this._socket) throw new Error("Not connected");
		const socket = this._socket;
		return new Promise((resolve) => {
			const chunks = [];
			let chunksLen = 0;
			const dataHandler = (data) => {
				chunks.push(data);
				chunksLen += data.length;
				/* v8 ignore next 3 -- @preserve */
				if (chunksLen < 24) return;
				const buffer = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, chunksLen);
				const totalLength = 24 + deserializeHeader(buffer).totalBodyLength;
				/* v8 ignore next 3 -- @preserve */
				if (chunksLen < totalLength) return;
				socket.removeListener("data", dataHandler);
				resolve(buffer.subarray(0, totalLength));
			};
			socket.on("data", dataHandler);
			socket.write(packet);
		});
	}
	/**
	* Binary protocol GET operation
	*/
	async binaryGet(key) {
		const { header, value } = parseGetResponse(await this.binaryRequest(buildGetRequest(key)));
		if (header.status === 1) {
			this.emit("miss", key);
			return;
		}
		/* v8 ignore next 3 -- @preserve */
		if (header.status !== 0 || !value) return;
		const result = value.toString("utf8");
		this.emit("hit", key, result);
		return result;
	}
	/**
	* Binary protocol SET operation
	*/
	async binarySet(key, value, exptime = 0, flags = 0) {
		return deserializeHeader(await this.binaryRequest(buildSetRequest(key, value, flags, exptime))).status === 0;
	}
	/**
	* Binary protocol ADD operation
	*/
	async binaryAdd(key, value, exptime = 0, flags = 0) {
		return deserializeHeader(await this.binaryRequest(buildAddRequest(key, value, flags, exptime))).status === 0;
	}
	/**
	* Binary protocol REPLACE operation
	*/
	async binaryReplace(key, value, exptime = 0, flags = 0) {
		return deserializeHeader(await this.binaryRequest(buildReplaceRequest(key, value, flags, exptime))).status === 0;
	}
	/**
	* Binary protocol DELETE operation
	*/
	async binaryDelete(key) {
		const header = deserializeHeader(await this.binaryRequest(buildDeleteRequest(key)));
		return header.status === 0 || header.status === 1;
	}
	/**
	* Binary protocol INCREMENT operation
	*/
	async binaryIncr(key, delta = 1, initial = 0, exptime = 0) {
		const { header, value } = parseIncrDecrResponse(await this.binaryRequest(buildIncrementRequest(key, delta, initial, exptime)));
		/* v8 ignore next 3 -- @preserve */
		if (header.status !== 0) return;
		return value;
	}
	/**
	* Binary protocol DECREMENT operation
	*/
	async binaryDecr(key, delta = 1, initial = 0, exptime = 0) {
		const { header, value } = parseIncrDecrResponse(await this.binaryRequest(buildDecrementRequest(key, delta, initial, exptime)));
		/* v8 ignore next 3 -- @preserve */
		if (header.status !== 0) return;
		return value;
	}
	/**
	* Binary protocol APPEND operation
	*/
	async binaryAppend(key, value) {
		return deserializeHeader(await this.binaryRequest(buildAppendRequest(key, value))).status === 0;
	}
	/**
	* Binary protocol PREPEND operation
	*/
	async binaryPrepend(key, value) {
		return deserializeHeader(await this.binaryRequest(buildPrependRequest(key, value))).status === 0;
	}
	/**
	* Binary protocol TOUCH operation
	*/
	async binaryTouch(key, exptime) {
		return deserializeHeader(await this.binaryRequest(buildTouchRequest(key, exptime))).status === 0;
	}
	/**
	* Binary protocol FLUSH operation
	*/
	/* v8 ignore next -- @preserve */
	async binaryFlush(exptime = 0) {
		return deserializeHeader(await this.binaryRequest(buildFlushRequest(exptime))).status === 0;
	}
	/**
	* Binary protocol VERSION operation
	*/
	async binaryVersion() {
		const response = await this.binaryRequest(buildVersionRequest());
		const header = deserializeHeader(response);
		/* v8 ignore next -- @preserve */
		if (header.status !== 0) return;
		return response.subarray(24, 24 + header.totalBodyLength).toString("utf8");
	}
	/**
	* Binary protocol STATS operation
	*/
	async binaryStats() {
		/* v8 ignore next -- @preserve */
		if (!this._socket) throw new Error("Not connected");
		const socket = this._socket;
		const stats = {};
		return new Promise((resolve) => {
			const chunks = [];
			let chunksLen = 0;
			let consumed = 0;
			const dataHandler = (data) => {
				chunks.push(data);
				chunksLen += data.length;
				let buffer;
				if (chunks.length === 1) buffer = chunks[0];
				else {
					buffer = Buffer.concat(chunks, chunksLen).subarray(consumed);
					chunks.length = 0;
					chunks.push(buffer);
					chunksLen = buffer.length;
					consumed = 0;
				}
				while (buffer.length >= 24) {
					const header = deserializeHeader(buffer);
					const totalLength = 24 + header.totalBodyLength;
					/* v8 ignore next -- @preserve */
					if (buffer.length < totalLength) return;
					if (header.keyLength === 0 && header.totalBodyLength === 0) {
						socket.removeListener("data", dataHandler);
						resolve(stats);
						return;
					}
					if (header.opcode === 16 && header.status === 0) {
						const keyStart = 24;
						const keyEnd = keyStart + header.keyLength;
						const valueEnd = 24 + header.totalBodyLength;
						const key = buffer.subarray(keyStart, keyEnd).toString("utf8");
						const value = buffer.subarray(keyEnd, valueEnd).toString("utf8");
						stats[key] = value;
					}
					consumed += totalLength;
					buffer = buffer.subarray(totalLength);
				}
			};
			socket.on("data", dataHandler);
			socket.write(buildStatRequest());
		});
	}
	/**
	* Binary protocol QUIT operation
	*/
	async binaryQuit() {
		if (this._socket) this._socket.write(buildQuitRequest());
	}
	/**
	* Gracefully quit the connection (send quit command then disconnect)
	*/
	async quit() {
		/* v8 ignore next -- @preserve */
		if (this._connected && this._socket) {
			try {
				await this.command("quit");
			} catch (error) {}
			await this.disconnect();
		}
	}
	/**
	* Check if connected to the memcache server
	*/
	isConnected() {
		return this._connected;
	}
	/**
	* Send a generic command to the memcache server
	* @param cmd The command string to send (without trailing \r\n)
	* @param options Command options for response parsing
	*/
	async command(cmd, options) {
		if (!this._connected || !this._socket) throw new Error(`Not connected to memcache server ${this.id}`);
		const wire = `${cmd}\r\n`;
		return new Promise((resolve, reject) => {
			this._commandQueue.push({
				command: cmd,
				resolve,
				reject,
				isMultiline: options?.isMultiline,
				isStats: options?.isStats,
				isConfig: options?.isConfig,
				requestedKeys: options?.requestedKeys
			});
			this._socket.write(wire);
		});
	}
	handleData(data) {
		const chunk = typeof data === "string" ? Buffer.from(data, "utf8") : data;
		this._buffer = this._buffer.length === 0 ? chunk : Buffer.concat([this._buffer, chunk]);
		while (true) {
			if (this._pendingValueBytes > 0) if (this._buffer.length >= this._pendingValueBytes + 2) {
				const value = this._buffer.subarray(0, this._pendingValueBytes).toString("utf8");
				this._buffer = this._buffer.subarray(this._pendingValueBytes + 2);
				this._multilineData.push(value);
				this._pendingValueBytes = 0;
			} else break;
			const lineEnd = this._buffer.indexOf("\r\n");
			if (lineEnd === -1) break;
			const line = this._buffer.subarray(0, lineEnd).toString("utf8");
			this._buffer = this._buffer.subarray(lineEnd + 2);
			this.processLine(line);
		}
	}
	processLine(line) {
		if (!this._currentCommand) {
			this._currentCommand = this._commandQueue.shift();
			if (!this._currentCommand) return;
		}
		if (this._currentCommand.isStats) {
			if (line === "END") {
				const stats = {};
				for (const statLine of this._multilineData) {
					const sp1 = statLine.indexOf(" ");
					const sp2 = statLine.indexOf(" ", sp1 + 1);
					/* v8 ignore next -- @preserve */
					if (sp1 !== -1 && sp2 !== -1) stats[statLine.substring(sp1 + 1, sp2)] = statLine.substring(sp2 + 1);
				}
				this._currentCommand.resolve(stats);
				this._multilineData = [];
				this._currentCommand = void 0;
				return;
			}
			if (line.startsWith("STAT ")) {
				this._multilineData.push(line);
				return;
			}
			if (line.startsWith("ERROR") || line.startsWith("CLIENT_ERROR") || line.startsWith("SERVER_ERROR")) {
				this._currentCommand.reject(new Error(line));
				this._currentCommand = void 0;
				return;
			}
			return;
		}
		if (this._currentCommand.isConfig) {
			if (line.startsWith("CONFIG ")) {
				const sp1 = line.indexOf(" ");
				const sp2 = line.indexOf(" ", sp1 + 1);
				const sp3 = line.indexOf(" ", sp2 + 1);
				this._pendingValueBytes = Number.parseInt(line.substring(sp3 + 1), 10);
			} else if (line === "END") {
				const result = this._multilineData.length > 0 ? this._multilineData : void 0;
				this._currentCommand.resolve(result);
				this._multilineData = [];
				this._currentCommand = void 0;
			} else if (line.startsWith("ERROR") || line.startsWith("CLIENT_ERROR") || line.startsWith("SERVER_ERROR")) {
				this._currentCommand.reject(new Error(line));
				this._multilineData = [];
				this._currentCommand = void 0;
			}
			return;
		}
		if (this._currentCommand.isMultiline) {
			if (this._currentCommand.requestedKeys && !this._currentCommand.foundKeys) this._currentCommand.foundKeys = [];
			if (line.startsWith("VALUE ")) {
				const sp1 = line.indexOf(" ");
				const sp2 = line.indexOf(" ", sp1 + 1);
				const sp3 = line.indexOf(" ", sp2 + 1);
				const sp4 = line.indexOf(" ", sp3 + 1);
				const key = line.substring(sp1 + 1, sp2);
				const bytes = parseInt(sp4 === -1 ? line.substring(sp3 + 1) : line.substring(sp3 + 1, sp4), 10);
				if (this._currentCommand.requestedKeys) this._currentCommand.foundKeys?.push(key);
				if (bytes === 0) this._multilineData.push("");
				else this._pendingValueBytes = bytes;
			} else if (line === "END") {
				let result;
				if (this._currentCommand.requestedKeys && this._currentCommand.foundKeys) result = {
					values: this._multilineData.length > 0 ? this._multilineData : void 0,
					foundKeys: this._currentCommand.foundKeys
				};
				else result = this._multilineData.length > 0 ? this._multilineData : void 0;
				/* v8 ignore next -- @preserve */
				if (this._currentCommand.requestedKeys && this._currentCommand.foundKeys) {
					const foundKeys = this._currentCommand.foundKeys;
					for (let i = 0; i < foundKeys.length; i++) this.emit("hit", foundKeys[i], this._multilineData[i]);
					const missedKeys = this._currentCommand.requestedKeys.filter((key) => !foundKeys.includes(key));
					for (const key of missedKeys) this.emit("miss", key);
				}
				this._currentCommand.resolve(result);
				this._multilineData = [];
				this._currentCommand = void 0;
			} else if (line.startsWith("ERROR") || line.startsWith("CLIENT_ERROR") || line.startsWith("SERVER_ERROR")) {
				this._currentCommand.reject(new Error(line));
				this._multilineData = [];
				this._currentCommand = void 0;
			}
		} else {
			if (line === "STORED" || line === "DELETED" || line === "OK" || line === "TOUCHED" || line === "EXISTS" || line === "NOT_FOUND") this._currentCommand.resolve(line);
			else if (line === "NOT_STORED") this._currentCommand.resolve(false);
			else if (line.startsWith("ERROR") || line.startsWith("CLIENT_ERROR") || line.startsWith("SERVER_ERROR")) this._currentCommand.reject(new Error(line));
			else if (/^\d+$/.test(line)) this._currentCommand.resolve(parseInt(line, 10));
			else this._currentCommand.resolve(line);
			this._currentCommand = void 0;
		}
	}
	rejectPendingCommands(error) {
		if (this._currentCommand) {
			/* v8 ignore next -- @preserve */
			this._currentCommand.reject(error);
			/* v8 ignore next -- @preserve */
			this._currentCommand = void 0;
		}
		while (this._commandQueue.length > 0) {
			const cmd = this._commandQueue.shift();
			/* v8 ignore next -- @preserve */
			if (cmd) cmd.reject(error);
		}
	}
};
/**
* Factory function to create a new MemcacheNode instance.
* @param host - The hostname or IP address of the memcache server
* @param port - The port number of the memcache server
* @param options - Optional configuration for the node
* @returns A new MemcacheNode instance
*
* @example
* ```typescript
* const node = createNode('localhost', 11211, {
*   timeout: 5000,
*   keepAlive: true,
*   weight: 1
* });
* await node.connect();
* ```
*/
function createNode(host, port, options) {
	return new MemcacheNode(host, port, options);
}
//#endregion
//#region src/auto-discovery.ts
/**
* Handles AWS ElastiCache Auto Discovery for memcache clusters.
* Connects to a configuration endpoint, periodically polls for cluster
* topology changes, and emits events when nodes are added or removed.
*/
var AutoDiscovery = class AutoDiscovery extends Hookified {
	_configEndpoint;
	_pollingInterval;
	_useLegacyCommand;
	_configVersion = -1;
	_pollingTimer;
	_configNode;
	_timeout;
	_keepAlive;
	_keepAliveDelay;
	_sasl;
	_isRunning = false;
	_isPolling = false;
	constructor(options) {
		super({ throwOnEmptyListeners: false });
		this._configEndpoint = options.configEndpoint;
		this._pollingInterval = options.pollingInterval;
		this._useLegacyCommand = options.useLegacyCommand;
		this._timeout = options.timeout;
		this._keepAlive = options.keepAlive;
		this._keepAliveDelay = options.keepAliveDelay;
		this._sasl = options.sasl;
	}
	/** Current config version. -1 means no config has been fetched yet. */
	get configVersion() {
		return this._configVersion;
	}
	/** Whether auto discovery is currently running. */
	get isRunning() {
		return this._isRunning;
	}
	/** The configuration endpoint being used. */
	get configEndpoint() {
		return this._configEndpoint;
	}
	/**
	* Start the auto discovery process.
	* Performs an initial discovery, then starts the polling timer.
	*/
	async start() {
		if (this._isRunning) throw new Error("Auto discovery is already running");
		this._isRunning = true;
		let config;
		try {
			const configNode = await this.ensureConfigNode();
			config = await this.fetchConfig(configNode);
		} catch (error) {
			this._isRunning = false;
			throw error;
		}
		this._configVersion = config.version;
		this.emit("autoDiscover", config);
		this._pollingTimer = setInterval(() => {
			this.poll();
		}, this._pollingInterval);
		if (this._pollingTimer && typeof this._pollingTimer === "object" && "unref" in this._pollingTimer) this._pollingTimer.unref();
		return config;
	}
	/**
	* Stop the auto discovery process.
	*/
	async stop() {
		this._isRunning = false;
		if (this._pollingTimer) {
			clearInterval(this._pollingTimer);
			this._pollingTimer = void 0;
		}
		if (this._configNode) {
			await this._configNode.disconnect();
			this._configNode = void 0;
		}
	}
	/**
	* Perform a single discovery cycle.
	* Returns the ClusterConfig if the version has changed, or undefined if unchanged.
	*/
	async discover() {
		const configNode = await this.ensureConfigNode();
		const config = await this.fetchConfig(configNode);
		if (config.version === this._configVersion) return;
		this._configVersion = config.version;
		return config;
	}
	/**
	* Parse the raw response data from a config get cluster command.
	* The raw data is the value content between the CONFIG/VALUE header and END.
	* Format: "<version>\n<host1>|<ip1>|<port1> <host2>|<ip2>|<port2>\n"
	*/
	static parseConfigResponse(rawData) {
		if (!rawData || rawData.length === 0) throw new Error("Empty config response");
		const lines = rawData.join("").split("\n").filter((line) => line.trim().length > 0);
		if (lines.length < 2) throw new Error("Invalid config response: expected version and node list");
		const version = Number.parseInt(lines[0].trim(), 10);
		if (Number.isNaN(version)) throw new Error(`Invalid config version: ${lines[0]}`);
		return {
			version,
			nodes: lines[1].trim().split(" ").filter((e) => e.length > 0).map((entry) => AutoDiscovery.parseNodeEntry(entry))
		};
	}
	/**
	* Parse a single node entry in the format "hostname|ip|port".
	*/
	static parseNodeEntry(entry) {
		const parts = entry.split("|");
		if (parts.length !== 3) throw new Error(`Invalid node entry format: ${entry}`);
		const hostname = parts[0];
		const ip = parts[1];
		const port = Number.parseInt(parts[2], 10);
		if (!hostname) throw new Error(`Invalid node entry: missing hostname in ${entry}`);
		if (Number.isNaN(port) || port <= 0 || port > 65535) throw new Error(`Invalid port in node entry: ${entry}`);
		return {
			hostname,
			ip,
			port
		};
	}
	/**
	* Build a node ID from a DiscoveredNode.
	* Prefers IP when available, falls back to hostname.
	*/
	static nodeId(node) {
		const host = node.ip || node.hostname;
		return `${host.includes(":") ? `[${host}]` : host}:${node.port}`;
	}
	async ensureConfigNode() {
		if (this._configNode?.isConnected()) return this._configNode;
		const { host, port } = this.parseEndpoint(this._configEndpoint);
		this._configNode = new MemcacheNode(host, port, {
			timeout: this._timeout,
			keepAlive: this._keepAlive,
			keepAliveDelay: this._keepAliveDelay,
			sasl: this._sasl
		});
		await this._configNode.connect();
		return this._configNode;
	}
	async fetchConfig(node) {
		if (!node.isConnected()) await node.connect();
		if (this._useLegacyCommand) {
			const result = await node.command("get AmazonElastiCache:cluster", {
				isMultiline: true,
				requestedKeys: ["AmazonElastiCache:cluster"]
			});
			if (!result?.values || result.values.length === 0) throw new Error("No config data received from legacy command");
			return AutoDiscovery.parseConfigResponse(result.values);
		}
		const result = await node.command("config get cluster", { isConfig: true });
		if (!result || result.length === 0) throw new Error("No config data received");
		return AutoDiscovery.parseConfigResponse(result);
	}
	async poll() {
		if (this._isPolling) return;
		this._isPolling = true;
		try {
			const config = await this.discover();
			if (config) this.emit("autoDiscoverUpdate", config);
		} catch (error) {
			this.emit("autoDiscoverError", error);
			try {
				if (this._configNode && !this._configNode.isConnected()) await this._configNode.reconnect();
			} catch {}
		} finally {
			this._isPolling = false;
		}
	}
	parseEndpoint(endpoint) {
		if (endpoint.startsWith("[")) {
			const bracketEnd = endpoint.indexOf("]");
			if (bracketEnd === -1) throw new Error("Invalid IPv6 endpoint: missing closing bracket");
			const host = endpoint.slice(1, bracketEnd);
			const remainder = endpoint.slice(bracketEnd + 1);
			if (remainder === "" || remainder === ":") return {
				host,
				port: 11211
			};
			if (remainder.startsWith(":")) {
				const port = Number.parseInt(remainder.slice(1), 10);
				return {
					host,
					port: Number.isNaN(port) ? 11211 : port
				};
			}
			return {
				host,
				port: 11211
			};
		}
		const colonIndex = endpoint.lastIndexOf(":");
		if (colonIndex === -1) return {
			host: endpoint,
			port: 11211
		};
		const host = endpoint.slice(0, colonIndex);
		const port = Number.parseInt(endpoint.slice(colonIndex + 1), 10);
		return {
			host,
			port: Number.isNaN(port) ? 11211 : port
		};
	}
};
//#endregion
//#region src/broadcast.ts
/**
* A distribution hash implementation that sends every key to all nodes.
* Unlike KetamaHash or ModulaHash, this does not partition keys — every
* operation targets every node in the cluster.
*
* This is useful for replication scenarios where all nodes should hold
* the same data, or for broadcast operations like flush/delete.
*
* @example
* ```typescript
* const client = new Memcache({
*   nodes: ['server1:11211', 'server2:11211'],
*   hash: new BroadcastHash(),
* });
* // Every set/get/delete will hit all nodes
* ```
*/
var BroadcastHash = class {
	/** The name of this distribution strategy */
	name = "broadcast";
	/** Map of node IDs to MemcacheNode instances */
	nodeMap;
	/** Cached array of nodes, rebuilt only on add/remove */
	nodeCache;
	constructor() {
		this.nodeMap = /* @__PURE__ */ new Map();
		this.nodeCache = [];
	}
	/**
	* Gets all nodes in the distribution.
	* @returns Array of all MemcacheNode instances
	*/
	get nodes() {
		return [...this.nodeCache];
	}
	/**
	* Adds a node to the distribution.
	* @param node - The MemcacheNode to add
	*/
	addNode(node) {
		this.nodeMap.set(node.id, node);
		this.rebuildCache();
	}
	/**
	* Removes a node from the distribution by its ID.
	* @param id - The node ID (e.g., "localhost:11211")
	*/
	removeNode(id) {
		if (this.nodeMap.delete(id)) this.rebuildCache();
	}
	/**
	* Gets a specific node by its ID.
	* @param id - The node ID (e.g., "localhost:11211")
	* @returns The MemcacheNode if found, undefined otherwise
	*/
	getNode(id) {
		return this.nodeMap.get(id);
	}
	/**
	* Returns all nodes regardless of key. Every operation is broadcast
	* to every node in the cluster.
	* @param _key - The cache key (ignored — all nodes are always returned)
	* @returns Array of all MemcacheNode instances
	*/
	getNodesByKey(_key) {
		return [...this.nodeCache];
	}
	/**
	* Rebuilds the cached node array from the map.
	*/
	rebuildCache() {
		this.nodeCache = [...this.nodeMap.values()];
	}
};
//#endregion
//#region src/ketama.ts
/**
* Orginal Work is from https://github.com/connor4312/ketama
* Maintained in project for bug fixes and also configuration
* Thanks connor4312!
*/
/**
* FNV-1a 32-bit hash operating directly on a JS string.
* Much faster than crypto hashes for routing decisions.
*/
function fnv1aString$1(input) {
	let hash = 2166136261;
	for (let i = 0; i < input.length; i++) {
		hash ^= input.charCodeAt(i);
		hash = hash * 16777619 | 0;
	}
	return hash;
}
/**
* Creates a hash function using a built-in Node.js crypto algorithm.
* @param algorithm - The name of the hashing algorithm (e.g., "sha1", "md5")
* @returns A HashFunction that uses the specified algorithm
*/
const hashFunctionForBuiltin$1 = (algorithm) => (value) => createHash(algorithm).update(value).digest().readInt32BE();
/**
* Wraps a Buffer-based HashFunction into a StringHashFunction.
*/
function wrapBufferHash$1(fn) {
	return (input) => fn(Buffer.from(input));
}
/**
* Extracts the key from a node, whether it's a string or an object with a key property.
* @param node - The node to extract the key from
* @returns The key as a string
*/
const keyFor = (node) => typeof node === "string" ? node : node.key;
/**
* A consistent hashing implementation using the Ketama algorithm.
* This provides a way to distribute keys across nodes in a way that minimizes
* redistribution when nodes are added or removed.
*
* @template TNode - The type of nodes in the ring (string or object with key property)
*
* @example
* ```typescript
* // Create a ring with string nodes
* const ring = new HashRing(['server1', 'server2', 'server3']);
* const node = ring.getNode('my-key'); // Returns the node responsible for 'my-key'
*
* // Create a ring with weighted nodes
* const weightedRing = new HashRing([
*   { node: 'server1', weight: 2 },
*   { node: 'server2', weight: 1 }
* ]);
*
* // Create a ring with object nodes
* const objRing = new HashRing([
*   { key: 'server1', host: 'localhost', port: 11211 },
*   { key: 'server2', host: 'localhost', port: 11212 }
* ]);
* ```
*/
var HashRing = class HashRing {
	/**
	* Base weight of each node in the hash ring. Having a base weight of 1 is
	* not very desirable, since then, due to the ketama-style "clock", it's
	* possible to end up with a clock that's very skewed when dealing with a
	* small number of nodes. Setting to 50 nodes seems to give a better
	* distribution, so that load is spread roughly evenly to +/- 5%.
	*/
	static baseWeight = 50;
	/** The string-native hash function used on the hot path */
	hashStr;
	/** The sorted array of [hash, node key] tuples representing virtual nodes on the ring */
	_clock = [];
	/** Map of node keys to actual node objects */
	_nodes = /* @__PURE__ */ new Map();
	/**
	* Gets the sorted array of [hash, node key] tuples representing virtual nodes on the ring.
	* @returns The hash clock array
	*/
	get clock() {
		return this._clock;
	}
	/**
	* Gets the map of node keys to actual node objects.
	* @returns The nodes map
	*/
	get nodes() {
		return this._nodes;
	}
	/**
	* Creates a new HashRing instance.
	*
	* @param initialNodes - Array of nodes to add to the ring, optionally with weights
	* @param hashFn - Hash function to use (string algorithm name or custom function, defaults to "sha1")
	*
	* @example
	* ```typescript
	* // Simple ring with default SHA-1 hashing
	* const ring = new HashRing(['node1', 'node2']);
	*
	* // Ring with custom hash function
	* const customRing = new HashRing(['node1', 'node2'], 'md5');
	*
	* // Ring with weighted nodes
	* const weightedRing = new HashRing([
	*   { node: 'heavy-server', weight: 3 },
	*   { node: 'light-server', weight: 1 }
	* ]);
	* ```
	*/
	constructor(initialNodes = [], hashFn) {
		this.hashStr = hashFn === void 0 ? fnv1aString$1 : typeof hashFn === "string" ? wrapBufferHash$1(hashFunctionForBuiltin$1(hashFn)) : wrapBufferHash$1(hashFn);
		for (const node of initialNodes) if (typeof node === "object" && "weight" in node && "node" in node) this.addNode(node.node, node.weight);
		else this.addNode(node);
	}
	/**
	* Add a new node to the ring. If the node already exists in the ring, it
	* will be updated. For example, you can use this to update the node's weight.
	*
	* @param node - The node to add to the ring
	* @param weight - The relative weight of this node (default: 1). Higher weights mean more keys will be assigned to this node. A weight of 0 removes the node.
	* @throws {RangeError} If weight is negative
	*
	* @example
	* ```typescript
	* const ring = new HashRing();
	* ring.addNode('server1'); // Add with default weight of 1
	* ring.addNode('server2', 2); // Add with weight of 2 (will handle ~2x more keys)
	* ring.addNode('server1', 3); // Update server1's weight to 3
	* ring.addNode('server2', 0); // Remove server2
	* ```
	*/
	addNode(node, weight = 1) {
		if (weight === 0) this.removeNode(node);
		else if (weight < 0) throw new RangeError("Cannot add a node to the hashring with weight < 0");
		else {
			this.removeNode(node);
			const key = keyFor(node);
			this._nodes.set(key, node);
			this.addNodeToClock(key, Math.round(weight * HashRing.baseWeight));
		}
	}
	/**
	* Removes the node from the ring. No-op if the node does not exist.
	*
	* @param node - The node to remove from the ring
	*
	* @example
	* ```typescript
	* const ring = new HashRing(['server1', 'server2']);
	* ring.removeNode('server1'); // Removes server1 from the ring
	* ring.removeNode('nonexistent'); // Safe to call with non-existent node
	* ```
	*/
	removeNode(node) {
		const key = keyFor(node);
		if (this._nodes.delete(key)) this._clock = this._clock.filter(([, n]) => n !== key);
	}
	/**
	* Gets the node which should handle the given input key. Returns undefined if
	* the hashring has no nodes.
	*
	* Uses consistent hashing to ensure the same input always maps to the same node,
	* and minimizes redistribution when nodes are added or removed.
	*
	* @param input - The key to find the responsible node for (string or Buffer)
	* @returns The node responsible for this key, or undefined if ring is empty
	*
	* @example
	* ```typescript
	* const ring = new HashRing(['server1', 'server2', 'server3']);
	* const node = ring.getNode('user:123'); // Returns e.g., 'server2'
	* const sameNode = ring.getNode('user:123'); // Always returns 'server2'
	*
	* // Also accepts Buffer input
	* const bufferNode = ring.getNode(Buffer.from('user:123'));
	* ```
	*/
	getNode(input) {
		if (this._clock.length === 0) return;
		const index = this.getIndexForInput(input);
		const key = index === this._clock.length ? this._clock[0][1] : this._clock[index][1];
		return this._nodes.get(key);
	}
	/**
	* Finds the index in the clock for the given input by hashing it and performing binary search.
	*
	* @param input - The input to find the clock position for
	* @returns The index in the clock array
	*/
	getIndexForInput(input) {
		const hash = this.hashStr(typeof input === "string" ? input : input.toString("utf8"));
		return binarySearchRing(this._clock, hash);
	}
	/**
	* Gets multiple replica nodes that should handle the given input. Useful for
	* implementing replication strategies where you want to store data on multiple nodes.
	*
	* The returned array will contain unique nodes in the order they appear on the ring
	* starting from the primary node. If there are fewer nodes than replicas requested,
	* all nodes are returned.
	*
	* @param input - The key to find replica nodes for (string or Buffer)
	* @param replicas - The number of replica nodes to return
	* @returns Array of nodes that should handle this key (length ≤ replicas)
	*
	* @example
	* ```typescript
	* const ring = new HashRing(['server1', 'server2', 'server3', 'server4']);
	*
	* // Get 3 replicas for a key
	* const replicas = ring.getNodes('user:123', 3);
	* // Returns e.g., ['server2', 'server4', 'server1']
	*
	* // If requesting more replicas than nodes, returns all nodes
	* const allNodes = ring.getNodes('user:123', 10);
	* // Returns ['server1', 'server2', 'server3', 'server4']
	* ```
	*/
	getNodes(input, replicas) {
		if (this._clock.length === 0) return [];
		if (replicas >= this._nodes.size) return [...this._nodes.values()];
		const chosen = /* @__PURE__ */ new Set();
		for (let i = this.getIndexForInput(input); chosen.size < replicas; i++) chosen.add(this._clock[i % this._clock.length][1]);
		return [...chosen].map((c) => this._nodes.get(c));
	}
	/**
	* Adds virtual nodes to the clock for the given node key.
	* Creates multiple positions on the ring for better distribution.
	*
	* @param key - The node key to add to the clock
	* @param weight - The number of virtual nodes to create (weight * baseWeight)
	*/
	addNodeToClock(key, weight) {
		for (let i = weight; i > 0; i--) {
			const hash = this.hashStr(`${key}\0${i}`);
			this._clock.push([hash, key]);
		}
		this._clock.sort((a, b) => a[0] - b[0]);
	}
};
/**
* A distribution hash implementation using the Ketama consistent hashing algorithm.
* This class wraps the HashRing to implement the DistributionHash interface for use with Memcache.
*
* @example
* ```typescript
* const distribution = new KetamaDistributionHash();
* distribution.addNode(node1);
* distribution.addNode(node2);
* const targetNode = distribution.getNodesByKey('my-key')[0];
* ```
*/
const CACHE_MAX = 5e3;
var KetamaHash = class {
	/** The name of this distribution strategy */
	name = "ketama";
	/** Internal hash ring for consistent hashing */
	hashRing;
	/** Map of node IDs to MemcacheNode instances */
	nodeMap;
	/** Bounded cache: key → [node] array to avoid re-hashing and array allocation */
	_cache = /* @__PURE__ */ new Map();
	/**
	* Creates a new KetamaDistributionHash instance.
	*
	* @param hashFn - Hash function to use (string algorithm name or custom function, defaults to "sha1")
	*
	* @example
	* ```typescript
	* // Use default SHA-1 hashing
	* const distribution = new KetamaDistributionHash();
	*
	* // Use MD5 hashing
	* const distribution = new KetamaDistributionHash('md5');
	* ```
	*/
	constructor(hashFn) {
		this.hashRing = new HashRing([], hashFn);
		this.nodeMap = /* @__PURE__ */ new Map();
	}
	/**
	* Gets all nodes in the distribution.
	* @returns Array of all MemcacheNode instances
	*/
	get nodes() {
		return Array.from(this.nodeMap.values());
	}
	/**
	* Adds a node to the distribution with its weight for consistent hashing.
	*
	* @param node - The MemcacheNode to add
	*
	* @example
	* ```typescript
	* const node = new MemcacheNode('localhost', 11211, { weight: 2 });
	* distribution.addNode(node);
	* ```
	*/
	addNode(node) {
		this.nodeMap.set(node.id, node);
		this.hashRing.addNode(node.id, node.weight);
		this._cache.clear();
	}
	/**
	* Removes a node from the distribution by its ID.
	*
	* @param id - The node ID (e.g., "localhost:11211")
	*
	* @example
	* ```typescript
	* distribution.removeNode('localhost:11211');
	* ```
	*/
	removeNode(id) {
		this.nodeMap.delete(id);
		this.hashRing.removeNode(id);
		this._cache.clear();
	}
	/**
	* Gets a specific node by its ID.
	*
	* @param id - The node ID (e.g., "localhost:11211")
	* @returns The MemcacheNode if found, undefined otherwise
	*
	* @example
	* ```typescript
	* const node = distribution.getNode('localhost:11211');
	* if (node) {
	*   console.log(`Found node: ${node.uri}`);
	* }
	* ```
	*/
	getNode(id) {
		return this.nodeMap.get(id);
	}
	/**
	* Gets the nodes responsible for a given key using consistent hashing.
	* Currently returns a single node (the primary node for the key).
	*
	* @param key - The cache key to find the responsible node for
	* @returns Array containing the responsible node(s), empty if no nodes available
	*
	* @example
	* ```typescript
	* const nodes = distribution.getNodesByKey('user:123');
	* if (nodes.length > 0) {
	*   console.log(`Key will be stored on: ${nodes[0].id}`);
	* }
	* ```
	*/
	getNodesByKey(key) {
		const cached = this._cache.get(key);
		if (cached) return cached;
		const nodeId = this.hashRing.getNode(key);
		if (!nodeId) return [];
		const node = this.nodeMap.get(nodeId);
		/* v8 ignore next -- @preserve */
		if (!node) return [];
		const result = Object.freeze([node]);
		if (this._cache.size >= CACHE_MAX) this._cache.clear();
		this._cache.set(key, result);
		return result;
	}
};
/**
* Performs binary search on the hash ring to find the appropriate position for a given hash.
* Returns the index of the first virtual node with a hash value >= the input hash.
* If no such node exists, returns the length of the ring (wraps to beginning).
*
* @param ring - The sorted array of [hash, node] tuples
* @param hash - The hash value to search for
* @returns The index where the hash should be inserted or the next node position
*/
function binarySearchRing(ring, hash) {
	let mid;
	let lo = 0;
	let hi = ring.length - 1;
	while (lo <= hi) {
		mid = Math.floor((lo + hi) / 2);
		if (ring[mid][0] >= hash) hi = mid - 1;
		else lo = mid + 1;
	}
	return lo;
}
//#endregion
//#region src/modula.ts
/**
* FNV-1a 32-bit hash operating directly on a JS string.
* Returns unsigned 32-bit integer.
*/
function fnv1aString(input) {
	let hash = 2166136261;
	for (let i = 0; i < input.length; i++) {
		hash ^= input.charCodeAt(i);
		hash = hash * 16777619 | 0;
	}
	return hash >>> 0;
}
/**
* Creates a hash function using a built-in Node.js crypto algorithm.
* @param algorithm - The name of the hashing algorithm (e.g., "sha1", "md5")
* @returns A HashFunction that uses the specified algorithm
*/
const hashFunctionForBuiltin = (algorithm) => (value) => createHash(algorithm).update(value).digest().readUInt32BE(0);
/**
* Wraps a Buffer-based HashFunction into a StringHashFunction.
*/
function wrapBufferHash(fn) {
	return (input) => fn(Buffer.from(input));
}
/**
* A distribution hash implementation using modulo-based hashing.
* This class provides a simple key distribution strategy where keys are
* assigned to nodes using `hash(key) % nodeCount`.
*
* Unlike consistent hashing (Ketama), modulo hashing redistributes all keys
* when nodes are added or removed. This makes it suitable for:
* - Fixed-size clusters
* - Testing environments
* - Scenarios where simplicity is preferred over minimal redistribution
*
* @example
* ```typescript
* const distribution = new ModulaHash();
* distribution.addNode(node1);
* distribution.addNode(node2);
* const targetNode = distribution.getNodesByKey('my-key')[0];
* ```
*/
var ModulaHash = class {
	/** The name of this distribution strategy */
	name = "modula";
	/** The string-native hash function used on the hot path */
	hashStr;
	/** Map of node IDs to MemcacheNode instances */
	nodeMap;
	/**
	* Weighted list of node IDs for modulo distribution.
	* Nodes with higher weights appear multiple times.
	*/
	nodeList;
	/**
	* Creates a new ModulaHash instance.
	*
	* @param hashFn - Hash function to use (string algorithm name or custom function, defaults to "sha1")
	*
	* @example
	* ```typescript
	* // Use default SHA-1 hashing
	* const distribution = new ModulaHash();
	*
	* // Use MD5 hashing
	* const distribution = new ModulaHash('md5');
	*
	* // Use custom hash function
	* const distribution = new ModulaHash((buf) => buf.readUInt32BE(0));
	* ```
	*/
	constructor(hashFn) {
		this.hashStr = hashFn === void 0 ? fnv1aString : typeof hashFn === "string" ? wrapBufferHash(hashFunctionForBuiltin(hashFn)) : wrapBufferHash(hashFn);
		this.nodeMap = /* @__PURE__ */ new Map();
		this.nodeList = [];
	}
	/**
	* Gets all nodes in the distribution.
	* @returns Array of all MemcacheNode instances
	*/
	get nodes() {
		return Array.from(this.nodeMap.values());
	}
	/**
	* Adds a node to the distribution with its weight.
	* Weight determines how many times the node appears in the distribution list.
	*
	* @param node - The MemcacheNode to add
	*
	* @example
	* ```typescript
	* const node = new MemcacheNode('localhost', 11211, { weight: 2 });
	* distribution.addNode(node);
	* ```
	*/
	addNode(node) {
		this.nodeMap.set(node.id, node);
		const weight = node.weight || 1;
		for (let i = 0; i < weight; i++) this.nodeList.push(node.id);
	}
	/**
	* Removes a node from the distribution by its ID.
	*
	* @param id - The node ID (e.g., "localhost:11211")
	*
	* @example
	* ```typescript
	* distribution.removeNode('localhost:11211');
	* ```
	*/
	removeNode(id) {
		this.nodeMap.delete(id);
		this.nodeList = this.nodeList.filter((nodeId) => nodeId !== id);
	}
	/**
	* Gets a specific node by its ID.
	*
	* @param id - The node ID (e.g., "localhost:11211")
	* @returns The MemcacheNode if found, undefined otherwise
	*
	* @example
	* ```typescript
	* const node = distribution.getNode('localhost:11211');
	* if (node) {
	*   console.log(`Found node: ${node.uri}`);
	* }
	* ```
	*/
	getNode(id) {
		return this.nodeMap.get(id);
	}
	/**
	* Gets the nodes responsible for a given key using modulo hashing.
	* Uses `hash(key) % nodeCount` to determine the target node.
	*
	* @param key - The cache key to find the responsible node for
	* @returns Array containing the responsible node(s), empty if no nodes available
	*
	* @example
	* ```typescript
	* const nodes = distribution.getNodesByKey('user:123');
	* if (nodes.length > 0) {
	*   console.log(`Key will be stored on: ${nodes[0].id}`);
	* }
	* ```
	*/
	getNodesByKey(key) {
		if (this.nodeList.length === 0) return [];
		const index = this.hashStr(key) % this.nodeList.length;
		const nodeId = this.nodeList[index];
		const node = this.nodeMap.get(nodeId);
		/* v8 ignore next -- @preserve */
		return node ? [node] : [];
	}
};
//#endregion
//#region src/types.ts
let MemcacheEvents = /* @__PURE__ */ function(MemcacheEvents) {
	MemcacheEvents["CONNECT"] = "connect";
	MemcacheEvents["QUIT"] = "quit";
	MemcacheEvents["HIT"] = "hit";
	MemcacheEvents["MISS"] = "miss";
	MemcacheEvents["ERROR"] = "error";
	MemcacheEvents["WARN"] = "warn";
	MemcacheEvents["INFO"] = "info";
	MemcacheEvents["TIMEOUT"] = "timeout";
	MemcacheEvents["CLOSE"] = "close";
	MemcacheEvents["AUTO_DISCOVER"] = "autoDiscover";
	MemcacheEvents["AUTO_DISCOVER_ERROR"] = "autoDiscoverError";
	MemcacheEvents["AUTO_DISCOVER_UPDATE"] = "autoDiscoverUpdate";
	return MemcacheEvents;
}({});
//#endregion
//#region src/index.ts
/**
* Default backoff function - returns fixed delay
*/
const defaultRetryBackoff = (_attempt, baseDelay) => baseDelay;
/**
* Exponential backoff function - doubles delay each attempt
*/
const exponentialRetryBackoff = (attempt, baseDelay) => baseDelay * 2 ** attempt;
const KEY_INVALID_CHARS = /[\s\r\n\0]/;
/**
* Resolve the user-supplied `hashLargeKey` option into the (enabled, hashery)
* pair used internally. A boolean value selects/disables the feature with a
* fresh Hashery; passing a Hashery instance enables the feature and uses that
* instance verbatim.
*/
function resolveHashLargeKeyOption(value) {
	if (value instanceof Hashery) return {
		enabled: true,
		hashery: value
	};
	return {
		enabled: value === true,
		hashery: new Hashery()
	};
}
/**
* Check if all results match an expected value.
* Fast-paths single-element arrays to avoid .every() overhead.
*/
function allResultsEqual(results, expected) {
	if (results.length === 1) return results[0] === expected;
	return results.every((r) => r === expected);
}
var Memcache = class extends Hookified {
	_nodes = [];
	_timeout;
	_keepAlive;
	_keepAliveDelay;
	_hash;
	_retries;
	_retryDelay;
	_retryBackoff;
	_retryOnlyIdempotent;
	_sasl;
	_tls;
	_autoDiscovery;
	_autoDiscoverOptions;
	_lazyConnect;
	_maxKeySize;
	_maxValueSize;
	_maxExpiration;
	_hashLargeKey;
	_hashery;
	constructor(options) {
		super({ throwOnEmptyListeners: false });
		if (typeof options === "string") {
			this._hash = new KetamaHash();
			this._timeout = 5e3;
			this._keepAlive = true;
			this._keepAliveDelay = 1e3;
			this._retries = 0;
			this._retryDelay = 100;
			this._retryBackoff = defaultRetryBackoff;
			this._retryOnlyIdempotent = true;
			this._sasl = void 0;
			this._tls = void 0;
			this._lazyConnect = true;
			this._maxKeySize = 250;
			this._maxValueSize = 1048576;
			this._maxExpiration = 2592e3;
			const stringResolved = resolveHashLargeKeyOption(void 0);
			this._hashLargeKey = stringResolved.enabled;
			this._hashery = stringResolved.hashery;
			this.addNode(options);
		} else {
			this._hash = options?.hash ?? new KetamaHash();
			this._timeout = options?.timeout || 5e3;
			this._keepAlive = options?.keepAlive !== false;
			this._keepAliveDelay = options?.keepAliveDelay || 1e3;
			this._retries = options?.retries ?? 0;
			this._retryDelay = options?.retryDelay ?? 100;
			this._retryBackoff = options?.retryBackoff ?? defaultRetryBackoff;
			this._retryOnlyIdempotent = options?.retryOnlyIdempotent ?? true;
			this._sasl = options?.sasl;
			this._tls = options?.tls;
			this._lazyConnect = options?.lazyConnect ?? true;
			this._maxKeySize = Math.max(0, Math.floor(Number.isFinite(options?.maxKeySize) ? options?.maxKeySize : 250));
			this._maxValueSize = Math.max(0, Math.floor(Number.isFinite(options?.maxValueSize) ? options?.maxValueSize : 1048576));
			this._maxExpiration = Math.max(0, Math.floor(Number.isFinite(options?.maxExpiration) ? options?.maxExpiration : 2592e3));
			const optionsResolved = resolveHashLargeKeyOption(options?.hashLargeKey);
			this._hashLargeKey = optionsResolved.enabled;
			this._hashery = optionsResolved.hashery;
			this._autoDiscoverOptions = options?.autoDiscover;
			const nodeUris = options?.nodes || ["localhost:11211"];
			for (const nodeUri of nodeUris) this.addNode(nodeUri);
		}
		if (!this._lazyConnect) process.nextTick(() => {
			this.connect().catch((error) => {
				/* v8 ignore next -- @preserve */
				this.emit("error", "connect", error);
			});
		});
	}
	/**
	* Get the list of nodes
	* @returns {MemcacheNode[]} Array of MemcacheNode
	*/
	get nodes() {
		return this._nodes;
	}
	/**
	* Get the list of node IDs (e.g., ["localhost:11211", "127.0.0.1:11212"])
	* @returns {string[]} Array of node ID strings
	*/
	get nodeIds() {
		return this._nodes.map((node) => node.id);
	}
	/**
	* Get the hash provider used for consistent hashing distribution.
	* @returns {HashProvider} The current hash provider instance
	* @default KetamaHash
	*
	* @example
	* ```typescript
	* const client = new Memcache();
	* const hashProvider = client.hash;
	* console.log(hashProvider.name); // "ketama"
	* ```
	*/
	get hash() {
		return this._hash;
	}
	/**
	* Set the hash provider used for consistent hashing distribution.
	* This allows you to customize the hashing strategy for distributing keys across nodes.
	* @param {HashProvider} hash - The hash provider instance to use
	*
	* @example
	* ```typescript
	* const client = new Memcache();
	* const customHashProvider = new KetamaHash();
	* client.hash = customHashProvider;
	* ```
	*/
	set hash(hash) {
		this._hash = hash;
	}
	/**
	* Get the timeout for Memcache operations.
	* @returns {number}
	* @default 5000
	*/
	get timeout() {
		return this._timeout;
	}
	/**
	* Set the timeout for Memcache operations.
	* @param {number} value
	* @default 5000
	*/
	set timeout(value) {
		this._timeout = value;
	}
	/**
	* Get the maximum allowed key size (in characters).
	* @returns {number}
	* @default 250
	*/
	get maxKeySize() {
		return this._maxKeySize;
	}
	/**
	* Set the maximum allowed key size (in characters). Memcache protocol max is 250.
	* @param {number} value
	* @default 250
	*/
	set maxKeySize(value) {
		this._maxKeySize = Math.max(0, Math.floor(Number.isFinite(value) ? value : 0));
	}
	/**
	* Whether keys exceeding `maxKeySize` are hashed with djb2 instead of throwing.
	* @returns {boolean}
	* @default false
	*/
	get hashLargeKey() {
		return this._hashLargeKey;
	}
	/**
	* Enable or disable hashing of keys that exceed `maxKeySize`.
	* When true, oversized keys are deterministically hashed before validation
	* using the configured `hashery` instance. When false, oversized keys throw
	* a validation error. To change the algorithm or providers, mutate or
	* replace the `hashery` property instead.
	* @param {boolean} value
	* @default false
	*/
	set hashLargeKey(value) {
		this._hashLargeKey = value;
	}
	/**
	* The `Hashery` instance used to hash oversized keys when `hashLargeKey`
	* is enabled. Always returns an instance, even when hashing is disabled,
	* so callers can pre-configure it (e.g. set `defaultAlgorithmSync` or
	* register custom providers) before flipping `hashLargeKey` on.
	* @returns {Hashery}
	*/
	get hashery() {
		return this._hashery;
	}
	/**
	* Replace the `Hashery` instance used to hash oversized keys.
	* @param {Hashery} value
	*/
	set hashery(value) {
		this._hashery = value;
	}
	/**
	* Get the maximum allowed value size (in bytes).
	* @returns {number}
	* @default 1048576
	*/
	get maxValueSize() {
		return this._maxValueSize;
	}
	/**
	* Set the maximum allowed value size (in bytes). Memcached default max is 1048576 (1 MiB).
	* @param {number} value
	* @default 1048576
	*/
	set maxValueSize(value) {
		this._maxValueSize = Math.max(0, Math.floor(Number.isFinite(value) ? value : 0));
	}
	/**
	* Get the maximum allowed expiration time (in seconds).
	* @returns {number}
	* @default 2592000
	*/
	get maxExpiration() {
		return this._maxExpiration;
	}
	/**
	* Set the maximum allowed expiration time (in seconds). Memcached treats values
	* greater than 2592000 (30 days) as absolute Unix timestamps. `0` (no expiration)
	* is always allowed regardless of this limit.
	* @param {number} value
	* @default 2592000
	*/
	set maxExpiration(value) {
		this._maxExpiration = Math.max(0, Math.floor(Number.isFinite(value) ? value : 0));
	}
	/**
	* Get the keepAlive setting for the Memcache connection.
	* @returns {boolean}
	* @default true
	*/
	get keepAlive() {
		return this._keepAlive;
	}
	/**
	* Set the keepAlive setting for the Memcache connection.
	* Updates all existing nodes with the new value.
	* Note: To apply the new value, you need to call reconnect() on the nodes.
	* @param {boolean} value
	* @default true
	*/
	set keepAlive(value) {
		this._keepAlive = value;
		this.updateNodes();
	}
	/**
	* Get the delay before the connection is kept alive.
	* @returns {number}
	* @default 1000
	*/
	get keepAliveDelay() {
		return this._keepAliveDelay;
	}
	/**
	* Set the delay before the connection is kept alive.
	* Updates all existing nodes with the new value.
	* Note: To apply the new value, you need to call reconnect() on the nodes.
	* @param {number} value
	* @default 1000
	*/
	set keepAliveDelay(value) {
		this._keepAliveDelay = value;
		this.updateNodes();
	}
	/**
	* Get the number of retry attempts for failed commands.
	* @returns {number}
	* @default 0
	*/
	get retries() {
		return this._retries;
	}
	/**
	* Set the number of retry attempts for failed commands.
	* Set to 0 to disable retries.
	* @param {number} value
	* @default 0
	*/
	set retries(value) {
		this._retries = Math.max(0, Math.floor(Number.isFinite(value) ? value : 0));
	}
	/**
	* Get the base delay in milliseconds between retry attempts.
	* @returns {number}
	* @default 100
	*/
	get retryDelay() {
		return this._retryDelay;
	}
	/**
	* Set the base delay in milliseconds between retry attempts.
	* @param {number} value
	* @default 100
	*/
	set retryDelay(value) {
		this._retryDelay = Math.max(0, value);
	}
	/**
	* Get the backoff function for retry delays.
	* @returns {RetryBackoffFunction}
	* @default defaultRetryBackoff
	*/
	get retryBackoff() {
		return this._retryBackoff;
	}
	/**
	* Set the backoff function for retry delays.
	* @param {RetryBackoffFunction} value
	* @default defaultRetryBackoff
	*/
	set retryBackoff(value) {
		this._retryBackoff = value;
	}
	/**
	* Get whether retries are restricted to idempotent commands only.
	* @returns {boolean}
	* @default true
	*/
	get retryOnlyIdempotent() {
		return this._retryOnlyIdempotent;
	}
	/**
	* Set whether retries are restricted to idempotent commands only.
	* When true (default), retries only occur for commands explicitly marked
	* as idempotent via ExecuteOptions. This prevents accidental double-execution
	* of non-idempotent operations like incr, decr, append, etc.
	* @param {boolean} value
	* @default true
	*/
	set retryOnlyIdempotent(value) {
		this._retryOnlyIdempotent = value;
	}
	/**
	* Whether nodes defer connecting until the first command is executed.
	* @returns {boolean}
	* @default true
	*/
	get lazyConnect() {
		return this._lazyConnect;
	}
	/**
	* Get an array of all MemcacheNode instances
	* @returns {MemcacheNode[]}
	*/
	getNodes() {
		return [...this._nodes];
	}
	/**
	* Get a specific node by its ID
	* @param {string} id - The node ID (e.g., "localhost:11211")
	* @returns {MemcacheNode | undefined}
	*/
	getNode(id) {
		return this._nodes.find((n) => n.id === id);
	}
	/**
	* Add a new node to the cluster
	* @param {string | MemcacheNode} uri - Node URI (e.g., "localhost:11212") or a MemcacheNode instance
	* @param {number} weight - Optional weight for consistent hashing (only used for string URIs)
	*/
	async addNode(uri, weight) {
		let node;
		let nodeKey;
		if (typeof uri === "string") {
			const { host, port, secure } = this.parseUri(uri);
			nodeKey = port === 0 ? host : `${host}:${port}`;
			if (this._nodes.some((n) => n.id === nodeKey)) throw new Error(`Node ${nodeKey} already exists`);
			node = new MemcacheNode(host, port, {
				timeout: this._timeout,
				keepAlive: this._keepAlive,
				keepAliveDelay: this._keepAliveDelay,
				weight,
				sasl: this._sasl,
				tls: secure ? this._tls || true : this._tls
			});
		} else {
			node = uri;
			nodeKey = node.id;
			if (this._nodes.some((n) => n.id === nodeKey)) throw new Error(`Node ${nodeKey} already exists`);
		}
		this.forwardNodeEvents(node);
		this._nodes.push(node);
		this._hash.addNode(node);
	}
	/**
	* Remove a node from the cluster
	* @param {string} uri - Node URI (e.g., "localhost:11212")
	*/
	async removeNode(uri) {
		const { host, port } = this.parseUri(uri);
		const nodeKey = port === 0 ? host : `${host}:${port}`;
		const node = this._nodes.find((n) => n.id === nodeKey);
		if (!node) return;
		await node.disconnect();
		this._nodes = this._nodes.filter((n) => n.id !== nodeKey);
		this._hash.removeNode(node.id);
	}
	/**
	* Parse a URI string into host and port.
	* Supports multiple formats:
	* - Simple: "localhost:11211" or "localhost"
	* - Protocol: "memcache://localhost:11211", "memcached://localhost:11211", "tcp://localhost:11211"
	* - TLS: "memcaches://localhost:11211" (sets `secure: true`, enabling TLS for the node)
	* - IPv6: "[::1]:11211" or "memcache://[2001:db8::1]:11212"
	* - Unix socket: "/var/run/memcached.sock" or "unix:///var/run/memcached.sock"
	*
	* @param {string} uri - URI string
	* @returns {{ host: string; port: number; secure?: boolean }} Object containing host and port (port is 0 for Unix sockets); `secure` is true for memcaches:// URIs
	* @throws {Error} If URI format is invalid
	*/
	parseUri(uri) {
		if (uri.startsWith("unix://")) return {
			host: uri.slice(7),
			port: 0
		};
		if (uri.startsWith("/")) return {
			host: uri,
			port: 0
		};
		let cleanUri = uri;
		let secure;
		if (uri.includes("://")) {
			const protocolParts = uri.split("://");
			const protocol = protocolParts[0];
			if (![
				"memcache",
				"memcached",
				"memcaches",
				"tcp"
			].includes(protocol)) throw new Error(`Invalid protocol '${protocol}'. Supported protocols: memcache://, memcached://, memcaches://, tcp://, unix://`);
			if (protocol === "memcaches") secure = true;
			cleanUri = protocolParts[1];
		}
		if (cleanUri.startsWith("[")) {
			const bracketEnd = cleanUri.indexOf("]");
			if (bracketEnd === -1) throw new Error("Invalid IPv6 format: missing closing bracket");
			const host = cleanUri.slice(1, bracketEnd);
			if (!host) throw new Error("Invalid URI format: host is required");
			const remainder = cleanUri.slice(bracketEnd + 1);
			if (remainder === "") return {
				host,
				port: 11211,
				secure
			};
			if (!remainder.startsWith(":")) throw new Error("Invalid IPv6 format: expected ':' after bracket");
			const portStr = remainder.slice(1);
			const port = Number.parseInt(portStr, 10);
			if (Number.isNaN(port) || port <= 0 || port > 65535) throw new Error("Invalid port number");
			return {
				host,
				port,
				secure
			};
		}
		const parts = cleanUri.split(":");
		if (parts.length === 0 || parts.length > 2) throw new Error("Invalid URI format");
		const host = parts[0];
		if (!host) throw new Error("Invalid URI format: host is required");
		const port = parts.length === 2 ? Number.parseInt(parts[1], 10) : 11211;
		if (Number.isNaN(port) || port < 0 || port > 65535) throw new Error("Invalid port number");
		if (port === 0) throw new Error("Invalid port number");
		return {
			host,
			port,
			secure
		};
	}
	/**
	* Connect to all Memcache servers or a specific node.
	* @param {string} nodeId - Optional node ID to connect to (e.g., "localhost:11211")
	* @returns {Promise<void>}
	*/
	async connect(nodeId) {
		if (nodeId) {
			const node = this._nodes.find((n) => n.id === nodeId);
			/* v8 ignore next -- @preserve */
			if (!node) throw new Error(`Node ${nodeId} not found`);
			/* v8 ignore next -- @preserve */
			await node.connect();
			/* v8 ignore next -- @preserve */
			return;
		}
		await Promise.all(this._nodes.map((node) => node.connect()));
		if (this._autoDiscoverOptions?.enabled && !this._autoDiscovery) await this.startAutoDiscovery();
	}
	/**
	* Get a value from the Memcache server.
	* When multiple nodes are returned by the hash provider (for replication),
	* queries all nodes and returns the first successful result.
	* @param {string} key
	* @returns {Promise<string | undefined>}
	*/
	async get(key) {
		const hasHooks = this._hasHooks;
		if (hasHooks) await this.beforeHook("get", { key });
		const resolvedKey = this.resolveKey(key);
		this.validateKey(resolvedKey);
		const nodes = await this.getNodesByKey(resolvedKey);
		const commandOptions = {
			isMultiline: true,
			requestedKeys: [resolvedKey]
		};
		let value;
		for (const node of nodes) try {
			const result = await node.command(`get ${resolvedKey}`, commandOptions);
			if (result?.values && result.values.length > 0) {
				value = result.values[0];
				break;
			}
		} catch {}
		if (hasHooks) await this.afterHook("get", {
			key,
			value
		});
		return value;
	}
	/**
	* Get multiple values from the Memcache server.
	* When multiple nodes are returned by the hash provider (for replication),
	* queries all replica nodes and returns the first successful result for each key.
	* @param keys {string[]}
	* @returns {Promise<Map<string, string>>}
	*/
	async gets(keys) {
		if (this._hasHooks) await this.beforeHook("gets", { keys });
		const originalsByResolved = /* @__PURE__ */ new Map();
		for (const inputKey of keys) {
			const resolved = this.resolveKey(inputKey);
			this.validateKey(resolved);
			let originals = originalsByResolved.get(resolved);
			if (!originals) {
				originals = [];
				originalsByResolved.set(resolved, originals);
			}
			originals.push(inputKey);
		}
		const keysByNode = /* @__PURE__ */ new Map();
		const keyToReplicas = /* @__PURE__ */ new Map();
		for (const resolvedKey of originalsByResolved.keys()) {
			const nodes = this._hash.getNodesByKey(resolvedKey);
			/* v8 ignore next 4 -- @preserve */
			if (nodes.length === 0) {
				const firstOriginal = originalsByResolved.get(resolvedKey)[0];
				throw new Error(`No node available for key: ${firstOriginal}`);
			}
			const primary = nodes[0];
			if (!keysByNode.has(primary)) keysByNode.set(primary, []);
			keysByNode.get(primary).push(resolvedKey);
			if (nodes.length > 1) keyToReplicas.set(resolvedKey, nodes.slice(1));
		}
		const map = /* @__PURE__ */ new Map();
		const missingResolvedKeys = [];
		const promises = Array.from(keysByNode.entries()).map(async ([node, nodeKeys]) => {
			try {
				if (!node.isConnected()) await node.connect();
				const keysStr = nodeKeys.join(" ");
				return {
					nodeKeys,
					result: await node.command(`get ${keysStr}`, {
						isMultiline: true,
						requestedKeys: nodeKeys
					})
				};
			} catch {
				/* v8 ignore next -- @preserve */
				return {
					nodeKeys,
					result: void 0
				};
			}
		});
		const results = await Promise.all(promises);
		for (const { nodeKeys, result } of results) {
			if (result?.foundKeys && result.values) for (let i = 0; i < result.foundKeys.length; i++) {
				const foundResolved = result.foundKeys[i];
				const originals = originalsByResolved.get(foundResolved);
				for (const original of originals) map.set(original, result.values[i]);
			}
			for (const resolvedKey of nodeKeys) {
				const firstOriginal = originalsByResolved.get(resolvedKey)[0];
				if (!map.has(firstOriginal) && keyToReplicas.has(resolvedKey)) missingResolvedKeys.push(resolvedKey);
			}
		}
		for (const resolvedKey of missingResolvedKeys) {
			const replicas = keyToReplicas.get(resolvedKey);
			/* v8 ignore next -- @preserve */
			if (!replicas) continue;
			for (const replica of replicas) try {
				/* v8 ignore next -- @preserve */
				if (!replica.isConnected()) await replica.connect();
				const result = await replica.command(`get ${resolvedKey}`, {
					isMultiline: true,
					requestedKeys: [resolvedKey]
				});
				if (result?.values && result.values.length > 0) {
					const originals = originalsByResolved.get(resolvedKey);
					for (const original of originals) map.set(original, result.values[0]);
					break;
				}
			} catch {}
		}
		if (this._hasHooks) await this.afterHook("gets", {
			keys,
			values: map
		});
		return map;
	}
	/**
	* Check-And-Set: Store a value only if it hasn't been modified since last fetch.
	* When multiple nodes are returned by the hash provider (for replication),
	* executes on all nodes and returns true only if all succeed.
	* @param key {string}
	* @param value {string}
	* @param casToken {string}
	* @param exptime {number}
	* @param flags {number}
	* @returns {Promise<boolean>}
	*/
	async cas(key, value, casToken, exptime = 0, flags = 0) {
		if (this._hasHooks) await this.beforeHook("cas", {
			key,
			value,
			casToken,
			exptime,
			flags
		});
		const resolvedKey = this.resolveKey(key);
		this.validateKey(resolvedKey);
		const sanitizedExptime = this.validateExpiration(exptime);
		const valueStr = String(value);
		const command = `cas ${resolvedKey} ${flags} ${sanitizedExptime} ${this.validateValue(valueStr)} ${casToken}\r\n${valueStr}`;
		const nodes = await this.getNodesByKey(resolvedKey);
		const success = allResultsEqual(await this.execute(command, nodes), "STORED");
		if (this._hasHooks) await this.afterHook("cas", {
			key,
			value,
			casToken,
			exptime,
			flags,
			success
		});
		return success;
	}
	/**
	* Set a value in the Memcache server.
	* When multiple nodes are returned by the hash provider (for replication),
	* executes on all nodes and returns true only if all succeed.
	* @param key {string}
	* @param value {string}
	* @param exptime {number}
	* @param flags {number}
	* @returns {Promise<boolean>}
	*/
	async set(key, value, exptime = 0, flags = 0) {
		const hasHooks = this._hasHooks;
		if (hasHooks) await this.beforeHook("set", {
			key,
			value,
			exptime,
			flags
		});
		const resolvedKey = this.resolveKey(key);
		this.validateKey(resolvedKey);
		const command = `set ${resolvedKey} ${flags} ${this.validateExpiration(exptime)} ${this.validateValue(value)}\r\n${value}`;
		const nodes = await this.getNodesByKey(resolvedKey);
		const success = allResultsEqual(await this.execute(command, nodes), "STORED");
		if (hasHooks) await this.afterHook("set", {
			key,
			value,
			exptime,
			flags,
			success
		});
		return success;
	}
	/**
	* Add a value to the Memcache server (only if key doesn't exist).
	* When multiple nodes are returned by the hash provider (for replication),
	* executes on all nodes and returns true only if all succeed.
	* @param key {string}
	* @param value {string}
	* @param exptime {number}
	* @param flags {number}
	* @returns {Promise<boolean>}
	*/
	async add(key, value, exptime = 0, flags = 0) {
		if (this._hasHooks) await this.beforeHook("add", {
			key,
			value,
			exptime,
			flags
		});
		const resolvedKey = this.resolveKey(key);
		this.validateKey(resolvedKey);
		const sanitizedExptime = this.validateExpiration(exptime);
		const valueStr = String(value);
		const command = `add ${resolvedKey} ${flags} ${sanitizedExptime} ${this.validateValue(valueStr)}\r\n${valueStr}`;
		const nodes = await this.getNodesByKey(resolvedKey);
		const success = allResultsEqual(await this.execute(command, nodes), "STORED");
		if (this._hasHooks) await this.afterHook("add", {
			key,
			value,
			exptime,
			flags,
			success
		});
		return success;
	}
	/**
	* Replace a value in the Memcache server (only if key exists).
	* When multiple nodes are returned by the hash provider (for replication),
	* executes on all nodes and returns true only if all succeed.
	* @param key {string}
	* @param value {string}
	* @param exptime {number}
	* @param flags {number}
	* @returns {Promise<boolean>}
	*/
	async replace(key, value, exptime = 0, flags = 0) {
		if (this._hasHooks) await this.beforeHook("replace", {
			key,
			value,
			exptime,
			flags
		});
		const resolvedKey = this.resolveKey(key);
		this.validateKey(resolvedKey);
		const sanitizedExptime = this.validateExpiration(exptime);
		const valueStr = String(value);
		const command = `replace ${resolvedKey} ${flags} ${sanitizedExptime} ${this.validateValue(valueStr)}\r\n${valueStr}`;
		const nodes = await this.getNodesByKey(resolvedKey);
		const success = allResultsEqual(await this.execute(command, nodes), "STORED");
		if (this._hasHooks) await this.afterHook("replace", {
			key,
			value,
			exptime,
			flags,
			success
		});
		return success;
	}
	/**
	* Append a value to an existing key in the Memcache server.
	* When multiple nodes are returned by the hash provider (for replication),
	* executes on all nodes and returns true only if all succeed.
	* @param key {string}
	* @param value {string}
	* @returns {Promise<boolean>}
	*/
	async append(key, value) {
		if (this._hasHooks) await this.beforeHook("append", {
			key,
			value
		});
		const resolvedKey = this.resolveKey(key);
		this.validateKey(resolvedKey);
		const valueStr = String(value);
		const command = `append ${resolvedKey} 0 0 ${this.validateValue(valueStr)}\r\n${valueStr}`;
		const nodes = await this.getNodesByKey(resolvedKey);
		const success = allResultsEqual(await this.execute(command, nodes), "STORED");
		if (this._hasHooks) await this.afterHook("append", {
			key,
			value,
			success
		});
		return success;
	}
	/**
	* Prepend a value to an existing key in the Memcache server.
	* When multiple nodes are returned by the hash provider (for replication),
	* executes on all nodes and returns true only if all succeed.
	* @param key {string}
	* @param value {string}
	* @returns {Promise<boolean>}
	*/
	async prepend(key, value) {
		if (this._hasHooks) await this.beforeHook("prepend", {
			key,
			value
		});
		const resolvedKey = this.resolveKey(key);
		this.validateKey(resolvedKey);
		const valueStr = String(value);
		const command = `prepend ${resolvedKey} 0 0 ${this.validateValue(valueStr)}\r\n${valueStr}`;
		const nodes = await this.getNodesByKey(resolvedKey);
		const success = allResultsEqual(await this.execute(command, nodes), "STORED");
		if (this._hasHooks) await this.afterHook("prepend", {
			key,
			value,
			success
		});
		return success;
	}
	/**
	* Delete a value from the Memcache server.
	* When multiple nodes are returned by the hash provider (for replication),
	* executes on all nodes and returns true only if all succeed.
	* @param key {string}
	* @returns {Promise<boolean>}
	*/
	async delete(key) {
		if (this._hasHooks) await this.beforeHook("delete", { key });
		const resolvedKey = this.resolveKey(key);
		this.validateKey(resolvedKey);
		const nodes = await this.getNodesByKey(resolvedKey);
		const success = allResultsEqual(await this.execute(`delete ${resolvedKey}`, nodes), "DELETED");
		if (this._hasHooks) await this.afterHook("delete", {
			key,
			success
		});
		return success;
	}
	/**
	* Increment a value in the Memcache server.
	* When multiple nodes are returned by the hash provider (for replication),
	* executes on all nodes and returns the first successful result.
	* @param key {string}
	* @param value {number}
	* @returns {Promise<number | undefined>}
	*/
	async incr(key, value = 1) {
		if (this._hasHooks) await this.beforeHook("incr", {
			key,
			value
		});
		const resolvedKey = this.resolveKey(key);
		this.validateKey(resolvedKey);
		const nodes = await this.getNodesByKey(resolvedKey);
		const newValue = (await this.execute(`incr ${resolvedKey} ${value}`, nodes)).find((v) => typeof v === "number");
		if (this._hasHooks) await this.afterHook("incr", {
			key,
			value,
			newValue
		});
		return newValue;
	}
	/**
	* Decrement a value in the Memcache server.
	* When multiple nodes are returned by the hash provider (for replication),
	* executes on all nodes and returns the first successful result.
	* @param key {string}
	* @param value {number}
	* @returns {Promise<number | undefined>}
	*/
	async decr(key, value = 1) {
		if (this._hasHooks) await this.beforeHook("decr", {
			key,
			value
		});
		const resolvedKey = this.resolveKey(key);
		this.validateKey(resolvedKey);
		const nodes = await this.getNodesByKey(resolvedKey);
		const newValue = (await this.execute(`decr ${resolvedKey} ${value}`, nodes)).find((v) => typeof v === "number");
		if (this._hasHooks) await this.afterHook("decr", {
			key,
			value,
			newValue
		});
		return newValue;
	}
	/**
	* Touch a value in the Memcache server (update expiration time).
	* When multiple nodes are returned by the hash provider (for replication),
	* executes on all nodes and returns true only if all succeed.
	* @param key {string}
	* @param exptime {number}
	* @returns {Promise<boolean>}
	*/
	async touch(key, exptime) {
		if (this._hasHooks) await this.beforeHook("touch", {
			key,
			exptime
		});
		const resolvedKey = this.resolveKey(key);
		this.validateKey(resolvedKey);
		const sanitizedExptime = this.validateExpiration(exptime);
		const nodes = await this.getNodesByKey(resolvedKey);
		const success = allResultsEqual(await this.execute(`touch ${resolvedKey} ${sanitizedExptime}`, nodes), "TOUCHED");
		if (this._hasHooks) await this.afterHook("touch", {
			key,
			exptime,
			success
		});
		return success;
	}
	/**
	* Flush all values from all Memcache servers.
	* @param delay {number}
	* @returns {Promise<boolean>}
	*/
	async flush(delay) {
		let command = "flush_all";
		if (delay !== void 0) command += ` ${delay}`;
		return allResultsEqual(await Promise.all(this._nodes.map(async (node) => {
			/* v8 ignore next -- @preserve */
			if (!node.isConnected()) await node.connect();
			return node.command(command);
		})), "OK");
	}
	/**
	* Get statistics from all Memcache servers.
	* @param type {string}
	* @returns {Promise<Map<string, MemcacheStats>>}
	*/
	async stats(type) {
		const command = type ? `stats ${type}` : "stats";
		const results = /* @__PURE__ */ new Map();
		await Promise.all(
			/* v8 ignore next -- @preserve */
			this._nodes.map(async (node) => {
				if (!node.isConnected()) await node.connect();
				const stats = await node.command(command, { isStats: true });
				results.set(node.id, stats);
			})
		);
		return results;
	}
	/**
	* Get the Memcache server version from all nodes.
	* @returns {Promise<Map<string, string>>} Map of node IDs to version strings
	*/
	async version() {
		const results = /* @__PURE__ */ new Map();
		await Promise.all(
			/* v8 ignore next -- @preserve */
			this._nodes.map(async (node) => {
				if (!node.isConnected()) await node.connect();
				const version = await node.command("version");
				results.set(node.id, version);
			})
		);
		return results;
	}
	/**
	* Quit all connections gracefully.
	* @returns {Promise<void>}
	*/
	async quit() {
		if (this._autoDiscovery) {
			await this._autoDiscovery.stop();
			this._autoDiscovery = void 0;
		}
		await Promise.all(this._nodes.map(async (node) => {
			if (node.isConnected()) await node.quit();
		}));
	}
	/**
	* Disconnect all connections.
	* @returns {Promise<void>}
	*/
	async disconnect() {
		if (this._autoDiscovery) {
			await this._autoDiscovery.stop();
			this._autoDiscovery = void 0;
		}
		await Promise.all(this._nodes.map((node) => node.disconnect()));
	}
	/**
	* Reconnect all nodes by disconnecting and connecting them again.
	* @returns {Promise<void>}
	*/
	async reconnect() {
		await Promise.all(this._nodes.map((node) => node.reconnect()));
	}
	/**
	* Check if any node is connected to a Memcache server.
	* @returns {boolean}
	*/
	isConnected() {
		return this._nodes.some((node) => node.isConnected());
	}
	/**
	* Get the nodes for a given key using consistent hashing, with lazy connection.
	* This method will automatically connect to the nodes if they're not already connected.
	* Returns an array to support replication strategies.
	* @param {string} key - The cache key
	* @returns {Promise<Array<MemcacheNode>>} The nodes responsible for this key
	* @throws {Error} If no nodes are available for the key
	*/
	async getNodesByKey(key) {
		const nodes = this._hash.getNodesByKey(key);
		/* v8 ignore next -- @preserve */
		if (nodes.length === 0) throw new Error(`No node available for key: ${key}`);
		if (nodes.length === 1 && nodes[0].isConnected()) return nodes;
		for (const node of nodes) if (!node.isConnected()) await node.connect();
		return nodes;
	}
	/**
	* Execute a command on the specified nodes with retry support.
	* @param {string} command - The memcache command string to execute
	* @param {MemcacheNode[]} nodes - Array of MemcacheNode instances to execute on
	* @param {ExecuteOptions} options - Optional execution options including retry overrides
	* @returns {Promise<unknown[]>} Promise resolving to array of results from each node
	*/
	async execute(command, nodes, options) {
		const configuredRetries = options?.retries ?? this._retries;
		const retryDelay = options?.retryDelay ?? this._retryDelay;
		const retryBackoff = options?.retryBackoff ?? this._retryBackoff;
		const isIdempotent = options?.idempotent === true;
		const maxRetries = this._retryOnlyIdempotent && !isIdempotent ? 0 : configuredRetries;
		if (nodes.length === 1) return [await this.executeWithRetry(nodes[0], command, options?.commandOptions, maxRetries, retryDelay, retryBackoff)];
		const promises = nodes.map(async (node) => {
			return this.executeWithRetry(node, command, options?.commandOptions, maxRetries, retryDelay, retryBackoff);
		});
		return Promise.all(promises);
	}
	/**
	* Resolves a key for transmission to the memcache server. When `hashLargeKey`
	* is true and the key length exceeds `maxKeySize`, the key is replaced with a
	* djb2 hex digest (via the `hashery` library) so it fits within the limit.
	* Otherwise the original key is returned unchanged.
	* @param {string} key - The original cache key
	* @returns {string} The key to send to memcache (possibly hashed)
	*
	* @example
	* ```typescript
	* const client = new Memcache({ hashLargeKey: true });
	* client.resolveKey("a".repeat(300)); // returns 8-char djb2 hex digest
	* client.resolveKey("short-key");      // returns "short-key"
	* ```
	*/
	resolveKey(key) {
		if (this._hashLargeKey && key.length > this._maxKeySize) return this._hashery.toHashSync(key);
		return key;
	}
	/**
	* Validates a Memcache key according to protocol requirements.
	* @param {string} key - The key to validate
	* @throws {Error} If the key is empty, exceeds `maxKeySize` characters, or contains invalid characters
	*
	* @example
	* ```typescript
	* client.validateKey("valid-key"); // OK
	* client.validateKey(""); // Throws: Key cannot be empty
	* client.validateKey("a".repeat(251)); // Throws: Key length cannot exceed 250 characters
	* client.validateKey("key with spaces"); // Throws: Key cannot contain spaces, newlines, or null characters
	* ```
	*/
	validateKey(key) {
		if (!key || key.length === 0) throw new Error("Key cannot be empty");
		if (key.length > this._maxKeySize) throw new Error(`Key length cannot exceed ${this._maxKeySize} characters`);
		if (KEY_INVALID_CHARS.test(key)) throw new Error("Key cannot contain spaces, newlines, or null characters");
	}
	/**
	* Validates the size of a Memcache value against `maxValueSize`.
	* Performs an O(1) character-length pre-check before calling
	* `Buffer.byteLength`, since UTF-8 byte length is always >= character length.
	* @param {string} value - The value to validate
	* @returns {number} The encoded byte length of the value
	* @throws {Error} If the value exceeds `maxValueSize` bytes
	*
	* @example
	* ```typescript
	* const bytes = client.validateValue("hello"); // returns 5
	* client.validateValue("a".repeat(2_000_000)); // Throws: Value size cannot exceed 1048576 bytes
	* ```
	*/
	validateValue(value) {
		if (value.length > this._maxValueSize) throw new Error(`Value size cannot exceed ${this._maxValueSize} bytes`);
		const bytes = Buffer.byteLength(value);
		if (bytes > this._maxValueSize) throw new Error(`Value size cannot exceed ${this._maxValueSize} bytes`);
		return bytes;
	}
	/**
	* Validates a Memcache expiration time against `maxExpiration` and returns a
	* sanitized integer value suitable for the wire protocol. Non-finite inputs
	* (e.g. NaN) and negative values are coerced to `0` (no expiration);
	* fractional values are floored. `0` is always allowed; any sanitized value
	* exceeding the limit throws.
	* @param {number} exptime - The expiration time in seconds
	* @returns {number} The sanitized expiration time in seconds
	* @throws {Error} If the sanitized expiration exceeds `maxExpiration` seconds
	*
	* @example
	* ```typescript
	* client.validateExpiration(60); // returns 60
	* client.validateExpiration(0); // returns 0 (no expiration)
	* client.validateExpiration(1.9); // returns 1
	* client.validateExpiration(Number.NaN); // returns 0
	* client.validateExpiration(2592001); // Throws: Expiration cannot exceed 2592000 seconds
	* ```
	*/
	validateExpiration(exptime) {
		const sanitized = Math.floor(Number.isFinite(exptime) ? Math.max(0, exptime) : 0);
		if (sanitized !== 0 && sanitized > this._maxExpiration) throw new Error(`Expiration cannot exceed ${this._maxExpiration} seconds`);
		return sanitized;
	}
	/**
	* Fast check for whether any hooks are registered.
	* Avoids the overhead of async beforeHook/afterHook calls when no hooks exist.
	*/
	get _hasHooks() {
		return this.hooks.size > 0;
	}
	/**
	* Sleep utility for retry delays.
	* @param {number} ms - Milliseconds to sleep
	* @returns {Promise<void>}
	*/
	sleep(ms) {
		return new Promise((resolve) => setTimeout(resolve, ms));
	}
	/**
	* Execute a command on a single node with retry logic.
	* @param {MemcacheNode} node - The node to execute on
	* @param {string} command - The command string
	* @param {CommandOptions} commandOptions - Optional command options
	* @param {number} maxRetries - Maximum number of retry attempts
	* @param {number} retryDelay - Base delay between retries in milliseconds
	* @param {RetryBackoffFunction} retryBackoff - Function to calculate backoff delay
	* @returns {Promise<unknown>} Result or undefined on failure
	*/
	async executeWithRetry(node, command, commandOptions, maxRetries, retryDelay, retryBackoff) {
		if (maxRetries === 0) try {
			return await node.command(command, commandOptions);
		} catch {
			return;
		}
		for (let attempt = 0; attempt <= maxRetries; attempt++) try {
			return await node.command(command, commandOptions);
		} catch {
			if (attempt >= maxRetries) break;
			const delay = retryBackoff(attempt, retryDelay);
			if (delay > 0) await this.sleep(delay);
			/* v8 ignore next 3 -- @preserve */
			if (!node.isConnected()) try {
				await node.connect();
			} catch {}
		}
	}
	/**
	* Update all nodes with current keepAlive settings
	*/
	updateNodes() {
		for (const node of this._nodes) {
			node.keepAlive = this._keepAlive;
			node.keepAliveDelay = this._keepAliveDelay;
		}
	}
	/**
	* Forward events from a MemcacheNode to the Memcache instance
	*/
	forwardNodeEvents(node) {
		node.on("connect", () => this.emit("connect", node.id));
		node.on("close", () => this.emit("close", node.id));
		node.on("error", (err) => this.emit("error", node.id, err));
		node.on("timeout", () => this.emit("timeout", node.id));
		node.on("hit", (key, value) => this.emit("hit", key, value));
		node.on("miss", (key) => this.emit("miss", key));
	}
	async startAutoDiscovery() {
		const options = this._autoDiscoverOptions;
		/* v8 ignore next -- @preserve */
		if (!options) return;
		/* v8 ignore start -- @preserve */
		const configEndpoint = options.configEndpoint || (this._nodes.length > 0 ? this._nodes[0].id : "localhost:11211");
		/* v8 ignore stop -- @preserve */
		this._autoDiscovery = new AutoDiscovery({
			configEndpoint,
			pollingInterval: options.pollingInterval ?? 6e4,
			useLegacyCommand: options.useLegacyCommand ?? false,
			timeout: this._timeout,
			keepAlive: this._keepAlive,
			keepAliveDelay: this._keepAliveDelay,
			sasl: this._sasl
		});
		/* v8 ignore next -- @preserve */
		this._autoDiscovery.on("autoDiscover", (config) => {
			this.emit("autoDiscover", config);
		});
		/* v8 ignore next -- @preserve */
		this._autoDiscovery.on("autoDiscoverError", (error) => {
			this.emit("autoDiscoverError", error);
		});
		this._autoDiscovery.on(
			"autoDiscoverUpdate",
			/* v8 ignore next -- @preserve */
			async (config) => {
				this.emit("autoDiscoverUpdate", config);
				try {
					await this.applyClusterConfig(config);
				} catch (error) {
					this.emit("autoDiscoverError", error);
				}
			}
		);
		try {
			const initialConfig = await this._autoDiscovery.start();
			/* v8 ignore next -- @preserve */
			await this.applyClusterConfig(initialConfig);
		} catch (error) {
			this.emit("autoDiscoverError", error);
		}
	}
	async applyClusterConfig(config) {
		if (config.nodes.length === 0) {
			this.emit("autoDiscoverError", /* @__PURE__ */ new Error("Discovery returned zero nodes; keeping current topology"));
			return;
		}
		const discoveredNodeIds = new Set(config.nodes.map((n) => AutoDiscovery.nodeId(n)));
		const currentNodeIds = new Set(this.nodeIds);
		for (const node of config.nodes) {
			const id = AutoDiscovery.nodeId(node);
			if (!currentNodeIds.has(id)) try {
				const host = node.ip || node.hostname;
				const wrappedHost = host.includes(":") ? `[${host}]` : host;
				await this.addNode(`${wrappedHost}:${node.port}`);
			} catch (error) {
				this.emit("error", id, error);
			}
		}
		for (const nodeId of currentNodeIds) if (!discoveredNodeIds.has(nodeId)) try {
			await this.removeNode(nodeId);
		} catch (error) {
			this.emit("error", nodeId, error);
		}
	}
};
//#endregion
export { AutoDiscovery, BroadcastHash, Hashery, Memcache, Memcache as default, MemcacheEvents, MemcacheNode, ModulaHash, createNode, defaultRetryBackoff, exponentialRetryBackoff };
