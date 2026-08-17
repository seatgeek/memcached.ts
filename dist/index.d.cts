import { Hashery, Hashery as Hashery$1 } from "hashery";
import { Hookified } from "hookified";
import { Socket } from "node:net";
import { ConnectionOptions } from "node:tls";

//#region src/node.d.ts
/**
 * TLS configuration for node connections.
 * - `true`: connect using TLS with Node's default trust store.
 * - a `tls.ConnectionOptions` object: connect using TLS with the provided
 *   options (e.g. `{ ca }` for a private certificate authority).
 * - `false` / `undefined`: connect using plain TCP.
 */
type MemcacheTlsOption = boolean | ConnectionOptions;
interface MemcacheNodeOptions {
  timeout?: number;
  keepAlive?: boolean;
  keepAliveDelay?: number;
  weight?: number;
  /** SASL authentication credentials */
  sasl?: SASLCredentials;
  /**
   * Enable TLS for this node's connection.
   * `true` uses Node's default trust store; a `tls.ConnectionOptions`
   * object is passed through to `tls.connect()` (e.g. `{ ca }`).
   * @default undefined (plain TCP)
   */
  tls?: MemcacheTlsOption;
}
interface CommandOptions {
  isMultiline?: boolean;
  isStats?: boolean;
  isConfig?: boolean;
  requestedKeys?: string[];
}
type CommandQueueItem = {
  command: string;
  resolve: (value: any) => void;
  reject: (reason?: any) => void;
  isMultiline?: boolean;
  isStats?: boolean;
  isConfig?: boolean;
  requestedKeys?: string[];
  foundKeys?: string[];
};
/**
 * MemcacheNode represents a single memcache server connection.
 * It handles the socket connection, command queue, and protocol parsing for one node.
 */
declare class MemcacheNode extends Hookified {
  private _host;
  private _port;
  private _socket;
  private _timeout;
  private _keepAlive;
  private _keepAliveDelay;
  private _weight;
  private _connected;
  private _commandQueue;
  private _buffer;
  private _currentCommand;
  private _multilineData;
  private _pendingValueBytes;
  private _sasl;
  private _tls;
  private _authenticated;
  private _binaryBuffer;
  constructor(host: string, port: number, options?: MemcacheNodeOptions);
  /**
   * Get the host of this node
   */
  get host(): string;
  /**
   * Get the port of this node
   */
  get port(): number;
  /**
   * Get the unique identifier for this node (host:port format)
   */
  get id(): string;
  /**
   * Get the full uri like memcache://localhost:11211
   */
  get uri(): string;
  /**
   * Get the socket connection
   */
  get socket(): Socket | undefined;
  /**
   * Get the weight of this node (used for consistent hashing distribution)
   */
  get weight(): number;
  /**
   * Set the weight of this node (used for consistent hashing distribution)
   */
  set weight(value: number);
  /**
   * Get the keepAlive setting for this node
   */
  get keepAlive(): boolean;
  /**
   * Set the keepAlive setting for this node
   */
  set keepAlive(value: boolean);
  /**
   * Get the keepAliveDelay setting for this node
   */
  get keepAliveDelay(): number;
  /**
   * Set the keepAliveDelay setting for this node
   */
  set keepAliveDelay(value: number);
  /**
   * Get the command queue
   */
  get commandQueue(): CommandQueueItem[];
  /**
   * Get whether SASL authentication is configured
   */
  get hasSaslCredentials(): boolean;
  /**
   * Get whether the node is authenticated (only relevant if SASL is configured)
   */
  get isAuthenticated(): boolean;
  /**
   * Connect to the memcache server
   */
  connect(): Promise<void>;
  /**
   * Disconnect from the memcache server
   */
  disconnect(): Promise<void>;
  /**
   * Reconnect to the memcache server by disconnecting and connecting again
   */
  reconnect(): Promise<void>;
  /**
   * Perform SASL PLAIN authentication using the binary protocol
   */
  private performSaslAuth;
  /**
   * Send a binary protocol request and wait for response.
   * Used internally for SASL-authenticated connections.
   */
  private binaryRequest;
  /**
   * Binary protocol GET operation
   */
  binaryGet(key: string): Promise<string | undefined>;
  /**
   * Binary protocol SET operation
   */
  binarySet(key: string, value: string, exptime?: number, flags?: number): Promise<boolean>;
  /**
   * Binary protocol ADD operation
   */
  binaryAdd(key: string, value: string, exptime?: number, flags?: number): Promise<boolean>;
  /**
   * Binary protocol REPLACE operation
   */
  binaryReplace(key: string, value: string, exptime?: number, flags?: number): Promise<boolean>;
  /**
   * Binary protocol DELETE operation
   */
  binaryDelete(key: string): Promise<boolean>;
  /**
   * Binary protocol INCREMENT operation
   */
  binaryIncr(key: string, delta?: number, initial?: number, exptime?: number): Promise<number | undefined>;
  /**
   * Binary protocol DECREMENT operation
   */
  binaryDecr(key: string, delta?: number, initial?: number, exptime?: number): Promise<number | undefined>;
  /**
   * Binary protocol APPEND operation
   */
  binaryAppend(key: string, value: string): Promise<boolean>;
  /**
   * Binary protocol PREPEND operation
   */
  binaryPrepend(key: string, value: string): Promise<boolean>;
  /**
   * Binary protocol TOUCH operation
   */
  binaryTouch(key: string, exptime: number): Promise<boolean>;
  /**
   * Binary protocol FLUSH operation
   */
  binaryFlush(exptime?: number): Promise<boolean>;
  /**
   * Binary protocol VERSION operation
   */
  binaryVersion(): Promise<string | undefined>;
  /**
   * Binary protocol STATS operation
   */
  binaryStats(): Promise<Record<string, string>>;
  /**
   * Binary protocol QUIT operation
   */
  binaryQuit(): Promise<void>;
  /**
   * Gracefully quit the connection (send quit command then disconnect)
   */
  quit(): Promise<void>;
  /**
   * Check if connected to the memcache server
   */
  isConnected(): boolean;
  /**
   * Send a generic command to the memcache server
   * @param cmd The command string to send (without trailing \r\n)
   * @param options Command options for response parsing
   */
  command(cmd: string, options?: CommandOptions): Promise<any>;
  private handleData;
  private processLine;
  private rejectPendingCommands;
}
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
declare function createNode(host: string, port: number, options?: MemcacheNodeOptions): MemcacheNode;
//#endregion
//#region src/types.d.ts
/**
 * SASL authentication credentials for connecting to a secured memcache server.
 */
interface SASLCredentials {
  /**
   * Username for SASL authentication
   */
  username: string;
  /**
   * Password for SASL authentication
   */
  password: string;
  /**
   * SASL mechanism to use (default: 'PLAIN')
   * Currently only 'PLAIN' is supported.
   */
  mechanism?: "PLAIN";
}
declare enum MemcacheEvents {
  CONNECT = "connect",
  QUIT = "quit",
  HIT = "hit",
  MISS = "miss",
  ERROR = "error",
  WARN = "warn",
  INFO = "info",
  TIMEOUT = "timeout",
  CLOSE = "close",
  AUTO_DISCOVER = "autoDiscover",
  AUTO_DISCOVER_ERROR = "autoDiscoverError",
  AUTO_DISCOVER_UPDATE = "autoDiscoverUpdate"
}
/**
 * Function to calculate delay between retry attempts.
 * @param attempt - The current attempt number (0-indexed)
 * @param baseDelay - The base delay in milliseconds
 * @returns The delay in milliseconds before the next retry
 */
type RetryBackoffFunction = (attempt: number, baseDelay: number) => number;
interface HashProvider {
  name: string;
  nodes: Array<MemcacheNode>;
  addNode: (node: MemcacheNode) => void;
  removeNode: (id: string) => void;
  getNode: (id: string) => MemcacheNode | undefined;
  getNodesByKey: (key: string) => Array<MemcacheNode>;
}
interface MemcacheOptions {
  /**
   * Array of node URIs or MemcacheNode instances to add to the consistent hashing ring.
   * Examples: ["localhost:11211", "memcache://192.168.1.100:11212", "server3:11213"]
   * Can also pass MemcacheNode instances directly: [createNode("localhost", 11211), createNode("server2", 11211)]
   */
  nodes?: (string | MemcacheNode)[];
  /**
   * The timeout for Memcache operations.
   * @default 5000
   */
  timeout?: number;
  /**
   * Whether to keep the connection alive.
   * @default true
   */
  keepAlive?: boolean;
  /**
   * The delay before the connection is kept alive.
   * @default 1000
   */
  keepAliveDelay?: number;
  /**
   * The hash provider used to determine the distribution on each item is placed based
   * on the number of nodes and hashing. By default it uses KetamaHash as the provider
   */
  hash?: HashProvider;
  /**
   * The number of retry attempts for failed commands.
   * Set to 0 to disable retries.
   * @default 0
   */
  retries?: number;
  /**
   * The base delay in milliseconds between retry attempts.
   * @default 100
   */
  retryDelay?: number;
  /**
   * Function to calculate backoff delay between retries.
   * Receives (attempt, baseDelay) and returns delay in ms.
   * @default defaultRetryBackoff (fixed delay)
   */
  retryBackoff?: RetryBackoffFunction;
  /**
   * When true, retries are only performed for commands marked as idempotent.
   * This prevents accidental double-execution of non-idempotent operations
   * (like incr, decr, append) if the server applies the command but the
   * client doesn't receive the response before a timeout/disconnect.
   * @default true
   */
  retryOnlyIdempotent?: boolean;
  /**
   * SASL authentication credentials for all nodes.
   * When provided, nodes will authenticate using SASL PLAIN mechanism
   * before accepting commands.
   */
  sasl?: SASLCredentials;
  /**
   * When true, nodes will not connect until the first command is executed.
   * When false, nodes connect eagerly during construction.
   * @default true
   */
  lazyConnect?: boolean;
  /**
   * The maximum allowed key size (in characters). Memcache protocol max is 250.
   * @default 250
   */
  maxKeySize?: number;
  /**
   * Controls hashing of keys whose length exceeds `maxKeySize`.
   * - `false` (default): oversized keys throw a validation error.
   * - `true`: oversized keys are deterministically hashed with a default
   *   `Hashery` instance (djb2 sync) before being sent to the server.
   * - a `Hashery` instance: oversized keys are hashed with that instance,
   *   so callers can pick `fnv1` / `murmur` / `crc32`, plug in custom
   *   providers, enable caching, etc.
   *
   * Note: hashing is one-way and can collide. Two distinct long keys could
   * map to the same hashed key.
   * @default false
   */
  hashLargeKey?: boolean | Hashery$1;
  /**
   * The maximum allowed value size in bytes. Memcached default max is 1048576 (1 MiB).
   * @default 1048576
   */
  maxValueSize?: number;
  /**
   * The maximum allowed expiration time in seconds. Memcached treats values greater
   * than 2592000 (30 days) as absolute Unix timestamps, so the default rejects any
   * ambiguous relative TTLs. `0` (no expiration) is always allowed. Raise this value
   * if you need to pass Unix timestamps as expirations.
   * @default 2592000
   */
  maxExpiration?: number;
  /**
   * Enable TLS for all node connections.
   * - `true`: connect using TLS with Node's default trust store. This is the
   *   typical setting for servers with publicly-trusted certificates
   *   (e.g. AWS ElastiCache Serverless, which requires TLS).
   * - a `tls.ConnectionOptions` object: connect using TLS with the provided
   *   options (e.g. `{ ca }` for a private certificate authority).
   * - `false` / `undefined` (default): connect using plain TCP.
   * @default undefined
   */
  tls?: MemcacheTlsOption;
  /**
   * AWS ElastiCache Auto Discovery configuration.
   * When enabled, the client will periodically poll the configuration endpoint
   * to detect cluster topology changes and automatically update the node list.
   */
  autoDiscover?: AutoDiscoverOptions;
}
interface MemcacheStats {
  [key: string]: string;
}
/**
 * Configuration for AWS ElastiCache Auto Discovery.
 * When enabled, the client connects to a configuration endpoint and periodically
 * polls for cluster topology changes, automatically adding/removing nodes.
 */
interface AutoDiscoverOptions {
  /**
   * Enable auto discovery of cluster nodes.
   */
  enabled: boolean;
  /**
   * How often to poll for topology changes, in milliseconds.
   * @default 60000
   */
  pollingInterval?: number;
  /**
   * The configuration endpoint to use for discovery.
   * This is typically the .cfg endpoint from ElastiCache.
   * If not specified, the first node in the nodes array will be used.
   */
  configEndpoint?: string;
  /**
   * Use the legacy `get AmazonElastiCache:cluster` command
   * instead of `config get cluster` (for engine versions < 1.4.14).
   * @default false
   */
  useLegacyCommand?: boolean;
}
/**
 * Represents a discovered node from the ElastiCache cluster configuration.
 */
interface DiscoveredNode {
  /** The hostname of the node */
  hostname: string;
  /** The IP address of the node (may be empty string) */
  ip: string;
  /** The port number of the node */
  port: number;
}
/**
 * Represents the parsed result of an ElastiCache cluster config response.
 */
interface ClusterConfig {
  /** The config version number (increments on topology changes) */
  version: number;
  /** The list of discovered nodes */
  nodes: DiscoveredNode[];
}
interface ExecuteOptions {
  /** Command options passed to node.command() */
  commandOptions?: CommandOptions;
  /**
   * Override the number of retries for this specific execution.
   * If undefined, uses the instance-level retries setting.
   */
  retries?: number;
  /**
   * Override the retry delay for this specific execution.
   * If undefined, uses the instance-level retryDelay setting.
   */
  retryDelay?: number;
  /**
   * Override the backoff function for this specific execution.
   * If undefined, uses the instance-level retryBackoff setting.
   */
  retryBackoff?: RetryBackoffFunction;
  /**
   * Mark this command as idempotent, allowing retries even when
   * retryOnlyIdempotent is true. Set this for read operations (get, gets)
   * or operations that are safe to repeat (set with same value).
   * @default false
   */
  idempotent?: boolean;
}
//#endregion
//#region src/auto-discovery.d.ts
interface AutoDiscoveryOptions {
  configEndpoint: string;
  pollingInterval: number;
  useLegacyCommand: boolean;
  timeout: number;
  keepAlive: boolean;
  keepAliveDelay: number;
  sasl?: SASLCredentials;
}
/**
 * Handles AWS ElastiCache Auto Discovery for memcache clusters.
 * Connects to a configuration endpoint, periodically polls for cluster
 * topology changes, and emits events when nodes are added or removed.
 */
declare class AutoDiscovery extends Hookified {
  private _configEndpoint;
  private _pollingInterval;
  private _useLegacyCommand;
  private _configVersion;
  private _pollingTimer;
  private _configNode;
  private _timeout;
  private _keepAlive;
  private _keepAliveDelay;
  private _sasl;
  private _isRunning;
  private _isPolling;
  constructor(options: AutoDiscoveryOptions);
  /** Current config version. -1 means no config has been fetched yet. */
  get configVersion(): number;
  /** Whether auto discovery is currently running. */
  get isRunning(): boolean;
  /** The configuration endpoint being used. */
  get configEndpoint(): string;
  /**
   * Start the auto discovery process.
   * Performs an initial discovery, then starts the polling timer.
   */
  start(): Promise<ClusterConfig>;
  /**
   * Stop the auto discovery process.
   */
  stop(): Promise<void>;
  /**
   * Perform a single discovery cycle.
   * Returns the ClusterConfig if the version has changed, or undefined if unchanged.
   */
  discover(): Promise<ClusterConfig | undefined>;
  /**
   * Parse the raw response data from a config get cluster command.
   * The raw data is the value content between the CONFIG/VALUE header and END.
   * Format: "<version>\n<host1>|<ip1>|<port1> <host2>|<ip2>|<port2>\n"
   */
  static parseConfigResponse(rawData: string[]): ClusterConfig;
  /**
   * Parse a single node entry in the format "hostname|ip|port".
   */
  static parseNodeEntry(entry: string): DiscoveredNode;
  /**
   * Build a node ID from a DiscoveredNode.
   * Prefers IP when available, falls back to hostname.
   */
  static nodeId(node: DiscoveredNode): string;
  private ensureConfigNode;
  private fetchConfig;
  private poll;
  private parseEndpoint;
}
//#endregion
//#region src/broadcast.d.ts
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
declare class BroadcastHash implements HashProvider {
  /** The name of this distribution strategy */
  readonly name = "broadcast";
  /** Map of node IDs to MemcacheNode instances */
  private nodeMap;
  /** Cached array of nodes, rebuilt only on add/remove */
  private nodeCache;
  constructor();
  /**
   * Gets all nodes in the distribution.
   * @returns Array of all MemcacheNode instances
   */
  get nodes(): Array<MemcacheNode>;
  /**
   * Adds a node to the distribution.
   * @param node - The MemcacheNode to add
   */
  addNode(node: MemcacheNode): void;
  /**
   * Removes a node from the distribution by its ID.
   * @param id - The node ID (e.g., "localhost:11211")
   */
  removeNode(id: string): void;
  /**
   * Gets a specific node by its ID.
   * @param id - The node ID (e.g., "localhost:11211")
   * @returns The MemcacheNode if found, undefined otherwise
   */
  getNode(id: string): MemcacheNode | undefined;
  /**
   * Returns all nodes regardless of key. Every operation is broadcast
   * to every node in the cluster.
   * @param _key - The cache key (ignored — all nodes are always returned)
   * @returns Array of all MemcacheNode instances
   */
  getNodesByKey(_key: string): Array<MemcacheNode>;
  /**
   * Rebuilds the cached node array from the map.
   */
  private rebuildCache;
}
//#endregion
//#region src/modula.d.ts
/**
 * Function that returns an unsigned 32-bit hash of the input.
 */
type HashFunction = (input: Buffer) => number;
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
declare class ModulaHash implements HashProvider {
  /** The name of this distribution strategy */
  readonly name = "modula";
  /** The string-native hash function used on the hot path */
  private readonly hashStr;
  /** Map of node IDs to MemcacheNode instances */
  private nodeMap;
  /**
   * Weighted list of node IDs for modulo distribution.
   * Nodes with higher weights appear multiple times.
   */
  private nodeList;
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
  constructor(hashFn?: string | HashFunction);
  /**
   * Gets all nodes in the distribution.
   * @returns Array of all MemcacheNode instances
   */
  get nodes(): Array<MemcacheNode>;
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
  addNode(node: MemcacheNode): void;
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
  removeNode(id: string): void;
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
  getNode(id: string): MemcacheNode | undefined;
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
  getNodesByKey(key: string): Array<MemcacheNode>;
}
//#endregion
//#region src/index.d.ts
/**
 * Default backoff function - returns fixed delay
 */
declare const defaultRetryBackoff: RetryBackoffFunction;
/**
 * Exponential backoff function - doubles delay each attempt
 */
declare const exponentialRetryBackoff: RetryBackoffFunction;
declare class Memcache extends Hookified {
  private _nodes;
  private _timeout;
  private _keepAlive;
  private _keepAliveDelay;
  private _hash;
  private _retries;
  private _retryDelay;
  private _retryBackoff;
  private _retryOnlyIdempotent;
  private _sasl;
  private _tls;
  private _autoDiscovery;
  private _autoDiscoverOptions;
  private readonly _lazyConnect;
  private _maxKeySize;
  private _maxValueSize;
  private _maxExpiration;
  private _hashLargeKey;
  private _hashery;
  constructor(options?: string | MemcacheOptions);
  /**
   * Get the list of nodes
   * @returns {MemcacheNode[]} Array of MemcacheNode
   */
  get nodes(): MemcacheNode[];
  /**
   * Get the list of node IDs (e.g., ["localhost:11211", "127.0.0.1:11212"])
   * @returns {string[]} Array of node ID strings
   */
  get nodeIds(): string[];
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
  get hash(): HashProvider;
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
  set hash(hash: HashProvider);
  /**
   * Get the timeout for Memcache operations.
   * @returns {number}
   * @default 5000
   */
  get timeout(): number;
  /**
   * Set the timeout for Memcache operations.
   * @param {number} value
   * @default 5000
   */
  set timeout(value: number);
  /**
   * Get the maximum allowed key size (in characters).
   * @returns {number}
   * @default 250
   */
  get maxKeySize(): number;
  /**
   * Set the maximum allowed key size (in characters). Memcache protocol max is 250.
   * @param {number} value
   * @default 250
   */
  set maxKeySize(value: number);
  /**
   * Whether keys exceeding `maxKeySize` are hashed with djb2 instead of throwing.
   * @returns {boolean}
   * @default false
   */
  get hashLargeKey(): boolean;
  /**
   * Enable or disable hashing of keys that exceed `maxKeySize`.
   * When true, oversized keys are deterministically hashed before validation
   * using the configured `hashery` instance. When false, oversized keys throw
   * a validation error. To change the algorithm or providers, mutate or
   * replace the `hashery` property instead.
   * @param {boolean} value
   * @default false
   */
  set hashLargeKey(value: boolean);
  /**
   * The `Hashery` instance used to hash oversized keys when `hashLargeKey`
   * is enabled. Always returns an instance, even when hashing is disabled,
   * so callers can pre-configure it (e.g. set `defaultAlgorithmSync` or
   * register custom providers) before flipping `hashLargeKey` on.
   * @returns {Hashery}
   */
  get hashery(): Hashery;
  /**
   * Replace the `Hashery` instance used to hash oversized keys.
   * @param {Hashery} value
   */
  set hashery(value: Hashery);
  /**
   * Get the maximum allowed value size (in bytes).
   * @returns {number}
   * @default 1048576
   */
  get maxValueSize(): number;
  /**
   * Set the maximum allowed value size (in bytes). Memcached default max is 1048576 (1 MiB).
   * @param {number} value
   * @default 1048576
   */
  set maxValueSize(value: number);
  /**
   * Get the maximum allowed expiration time (in seconds).
   * @returns {number}
   * @default 2592000
   */
  get maxExpiration(): number;
  /**
   * Set the maximum allowed expiration time (in seconds). Memcached treats values
   * greater than 2592000 (30 days) as absolute Unix timestamps. `0` (no expiration)
   * is always allowed regardless of this limit.
   * @param {number} value
   * @default 2592000
   */
  set maxExpiration(value: number);
  /**
   * Get the keepAlive setting for the Memcache connection.
   * @returns {boolean}
   * @default true
   */
  get keepAlive(): boolean;
  /**
   * Set the keepAlive setting for the Memcache connection.
   * Updates all existing nodes with the new value.
   * Note: To apply the new value, you need to call reconnect() on the nodes.
   * @param {boolean} value
   * @default true
   */
  set keepAlive(value: boolean);
  /**
   * Get the delay before the connection is kept alive.
   * @returns {number}
   * @default 1000
   */
  get keepAliveDelay(): number;
  /**
   * Set the delay before the connection is kept alive.
   * Updates all existing nodes with the new value.
   * Note: To apply the new value, you need to call reconnect() on the nodes.
   * @param {number} value
   * @default 1000
   */
  set keepAliveDelay(value: number);
  /**
   * Get the number of retry attempts for failed commands.
   * @returns {number}
   * @default 0
   */
  get retries(): number;
  /**
   * Set the number of retry attempts for failed commands.
   * Set to 0 to disable retries.
   * @param {number} value
   * @default 0
   */
  set retries(value: number);
  /**
   * Get the base delay in milliseconds between retry attempts.
   * @returns {number}
   * @default 100
   */
  get retryDelay(): number;
  /**
   * Set the base delay in milliseconds between retry attempts.
   * @param {number} value
   * @default 100
   */
  set retryDelay(value: number);
  /**
   * Get the backoff function for retry delays.
   * @returns {RetryBackoffFunction}
   * @default defaultRetryBackoff
   */
  get retryBackoff(): RetryBackoffFunction;
  /**
   * Set the backoff function for retry delays.
   * @param {RetryBackoffFunction} value
   * @default defaultRetryBackoff
   */
  set retryBackoff(value: RetryBackoffFunction);
  /**
   * Get whether retries are restricted to idempotent commands only.
   * @returns {boolean}
   * @default true
   */
  get retryOnlyIdempotent(): boolean;
  /**
   * Set whether retries are restricted to idempotent commands only.
   * When true (default), retries only occur for commands explicitly marked
   * as idempotent via ExecuteOptions. This prevents accidental double-execution
   * of non-idempotent operations like incr, decr, append, etc.
   * @param {boolean} value
   * @default true
   */
  set retryOnlyIdempotent(value: boolean);
  /**
   * Whether nodes defer connecting until the first command is executed.
   * @returns {boolean}
   * @default true
   */
  get lazyConnect(): boolean;
  /**
   * Get an array of all MemcacheNode instances
   * @returns {MemcacheNode[]}
   */
  getNodes(): MemcacheNode[];
  /**
   * Get a specific node by its ID
   * @param {string} id - The node ID (e.g., "localhost:11211")
   * @returns {MemcacheNode | undefined}
   */
  getNode(id: string): MemcacheNode | undefined;
  /**
   * Add a new node to the cluster
   * @param {string | MemcacheNode} uri - Node URI (e.g., "localhost:11212") or a MemcacheNode instance
   * @param {number} weight - Optional weight for consistent hashing (only used for string URIs)
   */
  addNode(uri: string | MemcacheNode, weight?: number): Promise<void>;
  /**
   * Remove a node from the cluster
   * @param {string} uri - Node URI (e.g., "localhost:11212")
   */
  removeNode(uri: string): Promise<void>;
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
  parseUri(uri: string): {
    host: string;
    port: number;
    secure?: boolean;
  };
  /**
   * Connect to all Memcache servers or a specific node.
   * @param {string} nodeId - Optional node ID to connect to (e.g., "localhost:11211")
   * @returns {Promise<void>}
   */
  connect(nodeId?: string): Promise<void>;
  /**
   * Get a value from the Memcache server.
   * When multiple nodes are returned by the hash provider (for replication),
   * queries all nodes and returns the first successful result.
   * @param {string} key
   * @returns {Promise<string | undefined>}
   */
  get(key: string): Promise<string | undefined>;
  /**
   * Get multiple values from the Memcache server.
   * When multiple nodes are returned by the hash provider (for replication),
   * queries all replica nodes and returns the first successful result for each key.
   * @param keys {string[]}
   * @returns {Promise<Map<string, string>>}
   */
  gets(keys: string[]): Promise<Map<string, string>>;
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
  cas(key: string, value: string, casToken: string, exptime?: number, flags?: number): Promise<boolean>;
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
  set(key: string, value: string, exptime?: number, flags?: number): Promise<boolean>;
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
  add(key: string, value: string, exptime?: number, flags?: number): Promise<boolean>;
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
  replace(key: string, value: string, exptime?: number, flags?: number): Promise<boolean>;
  /**
   * Append a value to an existing key in the Memcache server.
   * When multiple nodes are returned by the hash provider (for replication),
   * executes on all nodes and returns true only if all succeed.
   * @param key {string}
   * @param value {string}
   * @returns {Promise<boolean>}
   */
  append(key: string, value: string): Promise<boolean>;
  /**
   * Prepend a value to an existing key in the Memcache server.
   * When multiple nodes are returned by the hash provider (for replication),
   * executes on all nodes and returns true only if all succeed.
   * @param key {string}
   * @param value {string}
   * @returns {Promise<boolean>}
   */
  prepend(key: string, value: string): Promise<boolean>;
  /**
   * Delete a value from the Memcache server.
   * When multiple nodes are returned by the hash provider (for replication),
   * executes on all nodes and returns true only if all succeed.
   * @param key {string}
   * @returns {Promise<boolean>}
   */
  delete(key: string): Promise<boolean>;
  /**
   * Increment a value in the Memcache server.
   * When multiple nodes are returned by the hash provider (for replication),
   * executes on all nodes and returns the first successful result.
   * @param key {string}
   * @param value {number}
   * @returns {Promise<number | undefined>}
   */
  incr(key: string, value?: number): Promise<number | undefined>;
  /**
   * Decrement a value in the Memcache server.
   * When multiple nodes are returned by the hash provider (for replication),
   * executes on all nodes and returns the first successful result.
   * @param key {string}
   * @param value {number}
   * @returns {Promise<number | undefined>}
   */
  decr(key: string, value?: number): Promise<number | undefined>;
  /**
   * Touch a value in the Memcache server (update expiration time).
   * When multiple nodes are returned by the hash provider (for replication),
   * executes on all nodes and returns true only if all succeed.
   * @param key {string}
   * @param exptime {number}
   * @returns {Promise<boolean>}
   */
  touch(key: string, exptime: number): Promise<boolean>;
  /**
   * Flush all values from all Memcache servers.
   * @param delay {number}
   * @returns {Promise<boolean>}
   */
  flush(delay?: number): Promise<boolean>;
  /**
   * Get statistics from all Memcache servers.
   * @param type {string}
   * @returns {Promise<Map<string, MemcacheStats>>}
   */
  stats(type?: string): Promise<Map<string, MemcacheStats>>;
  /**
   * Get the Memcache server version from all nodes.
   * @returns {Promise<Map<string, string>>} Map of node IDs to version strings
   */
  version(): Promise<Map<string, string>>;
  /**
   * Quit all connections gracefully.
   * @returns {Promise<void>}
   */
  quit(): Promise<void>;
  /**
   * Disconnect all connections.
   * @returns {Promise<void>}
   */
  disconnect(): Promise<void>;
  /**
   * Reconnect all nodes by disconnecting and connecting them again.
   * @returns {Promise<void>}
   */
  reconnect(): Promise<void>;
  /**
   * Check if any node is connected to a Memcache server.
   * @returns {boolean}
   */
  isConnected(): boolean;
  /**
   * Get the nodes for a given key using consistent hashing, with lazy connection.
   * This method will automatically connect to the nodes if they're not already connected.
   * Returns an array to support replication strategies.
   * @param {string} key - The cache key
   * @returns {Promise<Array<MemcacheNode>>} The nodes responsible for this key
   * @throws {Error} If no nodes are available for the key
   */
  getNodesByKey(key: string): Promise<Array<MemcacheNode>>;
  /**
   * Execute a command on the specified nodes with retry support.
   * @param {string} command - The memcache command string to execute
   * @param {MemcacheNode[]} nodes - Array of MemcacheNode instances to execute on
   * @param {ExecuteOptions} options - Optional execution options including retry overrides
   * @returns {Promise<unknown[]>} Promise resolving to array of results from each node
   */
  execute(command: string, nodes: MemcacheNode[], options?: ExecuteOptions): Promise<unknown[]>;
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
  resolveKey(key: string): string;
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
  validateKey(key: string): void;
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
  validateValue(value: string): number;
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
  validateExpiration(exptime: number): number;
  /**
   * Fast check for whether any hooks are registered.
   * Avoids the overhead of async beforeHook/afterHook calls when no hooks exist.
   */
  private get _hasHooks();
  /**
   * Sleep utility for retry delays.
   * @param {number} ms - Milliseconds to sleep
   * @returns {Promise<void>}
   */
  private sleep;
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
  private executeWithRetry;
  /**
   * Update all nodes with current keepAlive settings
   */
  private updateNodes;
  /**
   * Forward events from a MemcacheNode to the Memcache instance
   */
  private forwardNodeEvents;
  private startAutoDiscovery;
  private applyClusterConfig;
}
//#endregion
export { type AutoDiscoverOptions, AutoDiscovery, BroadcastHash, type ClusterConfig, type DiscoveredNode, type ExecuteOptions, type HashProvider, Hashery, Memcache, Memcache as default, MemcacheEvents, MemcacheNode, type MemcacheOptions, type MemcacheStats, type MemcacheTlsOption, ModulaHash, type RetryBackoffFunction, type SASLCredentials, createNode, defaultRetryBackoff, exponentialRetryBackoff };