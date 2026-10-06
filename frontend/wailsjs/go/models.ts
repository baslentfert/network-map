export namespace baseline {
	
	export class Bevinding {
	    kind: string;
	    key: string;
	    args: Record<string, string>;
	    host: string;
	    severity: string;
	    // Go type: time
	    at: any;
	
	    static createFrom(source: any = {}) {
	        return new Bevinding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.kind = source["kind"];
	        this.key = source["key"];
	        this.args = source["args"];
	        this.host = source["host"];
	        this.severity = source["severity"];
	        this.at = this.convertValues(source["at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace dnsproxy {
	
	export class Apparaat {
	    client: string;
	    name: string;
	    queries: number;
	    domains: number;
	
	    static createFrom(source: any = {}) {
	        return new Apparaat(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.client = source["client"];
	        this.name = source["name"];
	        this.queries = source["queries"];
	        this.domains = source["domains"];
	    }
	}
	export class Status {
	    active: boolean;
	    address: string;
	    upstream: string[];
	    queries: number;
	    failed: number;
	    // Go type: time
	    since: any;
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.active = source["active"];
	        this.address = source["address"];
	        this.upstream = source["upstream"];
	        this.queries = source["queries"];
	        this.failed = source["failed"];
	        this.since = this.convertValues(source["since"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Teller {
	    client: string;
	    name: string;
	    count: number;
	    // Go type: time
	    first: any;
	    // Go type: time
	    last: any;
	    addresses?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Teller(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.client = source["client"];
	        this.name = source["name"];
	        this.count = source["count"];
	        this.first = this.convertValues(source["first"], null);
	        this.last = this.convertValues(source["last"], null);
	        this.addresses = source["addresses"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Vraag {
	    // Go type: time
	    at: any;
	    client: string;
	    name: string;
	    type: string;
	    rcode: string;
	    ms: number;
	    answers?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Vraag(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.at = this.convertValues(source["at"], null);
	        this.client = source["client"];
	        this.name = source["name"];
	        this.type = source["type"];
	        this.rcode = source["rcode"];
	        this.ms = source["ms"];
	        this.answers = source["answers"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace i18n {
	
	export class Taal {
	    code: string;
	    name: string;
	
	    static createFrom(source: any = {}) {
	        return new Taal(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.code = source["code"];
	        this.name = source["name"];
	    }
	}

}

export namespace listen {
	
	export class Luisteraar {
	    proto: string;
	    ip: string;
	    port: number;
	    dualStack: boolean;
	    pid: number;
	    process: string;
	    path: string;
	    user: string;
	    // Go type: time
	    since: any;
	    scope: string;
	    service: string;
	    explanation: string;
	    verdict: string;
	    why: string;
	    connections: number;
	
	    static createFrom(source: any = {}) {
	        return new Luisteraar(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.proto = source["proto"];
	        this.ip = source["ip"];
	        this.port = source["port"];
	        this.dualStack = source["dualStack"];
	        this.pid = source["pid"];
	        this.process = source["process"];
	        this.path = source["path"];
	        this.user = source["user"];
	        this.since = this.convertValues(source["since"], null);
	        this.scope = source["scope"];
	        this.service = source["service"];
	        this.explanation = source["explanation"];
	        this.verdict = source["verdict"];
	        this.why = source["why"];
	        this.connections = source["connections"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Verbinding {
	    proto: string;
	    local: string;
	    remote: string;
	    status: string;
	    pid: number;
	    process: string;
	
	    static createFrom(source: any = {}) {
	        return new Verbinding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.proto = source["proto"];
	        this.local = source["local"];
	        this.remote = source["remote"];
	        this.status = source["status"];
	        this.pid = source["pid"];
	        this.process = source["process"];
	    }
	}
	export class Overzicht {
	    listeners: Luisteraar[];
	    connections: Verbinding[];
	    withoutName: number;
	    elevated: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Overzicht(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.listeners = this.convertValues(source["listeners"], Luisteraar);
	        this.connections = this.convertValues(source["connections"], Verbinding);
	        this.withoutName = source["withoutName"];
	        this.elevated = source["elevated"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace main {
	
	export class BaselineInfo {
	    devices: number;
	    // Go type: time
	    updated: any;
	    empty: boolean;
	
	    static createFrom(source: any = {}) {
	        return new BaselineInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.devices = source["devices"];
	        this.updated = this.convertValues(source["updated"], null);
	        this.empty = source["empty"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Status {
	    lang: string;
	    adapter: netif.Adapter;
	    monitoring: boolean;
	    scanning: boolean;
	    passive: boolean;
	    passiveReason: string;
	    capture: boolean;
	    captureReason: string;
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.lang = source["lang"];
	        this.adapter = this.convertValues(source["adapter"], netif.Adapter);
	        this.monitoring = source["monitoring"];
	        this.scanning = source["scanning"];
	        this.passive = source["passive"];
	        this.passiveReason = source["passiveReason"];
	        this.capture = source["capture"];
	        this.captureReason = source["captureReason"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace model {
	
	export class Event {
	    // Go type: time
	    at: any;
	    tag: string;
	    key: string;
	    args?: Record<string, string>;
	    host: string;
	
	    static createFrom(source: any = {}) {
	        return new Event(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.at = this.convertValues(source["at"], null);
	        this.tag = source["tag"];
	        this.key = source["key"];
	        this.args = source["args"];
	        this.host = source["host"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Link {
	    from: string;
	    to: string;
	    kind: string;
	
	    static createFrom(source: any = {}) {
	        return new Link(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.from = source["from"];
	        this.to = source["to"];
	        this.kind = source["kind"];
	    }
	}
	export class Port {
	    number: number;
	    service: string;
	
	    static createFrom(source: any = {}) {
	        return new Port(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.number = source["number"];
	        this.service = source["service"];
	    }
	}
	export class NameSource {
	    value: string;
	    origin: string;
	
	    static createFrom(source: any = {}) {
	        return new NameSource(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.value = source["value"];
	        this.origin = source["origin"];
	    }
	}
	export class Host {
	    key: string;
	    ip: string;
	    mac: string;
	    vendor: string;
	    name: string;
	    kind: string;
	    status: string;
	    names: NameSource[];
	    model: string;
	    ports: Port[];
	    ttl: number;
	    osHint: string;
	    randomMac: boolean;
	    isGateway: boolean;
	    isSelf: boolean;
	    // Go type: time
	    firstSeen: any;
	    // Go type: time
	    lastSeen: any;
	    rxBytes: number;
	    txBytes: number;
	    noteKey: string;
	    noteArgs?: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new Host(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	        this.vendor = source["vendor"];
	        this.name = source["name"];
	        this.kind = source["kind"];
	        this.status = source["status"];
	        this.names = this.convertValues(source["names"], NameSource);
	        this.model = source["model"];
	        this.ports = this.convertValues(source["ports"], Port);
	        this.ttl = source["ttl"];
	        this.osHint = source["osHint"];
	        this.randomMac = source["randomMac"];
	        this.isGateway = source["isGateway"];
	        this.isSelf = source["isSelf"];
	        this.firstSeen = this.convertValues(source["firstSeen"], null);
	        this.lastSeen = this.convertValues(source["lastSeen"], null);
	        this.rxBytes = source["rxBytes"];
	        this.txBytes = source["txBytes"];
	        this.noteKey = source["noteKey"];
	        this.noteArgs = source["noteArgs"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Graph {
	    hosts: Host[];
	    links: Link[];
	    subnet: string;
	
	    static createFrom(source: any = {}) {
	        return new Graph(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hosts = this.convertValues(source["hosts"], Host);
	        this.links = this.convertValues(source["links"], Link);
	        this.subnet = source["subnet"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	

}

export namespace netif {
	
	export class Adapter {
	    index: number;
	    name: string;
	    description: string;
	    deviceName: string;
	    mac: string;
	    ip: string;
	    prefix: number;
	    cidr: string;
	    gateway: string;
	    dns: string[];
	    up: boolean;
	    metric: number;
	
	    static createFrom(source: any = {}) {
	        return new Adapter(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.index = source["index"];
	        this.name = source["name"];
	        this.description = source["description"];
	        this.deviceName = source["deviceName"];
	        this.mac = source["mac"];
	        this.ip = source["ip"];
	        this.prefix = source["prefix"];
	        this.cidr = source["cidr"];
	        this.gateway = source["gateway"];
	        this.dns = source["dns"];
	        this.up = source["up"];
	        this.metric = source["metric"];
	    }
	}

}

