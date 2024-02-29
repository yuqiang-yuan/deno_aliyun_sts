import { crypto } from "std/crypto/mod.ts";
import { encodeHex } from "std/encoding/hex.ts";

import { hmac } from "hmac/mod.ts";

import { currentDateAsISO8601, generateNonce } from "./helper.ts";

const DEBUG = (!!Deno.env.get("DEBUG")) && Deno.env.get("DEBUG")!.includes("sts-sdk");

export enum Versions {
    V1 = "1"
};

export type ConditionItem = Record<string, string | string[]>;

/**
 * Policy statement
 */
export interface StatementBlock {
    Effect: "Allow" | "Deny";
    Action: string | string[];
    Resource: string | string[];
    Condition?: Record<string, ConditionItem>;
};

/**
 * 权限策略。
 * 
 * 更多信息请参考 [阿里云官方文档](https://help.aliyun.com/zh/ram/user-guide/policy-language/?spm=a2c4g.11186623.0.0.5f0063e7VwDmOd)。
 */
export interface Policy {
    Version: Versions | "1";
    Statement: StatementBlock[];
}

export interface RequestOptions {
    /**
     * 请求超时，单位为毫秒
     * 因为 fetch API 对超时的控制没有区分连接超时和读取超时，
     * 虽然可以自己做读取超时，但是太复杂了，先用一个超时解决吧。
     * @type {[type]}
     */
    timeoutMs?: number;
};

/**
 * AssumeRole API request class
 */
export class AssumeRoleRequest {
    /**
     * Token 有效期。单位：秒。
     *
     * Token 有效期最小值为 `900` 秒，最大值为要扮演角色的 `MaxSessionDuration` 时间。默认值为 `3600` 秒。
     * @type {number}
     */
    public durationSeconds: number = 3600;

    /**
     * 为 STS Token 额外添加的一个权限策略，进一步限制 STS Token 的权限。具体如下：
     *
     * - 如果指定该权限策略，则 STS Token 最终的权限策略取 RAM 角色权限策略与该权限策略的交集。
     * - 如果不指定该权限策略，则 STS Token 最终的权限策略取 RAM 角色的权限策略。
     * 
     * @type {Policy | null}
     */
    public policy: Policy | null = null;

    /**
     * 要扮演的 RAM 角色 ARN。
     * @type {string}
     */
    public roleArn: string;

    /**
     * 角色会话名称。
     * 
     * 该参数为用户自定义参数。
     * 通常设置为调用该 API 的用户身份，例如：用户名。在操作审计日志中，
     * 即使是同一个 RAM 角色执行的操作，
     * 也可以根据不同的 `RoleSessionName` 来区分实际操作者，以实现用户级别的访问审计。
     * 
     * 长度为 `2~64` 个字符，可包含英文字母、数字和特殊字符`.@-_`。
     * @type {string}
     */
    public roleSessionName: string;

    /**
     * 角色外部 ID。
     * 该参数为外部提供的用于表示角色的参数信息，主要功能是防止混淆代理人问题。
     *
     * 长度为 `2~1224` 个字符，可包含英文字母、数字和特殊字符 `=,.@:/-_。正则为：[\w+=,.@:\/-]*`。
     * @type {[type]}
     */
    public externalId: string | null = null;

    /**
     * Construct an assume role request
     * @param {string}    roleArn         
     * @param {string}    roleSessionName [description]
     * @param {Policy |               null}        policy [description]
     */
    public constructor(roleArn: string, roleSessionName: string, policy: Policy | null) {
        this.roleArn = roleArn;
        this.roleSessionName = roleSessionName;
        this.policy = policy;
    }
};

/**
 * AssumeRole 操作成功的响应
 */
export interface AssumeRoleResponse {
    requestId: string;
    assumedRoleUser: {
        arn: string;
        assumedRoleId: string;
    };
    credentials: {
        securityToken: string;
        accessKeyId: string;
        accessKeySecret: string;
        expiration: string;
    }
};

class ClientError extends Error {
    #requestId?: string;
    #hostId?: string;
    #code?: string;
    #recommend?: string;

    constructor(message: string, requestId?: string, hostId?: string, code?: string, recommend?: string) {
        super(message);

        this.#requestId = requestId;
        this.#hostId = hostId;
        this.#code = code;
        this.#recommend = recommend;
    }

    static fromHttpError(message: string, status: number): ClientError {
        return new ClientError(message, undefined, undefined, `${status}`, undefined);
    }

    get requestId() {
        return this.#requestId;
    }

    get hostId() {
        return this.#hostId;
    }

    get code() {
        return this.#code;
    }

    get recommend() {
        return this.#recommend;
    }

}

function log(msg: string) {
    if (!DEBUG) {
        return;
    }
    console.log(msg);
}

export class StsClient {
    private endpoint: string;
    private accessKeyId: string;
    private accessKeySecret: string;

    private defaultHeaders: Record<string, string> = {
        "x-sdk-client": "deno/1.0.0",
        "x-acs-version": "2015-04-01",
        "Accept": "application/json",
    };

    /**
     * 构造函数
     * @param {string} endpoint        Sts 是不区分端点的，统一都是 `sts.aliyuncs.com`
     * @param {string} accessKeyId     访问 ID
     * @param {string} accessKeySecret 访问密钥
     */
    public constructor(endpoint: string, accessKeyId: string, accessKeySecret: string) {
        this.endpoint = endpoint;
        this.accessKeyId = accessKeyId;
        this.accessKeySecret = accessKeySecret;
    }

    private async doRequest(method: "GET"|"POST"|"PUT"|"DELETE"|"PATCH"|"OPTIONS"|"HEAD", 
                    uri: string,
                    headers: Record<string, string>,
                    query: Record<string, string>,
                    payload: Record<string, string> | null,
                    options?: RequestOptions) {
        const timeString = currentDateAsISO8601();
        const nonce = generateNonce();

        const allHeaders: Record<string, string> = Object.assign({
            "x-acs-signature-nonce": nonce,
            "x-acs-date": timeString,
            "host": this.endpoint,
        }, this.defaultHeaders, headers);

        // 传入的请求参数，按照 Key 排序，然后编码并且使用 & 拼接
        const canonicalQueryString = Object.entries(query)
            .sort((e1, e2) => e1[0].localeCompare(e2[0]))
            .map(([k, v]) => `${encodeURIComponent(k)}=${v === null || v === undefined ? "" : encodeURIComponent(v)}`)
            .join("&");

        // 组装 FORM 表单请求体    
        const payloadString = payload ? Object.entries(payload)
            .map(([k, v]) => `${encodeURIComponent(k)}=${v === null || v === undefined ? "" : encodeURIComponent(v)}`)
            .join("&") : "";

        const payloadBytes = (new TextEncoder()).encode(payloadString);

        // 对请求体进行 SHA256 摘要
        const payloadHashString = encodeHex(await crypto.subtle.digest("SHA-256", payloadBytes));

        // 摘要结果放到请求头中
        allHeaders["x-acs-content-sha256"] = payloadHashString;

        // 需要参与签名的请求头
        // 请求头转小写（阿里云公共请求头包含： host 和 x-acs- 开头的）
        // 排序
        const canonicalHeaders = Object.entries(allHeaders)
            .map(([k, v]) => [k.toLowerCase(), v.trim()])
            .filter(([k, v]) => k === "host" || k.startsWith("x-acs-"))
            .sort((e1, e2) => e1[0].localeCompare(e2[0]));

        // 请求头名和值使用冒号（:）拼接    
        const canonicalHeaderString = canonicalHeaders.map(([k, v]) => `${k}:${v}`).join("\n");

        // 请求头的名使用分号（;）拼接
        const canonicalHeaderNameString = canonicalHeaders.map(([k, _]) => k).join(";");

        // 构造规范请求的文本
        const canonicalRequest = `${method}\n${uri}\n${canonicalQueryString}\n${canonicalHeaderString}\n\n${canonicalHeaderNameString}\n${payloadHashString}`;

        log("\n---- begin of canoical request ----");
        log(canonicalRequest);
        log("---- end of canoical request ----\n");

        // 对规范请求体进行 SHA256 摘要
        const canonicalRequestHashString = encodeHex(await crypto.subtle.digest("SHA-256", (new TextEncoder()).encode(canonicalRequest)));

        log(`canonical request hash string: ${canonicalRequestHashString}`);

        const string2sign = `ACS3-HMAC-SHA256\n${canonicalRequestHashString}`;

        log("\n---- begin of string to sign ----")
        log(string2sign);
        log("---- endof of string to sign ----\n")

        const sigString = hmac("sha256", this.accessKeySecret, string2sign, "utf8", "hex");

        log(`Hmac-SHA256 signature result: ${sigString}`);

        const authorizationHeader = `ACS3-HMAC-SHA256 Credential=${this.accessKeyId},SignedHeaders=${canonicalHeaderNameString},Signature=${sigString}`;

        log(`authorization header: ${authorizationHeader}`);

        allHeaders["Authorization"] = authorizationHeader;

        if (payloadString.length > 0) {
            allHeaders["Content-Length"] = `${payloadBytes.length}`;
        }

        allHeaders["Content-Type"] = "application/x-www-form-urlencoded";

        const fullUrl = `https://${this.endpoint}${uri}${canonicalQueryString.length > 0 ? "?" : "" }${canonicalQueryString}`;
        log(`full url: ${fullUrl}`);

        log(`> ${method} ${fullUrl}`);
        if (DEBUG) {
            Object.entries(allHeaders).forEach(([k, v]) => log(`> Header ${k}:${v}`));
        }

        const { timeoutMs } = Object.assign({
            timeoutMs: 10000 // default timeout: 10 seconds
        }, options);

        const requestInit:RequestInit = {
            method: method,
            headers: allHeaders,
            keepalive: false,
            signal: AbortSignal.timeout(timeoutMs)
        };

        if (payloadString.length > 0) {
            requestInit.body = payloadBytes
        }

        try {
            const response = await fetch(fullUrl, requestInit);

            if (response.status >= 500) {
                log(`< response is NOT OK: ${response.status}`);
                throw ClientError.fromHttpError("response status code error", response.status);
            }

            if (response.status >= 400) {
                log(`< response is NOT OK: ${response.status}`);
                const {RequestId, HostId, Code, Message, Recommend } = await response.json();
                throw new ClientError(Message, RequestId, HostId, Code, Recommend);
            }

            const retObj = await response.json();
            return {
                requestId: retObj.RequestId,
                assumedRoleUser: {
                    assumedRoleId: retObj.AssumedRoleUser.AssumedRoleId,
                    arn: retObj.AssumedRoleUser.Arn
                },
                credentials: {
                    securityToken: retObj.Credentials.SecurityToken,
                    accessKeyId: retObj.Credentials.AccessKeyId,
                    accessKeySecret: retObj.Credentials.AccessKeySecret,
                    expiration: retObj.Credentials.Expiration
                }
            } as AssumeRoleResponse;
        } catch(e) {
            if (e.name === "TimeoutError") {
                throw new Error("request timeout");
            }

            throw e;
        }
    }

    public async assumeRole(config: AssumeRoleRequest, options?: RequestOptions) {
        const headers: Record<string, string> = {
            "x-acs-action": "AssumeRole",
        };

        const payload: Record<string, string> = {
            DurationSeconds: `${config.durationSeconds}`,
            RoleArn: config.roleArn,
            RoleSessionName: config.roleSessionName,
        };

        if (config.policy) {
            payload.Policy = JSON.stringify(config.policy);
        }

        if (config.externalId) {
            payload.ExternalId = config.externalId;
        }

        return await this.doRequest("POST", "/", headers, {}, payload, options);
    }

}
