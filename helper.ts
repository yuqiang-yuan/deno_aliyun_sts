/**
 * 
 * 
 * [官方文档](https://help.aliyun.com/zh/sdk/product-overview/v3-request-structure-and-signature?spm=a2c4g.11186623.0.0.500d46bc5FXfiO)
 * @return {string} 按照ISO 8601标准表示的UTC时间，格式为yyyy-MM-ddTHH:mm:ssZ，例如2018-01-01T12:00:00Z。
 */
export function currentDateAsISO8601(): string {
    const s = (new Date()).toISOString();
    return `${s.substring(0, s.length - 5)}Z`;
}

/**
 * 生成随机码
 * @return {string} 目前是比较简单的，取得是系统时间毫秒
 */
export function generateNonce(): string {
    return `${Date.now()}`;
}