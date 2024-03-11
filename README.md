# deno_aliyun_sts 阿里云 STS SDK Deno 版本。

最近尝试使用 Deno 做一个小项目，需要用到调用阿里云 OpenAPI 中的 STS 部分，
所以先编写了一个简单的 `StsClient`，目前仅实现了 `AssumeRole` 方法。

官方文档：

- [AssumeRole - 获取扮演角色的临时身份凭证](https://help.aliyun.com/zh/ram/developer-reference/api-sts-2015-04-01-assumerole?spm=a2c4g.11186623.0.0.104c2600muyjDV)
- [OpenAPI Explorer: AssumeRole](https://next.api.aliyun.com/api/Sts/2015-04-01/AssumeRole)


使用方法：

```typescript
const client = new StsClient("sts.aliyuncs.com", Deno.env.get("AID")!, Deno.env.get("ASEC")!);

const response = await client.assumeRole(new AssumeRoleRequest(
    Deno.env.get("ARN")!,
    "aliyun-sts-deno-sdk",
    policy)
);
```