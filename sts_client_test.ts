import { AssumeRoleRequest, Policy, StsClient } from "./sts_client.ts";

function sleep(seconds: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, seconds * 1000))
}

Deno.test("test aliyun sts client", async () => {
    const policy: Policy = {
        "Version": "1",
        "Statement":[
            {
                "Action":[
                    "oss:*"
                ],
                "Effect":"Allow",
                "Resource":[
                    "acs:oss:*:*:xxxxxx"
                ]
            }
        ]
    };

    const client = new StsClient("sts.aliyuncs.com", Deno.env.get("AID")!, Deno.env.get("ASEC")!);

    const response = await client.assumeRole(new AssumeRoleRequest(
        Deno.env.get("ARN")!,
        "aliyun-sts-deno-sdk",
        policy), {
        timeoutMs: 3000
    });

    console.log(response);

    console.log('sleep 3 seconds to release the AbortSignal');
    await sleep(3);
});