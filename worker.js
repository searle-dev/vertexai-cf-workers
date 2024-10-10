const MODELS = {
    "claude-3-opus": {
        vertexName: "claude-3-opus@20240229",
        region: "us-east5",
    },
    "claude-3-sonnet": {
        vertexName: "claude-3-sonnet@20240229",
        region: "us-central1",
    },
    "claude-3-haiku": {
        vertexName: "claude-3-haiku@20240307",
        region: "us-central1",
    },
    "claude-3-5-sonnet": {
        vertexName: "claude-3-5-sonnet@20240620",
        region: "us-east5",
    },
    "claude-3-opus-20240229": {
        vertexName: "claude-3-opus@20240229",
        region: "us-east5",
    },
    "claude-3-sonnet-20240229": {
        vertexName: "claude-3-sonnet@20240229",
        region: "us-central1",
    },
    "claude-3-haiku-20240307": {
        vertexName: "claude-3-haiku@20240307",
        region: "us-central1",
    },
    "claude-3-5-sonnet-20240620": {
        vertexName: "claude-3-5-sonnet@20240620",
        region: "us-east5",
    },
};
var apiFormat;

addEventListener("fetch", (event) => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    let headers = new Headers({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    });
    if (request.method === "OPTIONS") {
        return new Response(null, { headers });
    } else if (request.method === "GET") {
        return createErrorResponse(405, "invalid_request_error", "GET method is not allowed");
    }

    if (request.headers.get("x-api-key")) {
        apiFormat = "claude";
        var apiKey = request.headers.get("x-api-key");
    } else {
        apiFormat = "openai";
        var apiKey = request.headers.get("Authorization").slice(7);
    }
    if (!API_KEY || API_KEY !== apiKey) {
        return createErrorResponse(401, "authentication_error", "invalid x-api-key");
    }

    const signedJWT = await createSignedJWT(CLIENT_EMAIL, PRIVATE_KEY)
    const [token, err] = await exchangeJwtForAccessToken(signedJWT)
    if (token === null) {
        console.log(`Invalid jwt token: ${err}`)
        return createErrorResponse(500, "api_error", "invalid authentication credentials");
    }

    try {
        const url = new URL(request.url);
        const normalizedPathname = url.pathname.replace(/^(\/)+/, '/');
        switch(normalizedPathname) {
            case "/v1/v1/messages":
            case "/v1/messages":
            case "/messages":
            case "/v1/chat/completions":
            case "/v1/v1/chat/completions":
                return handleMessagesEndpoint(request, token);
            default:
                return createErrorResponse(404, "not_found_error", "Not Found");
        }
    } catch (error) {
        console.error(error);
        return createErrorResponse(500, "api_error", `An unexpected error occurred: ${error.message}`);
    }
}
 
async function handleMessagesEndpoint(request, api_token) {
    const anthropicVersion = request.headers.get('anthropic-version');
    if (anthropicVersion && anthropicVersion !== '2023-06-01' && apiFormat === 'claude') {
        return createErrorResponse(400, "invalid_request_error", "API version not supported");
    }

    let payload;
    try {
        payload = await request.json();
    } catch (err) {
        return createErrorResponse(400, "invalid_request_error", `The request body is not valid JSON: ${err.message}`);
    }

    payload.anthropic_version = "vertex-2023-10-16";
    
    payload = convertPayloadFormat(payload, apiFormat);
    if (!payload.max_tokens) {
        payload.max_tokens = 4000;
    }

    if (!payload.model) {
        return createErrorResponse(400, "invalid_request_error", "Missing model in the request payload.");
    } else if (!MODELS[payload.model]) {
        return createErrorResponse(400, "invalid_request_error", `Model \`${payload.model}\` not found.`);
    }

    const stream = payload.stream || false;
    const model = MODELS[payload.model];
    const url = `https://${model.region}-aiplatform.googleapis.com/v1/projects/${PROJECT}/locations/${model.region}/publishers/anthropic/models/${model.vertexName}:streamRawPredict`;
    delete payload.model;

    let response, contentType
    try {
        response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${api_token}`
            },
            body: JSON.stringify(payload)
        });
        contentType = response.headers.get("Content-Type") || "application/json";
    } catch (error) {
        return createErrorResponse(500, "api_error", `Server Error: ${error.message}`);
    }

    if (stream && contentType.startsWith('text/event-stream')) {
        if (!(response.body instanceof ReadableStream)) {
            return createErrorResponse(500, "api_error", "Server Error: Response body is not a ReadableStream");
        }

        const encoder = new TextEncoder();
        const decoder = new TextDecoder("utf-8");
        let buffer = '';
        let { readable, writable } = new TransformStream({
            transform(chunk, controller) {
                let decoded = decoder.decode(chunk, { stream: true });
                buffer += decoded;
                let eventList = buffer.split(/\r\n\r\n|\r\r|\n\n/g);
                if (eventList.length === 0) return;
                buffer = eventList.pop();
                
                let stop = false;
                for (let event of eventList) {
                    if (apiFormat === "openai") {
                        const eventMatch = event.match(/event:(.+?)\n/);
                        if (eventMatch[1].trim() === 'content_block_stop') {
                            stop = true;
                        }

                        if (eventMatch[1].trim() === "content_block_delta") {
                            const dataMatch = event.match(/data:(.+)$/);
                            let chunk_data = JSON.parse(dataMatch[1]);

                            let transformedData = {
                                id: '01234567-890a-bcde-f012-34567890abcd',
                                object: 'chat.completion.chunk',
                                created: Math.floor(Date.now() / 1000),
                                model: payload.model, // 使用原始请求体中的model字段
                                system_fingerprint: 'vertexai-cf-workers-123456789',
                                choices: [{
                                index: 0,
                                delta: { content: chunk_data.delta.text },
                                logprobs: null,
                                finish_reason: ''
                                }]
                            };
                            controller.enqueue(encoder.encode(`data: ${JSON.stringify(transformedData)}\n\n`));
                        } else {
                            continue;
                        }
                    } else {
                        controller.enqueue(encoder.encode(`${event}\n\n`));
                    }                    
                }
            },
        });
        response.body.pipeTo(writable);
        return new Response(readable, {
            status: response.status,
            headers: {
                "Content-Type": response.headers.get("Content-Type") || "text/event-stream",
                "Access-Control-Allow-Origin": "*",
            },
        });
    } else {
        try {
            let data = await response.json();
            if (apiFormat === "openai") {
                const transformedData = {
                    id: data.id || `chatcmpl-${Math.random().toString(36).substr(2, 9)}`,
                    object: "chat.completion",
                    created: Math.floor(Date.now() / 1000),
                    model: data.model || payload.model,
                    system_fingerprint: `fp_${Math.random().toString(36).substr(2, 8)}`,
                    choices: [{
                        index: 0,
                        message: {
                            role: data.role || "assistant",
                            content: data.content[0]?.text || "",
                        },
                        logprobs: null,
                        finish_reason: data.stop_reason || "stop"
                    }],
                    usage: {
                        prompt_tokens: data.usage?.input_tokens || 0,
                        completion_tokens: data.usage?.output_tokens || 0,
                        total_tokens: (data.usage?.input_tokens || 0) + (data.usage?.output_tokens || 0),
                        completion_tokens_details: {
                            reasoning_tokens: 0
                        }
                    }
                };
                return new Response(JSON.stringify(transformedData), {
                    status: response.status,
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                    },
                });
            } else {
                return new Response(JSON.stringify(data), {
                    status: response.status,
                    headers: {
                        "Content-Type": contentType,
                        "Access-Control-Allow-Origin": "*",
                    },
                });
            }
        } catch (error) {
            console.error("Error processing API response:", error);
            return createErrorResponse(500, "api_error", `Server Error: ${error.message}`);
        }
    }
}

function convertPayloadFormat(payload, apiFormat) {
    if (apiFormat === "openai") {
        const convertedPayload = {
            ...payload,
            messages: []
        };
        for (const message of payload.messages) {
            if (message.role === "system") {
                // 如果 message.role 为 "system",将 message.content 赋值给 payload.system,并跳过这个 message
                convertedPayload.system = message.content;
                continue;
            }
            
            const convertedMessage = {
                role: message.role,
                content: []
            };
            // 判断 message.content 的类型是否为字符串
            if (typeof message.content === "string") {
                // 如果是字符串,直接将其作为文本类型添加到 convertedMessage.content 数组中
                convertedMessage.content.push({
                    type: "text",
                    text: message.content
                });
            } else {
                // 如果不是字符串,则认为它是一个数组,遍历数组中的每个 content 对象
                for (const content of message.content) {
                    if (content.type === "text") {
                        convertedMessage.content.push({
                            type: "text",
                            text: content.text
                        });
                    } else if (content.type === "image_url") {
                        const [mediaType, imageData] = content.image_url.url.split(";base64,");
                        convertedMessage.content.push({
                            type: "image",
                            source: {
                                type: "base64",
                                media_type: mediaType.split(":")[1],
                                data: imageData
                            }
                        });
                    }
                }
            }
            convertedPayload.messages.push(convertedMessage);
        }
        return convertedPayload;
    }
    return payload;
}

function createErrorResponse(status, errorType, message) {
    const errorObject = { type: "error", error: { type: errorType, message: message } };
    return new Response(JSON.stringify(errorObject), {
        status: status,
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
    });
}

async function createSignedJWT(email, pkey) {
    pkey = pkey.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\r|\n|\\n/g, "");
    let cryptoKey = await crypto.subtle.importKey(
        "pkcs8",
        str2ab(atob(pkey)),
        {
            name: "RSASSA-PKCS1-v1_5",
            hash: { name: "SHA-256" },
        },
        false,
        ["sign"]
    );

    const authUrl = "https://www.googleapis.com/oauth2/v4/token";
    const issued = Math.floor(Date.now() / 1000);
    const expires = issued + 600;

    const header = {
        alg: "RS256",
        typ: "JWT",
    };

    const payload = {
        iss: email,
        aud: authUrl,
        iat: issued,
        exp: expires,
        scope: "https://www.googleapis.com/auth/cloud-platform",
    };

    const encodedHeader = urlSafeBase64Encode(JSON.stringify(header));
    const encodedPayload = urlSafeBase64Encode(JSON.stringify(payload));

    const unsignedToken = `${encodedHeader}.${encodedPayload}`;

    const signature = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        cryptoKey,
        str2ab(unsignedToken)
    );

    const encodedSignature = urlSafeBase64Encode(signature);
    return `${unsignedToken}.${encodedSignature}`;
}

async function exchangeJwtForAccessToken(signed_jwt) {
    const auth_url = "https://www.googleapis.com/oauth2/v4/token";
    const params = {
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: signed_jwt,
    };

    const r = await fetch(auth_url, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: Object.entries(params)
            .map(([k, v]) => k + "=" + v)
            .join("&"),
    }).then((res) => res.json());

    if (r.access_token) {
        return [r.access_token, ""];
    }

    return [null, JSON.stringify(r)];
}

function str2ab(str) {
    const buffer = new ArrayBuffer(str.length);
    let bufferView = new Uint8Array(buffer);
    for (let i = 0; i < str.length; i++) {
        bufferView[i] = str.charCodeAt(i);
    }
    return buffer;
}

function urlSafeBase64Encode(data) {
    let base64 = typeof data === "string" ? btoa(encodeURIComponent(data).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode(parseInt("0x" + p1)))) : btoa(String.fromCharCode(...new Uint8Array(data)));
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}