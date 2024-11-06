const MODELS = {
    "claude-3-opus": {
        vertexName: "claude-3-opus@20240229",
        regions: ["asia-southeast1", "europe-west1", "us-east5"],
    },
    "claude-3-sonnet": {
        vertexName: "claude-3-sonnet@20240229", 
        regions: ["asia-southeast1", "europe-west1", "us-east5"],
    },
    "claude-3-haiku": {
        vertexName: "claude-3-haiku@20240307",
        regions: ["asia-southeast1", "europe-west1", "us-east5"],
    },
    "claude-3-5-sonnet": {
        vertexName: "claude-3-5-sonnet@20240620",
        regions: ["asia-southeast1", "europe-west1", "us-east5"],
    },
    "claude-3-opus-20240229": {
        vertexName: "claude-3-opus@20240229",
        regions: ["asia-southeast1", "europe-west1", "us-east5"],
    },
    "claude-3-sonnet-20240229": {
        vertexName: "claude-3-sonnet@20240229",
        regions: ["asia-southeast1", "europe-west1", "us-east5"],
    },
    "claude-3-haiku-20240307": {
        vertexName: "claude-3-haiku@20240307",
        regions: ["asia-southeast1", "europe-west1", "us-east5"],
    },
    "claude-3-5-sonnet-20240620": {
        vertexName: "claude-3-5-sonnet@20240620",
        regions: ["asia-southeast1", "europe-west1", "us-east5"],
    },
    "claude-3-5-sonnet-v2": {
        vertexName: "claude-3-5-sonnet-v2@20241022",
        regions: ["asia-southeast1", "europe-west1", "us-east5"],
    },
    "claude-3-5-sonnet-v2-20241022": {
        vertexName: "claude-3-5-sonnet-v2@20241022",
        regions: ["asia-southeast1", "europe-west1", "us-east5"],
    },
    "claude-3-5-sonnet-v2@20241022": {
        vertexName: "claude-3-5-sonnet-v2@20241022",
        regions: ["asia-southeast1", "europe-west1", "us-east5"],
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
        var authHeader = request.headers.get("Authorization");
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return createErrorResponse(401, "authentication_error", "Missing or invalid Authorization header");
        }
        var apiKey = authHeader.slice(7);
    }
    if (!API_KEY || API_KEY !== apiKey) {
        return createErrorResponse(401, "authentication_error", "Invalid API key");
    }

    const signedJWT = await createSignedJWT(CLIENT_EMAIL, PRIVATE_KEY)
    const [token, err] = await exchangeJwtForAccessToken(signedJWT)
    if (token === null) {
        console.log(`Invalid jwt token: ${err}`)
        return createErrorResponse(500, "api_error", "Invalid authentication credentials");
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

    let payload;
    try {
        payload = await request.json();
    } catch (err) {
        return createErrorResponse(400, "invalid_request_error", `The request body is not valid JSON: ${err.message}`);
    }

    payload.anthropic_version = "vertex-2023-10-16";
    
    payload = await convertPayloadFormat(payload, apiFormat); // 修改为异步函数
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
    // 随机选择一个region
    const region = model.regions[Math.floor(Math.random() * model.regions.length)];
    const url = `https://${region}-aiplatform.googleapis.com/v1/projects/${PROJECT}/locations/${region}/publishers/anthropic/models/${model.vertexName}:streamRawPredict`;
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
                let eventList = buffer.split(/\r?\n\r?\n/);
                buffer = eventList.pop(); // 保留未完成的部分
                
                for (let event of eventList) {
                    if (apiFormat === "openai") {
                        const lines = event.split('\n');
                        let eventData = {};
                        for (const line of lines) {
                            const [key, value] = line.split(/:(.+)/);
                            if (key && value) {
                                eventData[key.trim()] = value.trim();
                            }
                        }
                        if (eventData.event === "content_block_end") {
                            controller.enqueue(encoder.encode(`data: [DONE]\n\n`));
                            controller.close();
                        } else if (eventData.event === "content_block_delta") {
                            const dataContent = JSON.parse(eventData.data);
                            let deltaContent = dataContent.delta.text || '';
                            
                            let transformedData = {
                                id: dataContent.request_id || `chatcmpl-${Math.random().toString(36).substr(2, 9)}`,
                                object: 'chat.completion.chunk',
                                created: Math.floor(Date.now() / 1000),
                                model: payload.model,
                                choices: [{
                                    index: 0,
                                    delta: { content: deltaContent },
                                    finish_reason: null
                                }]
                            };
                            controller.enqueue(encoder.encode(`data: ${JSON.stringify(transformedData)}\n\n`));
                        }
                    } else {
                        // 对于 Claude 格式，直接转发
                        controller.enqueue(encoder.encode(`${event}\n\n`));
                    }                    
                }
            },
            flush(controller) {
                if (buffer) {
                    controller.enqueue(encoder.encode(buffer));
                }
            }
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
                // 修改这里以正确提取 Claude API 返回的内容
                let content = "";
                if (data.content && data.content.length > 0) {
                    content = data.content.map(item => item.text).join('');
                } else if (data.completion) {
                    content = data.completion;
                }

                const transformedData = {
                    id: data.id || `chatcmpl-${Math.random().toString(36).substr(2, 9)}`,
                    object: "chat.completion",
                    created: Math.floor(Date.now() / 1000),
                    model: payload.model, // 使用原始请求体中的 model
                    choices: [{
                        index: 0,
                        message: {
                            role: "assistant",
                            content: content,
                        },
                        finish_reason: mapStopReason(data.stop_reason)
                    }],
                    usage: {
                        prompt_tokens: data.usage?.input_tokens || 0,
                        completion_tokens: data.usage?.output_tokens || 0,
                        total_tokens: (data.usage?.input_tokens || 0) + (data.usage?.output_tokens || 0)
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

function mapStopReason(stopReason) {
    switch (stopReason) {
        case "stop_sequence":
            return "stop";
        case "max_tokens":
            return "length";
        default:
            return null;
    }
}

async function convertPayloadFormat(payload, apiFormat) {
    if (apiFormat === "openai") {
        const convertedPayload = {
            messages: [],
            model: payload.model,
            max_tokens: payload.max_tokens,
            temperature: payload.temperature,
            top_p: payload.top_p,
            stream: payload.stream,
            stop_sequences: payload.stop,
            anthropic_version: "vertex-2023-10-16" // 添加 Claude 所需的版本参数
        };

        // 处理 system 消息
        const systemMessage = payload.messages.find(msg => msg.role === "system");
        if (systemMessage) {
            convertedPayload.system = systemMessage.content;
        }

        // 处理其他消息
        for (const message of payload.messages) {
            if (message.role === "system") continue; // 已经处理过了

            const convertedMessage = {
                role: message.role,
                content: []
            };

            if (typeof message.content === "string") {
                convertedMessage.content.push({
                    type: "text",
                    text: message.content
                });
            } else if (Array.isArray(message.content)) {
                for (const content of message.content) {
                    if (content.type === "text") {
                        convertedMessage.content.push({
                            type: "text",
                            text: content.text
                        });
                    } else if (content.type === "image_url") {
                        // 下载并编码图像
                        const base64Data = await downloadAndEncodeImage(content.image_url.url);
                        convertedMessage.content.push({
                            type: "image",
                            source: {
                                type: "base64",
                                media_type: "image/png", // 根据实际情况设置
                                data: base64Data
                            }
                        });
                    }
                }
            }
            convertedPayload.messages.push(convertedMessage);
        }

        // 处理 tools/functions
        if (payload.functions || payload.tools) {
            convertedPayload.tools = payload.functions || payload.tools;
        }

        // 移除所有未定义的属性
        Object.keys(convertedPayload).forEach(key => 
            convertedPayload[key] === undefined && delete convertedPayload[key]
        );

        return convertedPayload;
    }
    return payload;
}

async function downloadAndEncodeImage(url) {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`Unable to download image: ${response.statusText}`);
    }
    const arrayBuffer = await response.arrayBuffer();
    const base64String = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
    return base64String;
}

function createErrorResponse(status, errorType, message) {
    const errorObject = {
        error: {
            message: message,
            type: errorType,
            param: null,
            code: null
        }
    };
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
            .map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v))
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