# vertexai-cf-workers

## 前提条件
1. 注册GCP账户：
   - 访问 [https://cloud.google.com/vertex-ai](https://cloud.google.com/vertex-ai) 并注册GCP账户。
   - 您可以获得150美元的免费额度（无需信用卡），或者提供信用卡信息获得300美元的免费额度。（请注意，免费额度将在90天后过期）

2. 启用Vertex AI API：
   - 访问 [https://console.cloud.google.com/marketplace/product/google/aiplatform.googleapis.com](https://console.cloud.google.com/marketplace/product/google/aiplatform.googleapis.com) 为您的项目启用Vertex AI API。
   
3. 申请使用Claude模型：
   - 访问 [https://console.cloud.google.com/vertex-ai](https://console.cloud.google.com/vertex-ai) 并申请访问Claude模型。

4. 创建[服务账户](https://console.cloud.google.com/projectselector/iam-admin/serviceaccounts/create?walkthrough_id=iam--create-service-account#step_index=1)：
   - 选择您之前创建的项目ID。
   - 确保为服务账户授予"Vertex AI User"或"Vertex AI Administrator"角色。
   - 在您刚刚创建的服务账户页面，转到"密钥"标签页并点击"添加密钥"。
   - 选择"创建新密钥"并选择"JSON"作为密钥类型。
   - 密钥文件将自动下载。该文件包含worker所需的变量，如project_id、private_key和client_email。
   
## Worker变量

worker需要设置以下几个环境变量：

- `CLIENT_EMAIL`：这是与您的GCP服务账户关联的电子邮件。您可以在服务账户的JSON密钥文件中找到它。
- `PRIVATE_KEY`：这是与您的GCP服务账户关联的私钥。您可以在服务账户的JSON密钥文件中找到它。
- `PROJECT`：这是您的GCP项目的ID。您可以在服务账户的JSON密钥文件中找到它。
- `API_KEY`：这是您自定义的字符串。它用于验证对worker的请求。



## 接口使用说明

本worker支持两种API风格：OpenAI风格和Claude风格。您可以根据自己的需求选择使用其中一种。

支持以下路径：
 `/v1/chat/completions`、`/v1/v1/chat/completions`、`/v1/messages`、`/v1/v1/messages`、`/messages`

### OpenAI风格

1. 发送POST请求到worker的URL。
2. 在请求头中设置：
   - `Content-Type: application/json`
   - `Authorization: Bearer YOUR_API_KEY`（将YOUR_API_KEY替换为您设置的API_KEY）

### Claude风格

1. 发送POST请求到worker的URL。
2. 在请求头中设置：
   - `Content-Type: application/json`
   - `x-api-key: YOUR_API_KEY`（将YOUR_API_KEY替换为您设置的API_KEY）

注意：请确保在使用API时遵守相关的使用条款和隐私政策。

