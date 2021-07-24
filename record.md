



# 登录请求包

```http
POST /api/v1/me/login HTTP/1.1
Host: 150.158.186.39:3443
Connection: keep-alive
Content-Length: 123
Accept: application/json, text/plain, */*
Origin: https://150.158.186.39:3443
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36
Content-Type: application/json
Referer: https://150.158.186.39:3443/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9

{"email":"awvs@awvs.com","password":"9382b12ca4229acc0320b739c5721d39946fdf98f448ac099464c4d6664121c3","remember_me":false}


返回包：

HTTP/1.1 204 No Content
X-Auth: 2986ad8c0a5b3df4d7028d5f3c06e936c61019146a864a03a2d0845649c2d5cf0714cb599c16294d2f8d6a865761b5d637763c181ac9e1993fd8277536c3ea8b1
Pragma: no-cache
Expires: -1
Cache-Control: no-cache, must-revalidate
Set-Cookie: ui_session=2986ad8c0a5b3df4d7028d5f3c06e936c61019146a864a03a2d0845649c2d5cf0714cb599c16294d2f8d6a865761b5d637763c181ac9e1993fd8277536c3ea8b1; Secure; HttpOnly; Path=/; SameSite=Strict
x-acxv: 14.3.210615184
Date: Tue, 20 Jul 2021 17:17:58 GMT
```

# 获取key

```http
POST /api/v1/me/credentials/api-key HTTP/1.1
Host: 150.158.186.39:3443
Connection: keep-alive
Content-Length: 2
Origin: https://150.158.186.39:3443
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36
Content-Type: application/json
Accept: application/json, text/plain, */*
Cache-Control: no-cache
x-auth: 2986ad8c0a5b3df4d7028d5f3c06e936c610137b9ea02010941d6474abf51823f17e04e48af784cbb979b6b59e1afbc2eca57c493d27da84c3302e01959c4cdb9
Referer: https://150.158.186.39:3443/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: ui_session=2986ad8c0a5b3df4d7028d5f3c06e936c610137b9ea02010941d6474abf51823f17e04e48af784cbb979b6b59e1afbc2eca57c493d27da84c3302e01959c4cdb9

{}
```

# 添加任务

![image-20210721004958543](readme.assets/image-20210721004958543.png)

```http
POST /api/v1/targets/add HTTP/1.1
Host: 150.158.186.39:3443
Connection: keep-alive
Content-Length: 95
Origin: https://150.158.186.39:3443
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36
Content-Type: application/json
Accept: application/json, text/plain, */*
Cache-Control: no-cache
x-auth: 2986ad8c0a5b3df4d7028d5f3c06e936c610137b9ea02010941d6474abf51823f17e04e48af784cbb979b6b59e1afbc2eca57c493d27da84c3302e01959c4cdb9
Referer: https://150.158.186.39:3443/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: ui_session=2986ad8c0a5b3df4d7028d5f3c06e936c610137b9ea02010941d6474abf51823f17e04e48af784cbb979b6b59e1afbc2eca57c493d27da84c3302e01959c4cdb9

{"targets":[{"address":"https://github.com/","description":"https://github.com/"}],"groups":[]}
```

## 返回包

```http
{
 "targets": [
  {
   "address": "https://github.com/",
   "criticality": 10,
   "description": "https://github.com/",
   "type": "default",
   "domain": "github.com",
   "target_id": "b0194afd-7c76-42c2-a8fb-65482498fe46",
   "target_type": null,
   "canonical_address": "github.com",
   "canonical_address_hash": "5449c29ccc8e333a30545d3434cc3b33"
  }
 ]
}
```



保存任务：

```http
{"scan_speed":"fast","login":{"kind":"none"},"ssh_credentials":{"kind":"none"},"default_scanning_profile_id":"11111111-1111-1111-1111-111111111111","sensor":true,"user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4298.0 Safari/537.36","case_sensitive":"no","limit_crawler_scope":true,"excluded_paths":[],"authentication":{"enabled":false},"proxy":{"enabled":false},"technologies":[],"custom_headers":[],"custom_cookies":[],"debug":false,"restrict_scans_to_import_files":false,"client_certificate_password":"","client_certificate_url":null,"issue_tracker_id":"","excluded_hours_id":null,"preseed_mode":""}
```





# 启动任务

```http
POST /api/v1/scans HTTP/1.1
Host: 150.158.186.39:3443
Connection: keep-alive
Content-Length: 245
Origin: https://150.158.186.39:3443
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36
Content-Type: application/json
Accept: application/json, text/plain, */*
Cache-Control: no-cache
x-auth: 2986ad8c0a5b3df4d7028d5f3c06e936c610137b9ea02010941d6474abf51823f17e04e48af784cbb979b6b59e1afbc2eca57c493d27da84c3302e01959c4cdb9
Referer: https://150.158.186.39:3443/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: ui_session=2986ad8c0a5b3df4d7028d5f3c06e936c610137b9ea02010941d6474abf51823f17e04e48af784cbb979b6b59e1afbc2eca57c493d27da84c3302e01959c4cdb9

{"profile_id":"11111111-1111-1111-1111-111111111117","ui_session_id":"d9b2b4b5b6d036102247630f643babb6","incremental":false,"schedule":{"disable":false,"start_date":null,"time_sensitive":false},"target_id":"b0194afd-7c76-42c2-a8fb-65482498fe46"}
```

## 返回包

```http
{
 "profile_id": "11111111-1111-1111-1111-111111111117",
 "schedule": {
  "disable": false,
  "start_date": null,
  "time_sensitive": false,
  "triggerable": false
 },
 "target_id": "b0194afd-7c76-42c2-a8fb-65482498fe46",
 "incremental": false,
 "max_scan_time": 0,
 "ui_session_id": null
}
```







