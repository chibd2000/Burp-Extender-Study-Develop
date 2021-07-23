package burp.core.scanner.active.bugscanner;

import burp.IBurpExtenderCallbacks;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.io.PrintWriter;

/*
* 动态配置类
* */
public class AWVSTask {
    public IBurpExtenderCallbacks callbacks;
    public PrintWriter stdout;
    public AWVSConfig AWVSConfig;

    private String targetUrl;
    private String targetCookie;

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public String getTargetCookie() {
        return targetCookie;
    }

    public void setTargetCookie(String targetCookie) {
        this.targetCookie = targetCookie;
    }

    private String targetId;

    public AWVSTask(IBurpExtenderCallbacks callbacks, String targetUrl, String targetCookie){
        this.callbacks = callbacks;
        this.targetUrl = targetUrl;
        this.targetCookie = targetCookie;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.AWVSConfig = new AWVSConfig(callbacks);
    }

    public void setTargetId(String targetId) {
        this.targetId = targetId;
    }
    public String getTargetId() {
        return targetId;
    }

    public String getAddTaskJsonString(){
        JSONObject taskObject = new JSONObject();
        JSONObject targetsObject = new JSONObject();
        targetsObject.put("address", this.targetUrl);
        targetsObject.put("description", "burp-add");
        JSONArray targetsArray = new JSONArray();
        targetsArray.add(targetsObject);
        taskObject.put("targets", targetsArray);
        JSONArray nullArray = new JSONArray();
        taskObject.put("groups", nullArray);
        return taskObject.toJSONString();
    }

    public String getConfigureTaskJsonString(){

        return "{\"scan_speed\":\""+ this.AWVSConfig.getScanSpeed() +"\"," +
                "\"login\":{\"kind\":\"none\"}," +
                "\"ssh_credentials\":{\"kind\":\"none\"}," +
                "\"default_scanning_profile_id\":\"" + this.AWVSConfig.getScanType() + "\"," +
                "\"sensor\":false," +
                "\"user_agent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4298.0 Safari/537.36\"," +
                "\"case_sensitive\":\"no\"," +
                "\"limit_crawler_scope\":" + this.AWVSConfig.getLimitCrawlerScope() +"," +
                "\"excluded_paths\":[]," +
                "\"authentication\":{\"enabled\":false}," +
                "\"proxy\":{\"enabled\":true," +
                "\"protocol\":\"http\"," +
                "\"address\":\"" + this.AWVSConfig.getProxyServerAddr() + "\"," +
                "\"port\":\""+ this.AWVSConfig.getProxyServerPort() + "\"}," +
                "\"technologies\":[]," +
                "\"custom_headers\":[],\"custom_cookies\":[]," +
                "\"debug\":false," +
                "\"restrict_scans_to_import_files\":false," +
                "\"client_certificate_password\":\"\"," +
                "\"client_certificate_url\":null," +
                "\"issue_tracker_id\":\"\"," +
                "\"excluded_hours_id\":null," +
                "\"preseed_mode\":\"\"}";
    }

    public String getStartTaskJsonString(){
        return "{\"target_id\": \"" + this.targetId +"\", \"profile_id\": \""+ this.AWVSConfig.getScanType() + "\", \"incremental\": false, " +
                "\"schedule\": {\"disable\": false, \"start_date\": null, \"time_sensitive\": false}}";
    }
}
