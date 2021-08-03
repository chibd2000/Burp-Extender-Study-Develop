package burp.core.scanner.active.bugscanner;

import burp.*;
import burp.core.scanner.active.BaseActiveScanner;
import burp.core.scanner.active.IActiveScanner;
import burp.utils.BurpAnalyzedRequest;
import burp.utils.HttpClientWrapper;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/*
* 控制类
* */
public class AWVScanner extends BaseActiveScanner implements ActionListener, Runnable, IActiveScanner {
    public HttpClientWrapper httpClientWrapper;
    public AWVSTask awvsTask;
    public Map<String, String> headers = new HashMap<>();

    public AWVScanner(IBurpExtenderCallbacks callbacks, IHttpRequestResponse httpRequestResponse){
        super("AWVXrayScanner");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.httpRequestResponse = httpRequestResponse;
        this.httpClientWrapper = new HttpClientWrapper();
        this.burpAnalyzedRequest = new BurpAnalyzedRequest();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
    }

    public void initTargetInfor(){
        String targetUrl = this.burpAnalyzedRequest.getRequestDomain(this.httpRequestResponse);
        List<String> cookieList = this.burpAnalyzedRequest.getCookies(this.httpRequestResponse);
        List<String> headerList = this.burpAnalyzedRequest.getCustomHeaders(this.httpRequestResponse);
//        this.stdout.println(cookieList.toString());
//        this.stdout.println(headerList.toString());
        this.awvsTask = new AWVSTask(this.callbacks, targetUrl, cookieList.toString(), headerList.toString());
        this.headers = new HashMap<String, String>();
        headers.put("X-Auth", awvsTask.AWVSConfig.getAwvsAPIKey());
        headers.put("Content-Type", "application/json");
    }

    public boolean addTask() {
        String addTaskJsonString = this.awvsTask.getAddTaskJsonString();
        this.stdout.println(this.awvsTask.AWVSConfig.getAwvsServerAddr() + "/api/v1/targets/add");
//        this.stdout.println(addTaskJsonString);
        String s = this.httpClientWrapper.doPostJson(this.awvsTask.AWVSConfig.getAwvsServerAddr() + "/api/v1/targets/add", addTaskJsonString, this.headers);
        JSONObject jsonObject = JSON.parseObject(s);
        JSONArray targets1 = jsonObject.getJSONArray("targets");
        JSONObject o = (JSONObject) targets1.get(0);
        String targetId = (String) o.get("target_id");
        if (targetId != null){
            this.awvsTask.setTargetId(targetId);
            return true;
        }else{
            return false;
        }
    }

    public int configureTask() {
        String configureTaskJsonString = this.awvsTask.getConfigureTaskJsonString();
        this.stdout.println(this.awvsTask.AWVSConfig.getAwvsServerAddr() + "/api/v1/targets/" + this.awvsTask.getTargetId() + "/configuration");
        this.stdout.println(configureTaskJsonString);
        return this.httpClientWrapper.doPatchJson(this.awvsTask.AWVSConfig.getAwvsServerAddr() + "/api/v1/targets/"
                + this.awvsTask.getTargetId() + "/configuration", configureTaskJsonString, this.headers);
    }

    public boolean startTask() {
        String startTaskJsonString = this.awvsTask.getStartTaskJsonString();
        this.stdout.println(this.awvsTask.AWVSConfig.getAwvsServerAddr() + "/api/v1/scans");
//        this.stdout.println(startTaskJsonString);
        String s = this.httpClientWrapper.doPostJson(awvsTask.AWVSConfig.getAwvsServerAddr() + "/api/v1/scans", startTaskJsonString, this.headers);
        return s.contains("profile_id") && s.contains("target_id");
    }


    /**
     * Invoked when an action occurs.
     *
     * @param e
     */
    @Override
    public void actionPerformed(ActionEvent e) {
        new Thread(this).start();
    }

    /**
     * When an object implementing interface <code>Runnable</code> is used
     * to create a thread, starting the thread causes the object's
     * <code>run</code> method to be called in that separately executing
     * thread.
     * <p>
     * The general contract of the method <code>run</code> is that it may
     * take any action whatsoever.
     *
     * @see Thread#run()
     */
    @Override
    public void run() {
        // 刷新当前新的任务
        this.initTargetInfor();

        // 添加当前新的任务，返回的为targetId
        int addId;
        boolean a = this.addTask();
        if (a){
            addId = BurpExtender.tags.add(this.scannerName, this.awvsTask.getTargetUrl(), "200", "[-] waiting for results", null);
        }else{
            BurpExtender.tags.add(this.scannerName, this.awvsTask.getTargetUrl(), "500", "[-] add task fail", null);
            return;
        }

        try {
            Thread.sleep(2000);
        } catch (InterruptedException ex) {
            throw new RuntimeException(ex);
        }

        int httpStatusCode = this.configureTask();

        if (httpStatusCode == 500){
            BurpExtender.tags.update(addId, this.scannerName, this.awvsTask.getTargetUrl(), "500", "[-] configure task fail", null);
            return;
        }

        try {
            Thread.sleep(2000);
        } catch (InterruptedException ex) {
            throw new RuntimeException(ex);
        }

        boolean c = this.startTask();
        if (c){
            BurpExtender.tags.update(addId, this.scannerName, this.awvsTask.getTargetUrl(), "200", "[+] start task success",null);
        }else{
            BurpExtender.tags.update(addId, this.scannerName, this.awvsTask.getTargetUrl(), "500", "[-] start task fail",null);
        }
    }

    @Override
    public List<String> getPayload() {
        return null;
    }

    @Override
    public List<IHttpRequestResponse> sendPayload() {
        return null;
    }
}
