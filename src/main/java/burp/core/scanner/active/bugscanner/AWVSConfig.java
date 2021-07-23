package burp.core.scanner.active.bugscanner;

import burp.IBurpExtenderCallbacks;
import java.io.*;
import java.util.Properties;

/*
* 静态配置类
* */
public class AWVSConfig {
    public String getProxyServerAddr() {
        return proxyServerAddr;
    }

    public String getProxyServerPort() {
        return proxyServerPort;
    }

    public String getAwvsServerAddr() {
        return awvsServerAddr;
    }

    public String getAwvsAPIKey() {
        return awvsAPIKey;
    }

    public String getScanType() {
        return scanType;
    }

    public String getScanSpeed() {
        return scanSpeed;
    }

    public String getLimitCrawlerScope() {
        return limitCrawlerScope;
    }

    private String proxyServerAddr;
    private String proxyServerPort;
    private String awvsServerAddr;
    private String awvsAPIKey;
    private String scanType;
    private String scanSpeed;
    private String limitCrawlerScope;
    private PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;

    public AWVSConfig(IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.scanType = "11111111-1111-1111-1111-111111111117";
        this.configInit();
    }

    public void configInit(){
        InputStream in = null;
        try {
            in = new BufferedInputStream(new FileInputStream("db.properties"));
            Properties p = new Properties();
            p.load(in);
            this.proxyServerAddr = p.getProperty("proxyServerAddr");
            this.proxyServerPort = p.getProperty("proxyServerPort");
            this.awvsServerAddr = p.getProperty("awvsServerAddr");
            this.awvsAPIKey = p.getProperty("awvsAPIKey");
            this.scanSpeed = p.getProperty("scanSpeed");
            this.limitCrawlerScope = p.getProperty("limitCrawlerScope");
        } catch (FileNotFoundException e) {
            this.stdout.println("配置文件未找到，请检查配置文件db.properties是否存在！");
        } catch (IOException e) {
            this.stdout.println("配置文件相关IO错误，请检查！");
        }finally {
            try {
                assert in != null;
                in.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
