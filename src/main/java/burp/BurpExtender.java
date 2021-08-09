package burp;


import burp.core.scanner.active.bugscanner.AWVScanner;
import burp.core.scanner.active.jwtscanner.JWTLeakScanner;
import burp.core.scanner.active.shiroscanner.ShiroBypassScanner;
import burp.core.scanner.passive.*;
import burp.core.service.QueueDispatcherService;
import burp.ui.MultiTarget;
import burp.ui.Tags;
import burp.utils.BurpAnalyzedRequest;
import burp.utils.UrlRepeatMap;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, IScannerCheck{

    public static String NAME = "MyScanner";
    public static String VERSION = "1.0";
    public static IBurpExtenderCallbacks callbacks;
    public static Tags tags;
    public static QueueDispatcherService queueDispatcherService;
    public static UrlRepeatMap<String, Integer> urlRepeatMap;

    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    public BurpAnalyzedRequest burpAnalyzedRequest;
    /**
     * This method is invoked when the extension is loaded. It registers an
     * instance of the
     * <code>IBurpExtenderCallbacks</code> interface,d providing methods that may
     * be invoked by the extension to perform various actions.
     *
     * @param callbacks An
     *                  <code>IBurpExtenderCallbacks</code> object.
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 这些为了在其他地方进行调用，所以设置成为了静态属性
        BurpExtender.callbacks = callbacks;
        BurpExtender.callbacks.setExtensionName("MyScanner");
        BurpExtender.callbacks.registerContextMenuFactory(this);
        BurpExtender.tags = new Tags(callbacks, NAME);
        BurpExtender.urlRepeatMap = UrlRepeatMap.getUrlRepeatMap();

        // 下面的为成员属性
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.burpAnalyzedRequest = new BurpAnalyzedRequest();
        this.getBanner();
        this.initDispatcher();

        BurpExtender.callbacks.registerScannerCheck(this);
    }

    public void getBanner(){
        this.stdout.println(String.format("- %s plugin load success", NAME));
        this.stdout.println(String.format("- version %s", VERSION));
        this.stdout.println("- For bugs please on the official github: https://github.com/chibd2000/Burp-Extender-Study-Develop");
        this.stdout.println("- author: chibd2000");
        this.stdout.println("- github: https://github.com/chibd2000");
    }

    public void initDispatcher(){
        BurpExtender.queueDispatcherService = new QueueDispatcherService(BurpExtender.callbacks);
        BurpExtender.queueDispatcherService.init();
    }

    /**
     * This method will be called by Burp when the user invokes a context menu
     * anywhere within Burp. The factory can then provide any custom context
     * menu items that should be displayed in the context menu, based on the
     * details of the menu invocation.
     *
     * @param invocation An object that implements the
     *                   <code>IMessageEditorTabFactory</code> interface, which the extension can
     *                   query to obtain details of the context menu invocation.
     * @return A list of custom menu items (which may include sub-menus,
     * checkbox menu items, etc.) that should be displayed. Extensions may
     * return
     * <code>null</code> from this method, to indicate that no menu items are
     * required.
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> jMenuItemList = new ArrayList<>();
        JMenu scannerJMenu = new JMenu("Send To MyScanner");

        JMenuItem awvsScanner = new JMenuItem("awvsXrayScan");
        awvsScanner.addActionListener(new AWVScanner(BurpExtender.callbacks, invocation.getSelectedMessages()[0]));

        JMenuItem jwtScanner = new JMenuItem("JWTScan");
        jwtScanner.addActionListener(new JWTLeakScanner(BurpExtender.callbacks, invocation.getSelectedMessages()[0]));

        JMenuItem shiroScanner = new JMenuItem("ShiroPermissionScan");
        shiroScanner.addActionListener(new ShiroBypassScanner(BurpExtender.callbacks, invocation.getSelectedMessages()[0]));

        JMenuItem awvsMultiTaskDlg = new JMenuItem("AWVSMultiDlg");
        awvsMultiTaskDlg.addActionListener(new MultiTarget());

        scannerJMenu.add(awvsScanner);
        scannerJMenu.add(jwtScanner);
        scannerJMenu.add(shiroScanner);
        scannerJMenu.add(awvsMultiTaskDlg);
        jMenuItemList.add(scannerJMenu);
        return jMenuItemList;
    }

    /**
     * The Scanner invokes this method for each base request / response that is
     * passively scanned. <b>Note:</b> Extensions should only analyze the
     * HTTP messages provided during passive scanning, and should not make any
     * new HTTP requests of their own.
     *
     * @param baseRequestResponse The base HTTP request / response that should
     *                            be passively scanned.
     * @return A list of <code>IScanIssue</code> objects, or <code>null</code>
     * if no issues are identified.
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        BurpAnalyzedRequest burpAnalyzedRequest = new BurpAnalyzedRequest();
        String requestDomain = burpAnalyzedRequest.getRequestDomain(baseRequestResponse);
        IRequestInfo requestInfo = this.helpers.analyzeRequest(baseRequestResponse);
        String method = requestInfo.getMethod();
        // 判断URL的重复
        String requestUrl = this.burpAnalyzedRequest.getRequestDomain(baseRequestResponse)+
                this.burpAnalyzedRequest.getRequestURI(baseRequestResponse);
        String requestUrlRoot = requestUrl.endsWith("/") ? requestUrl : requestUrl.substring(0,requestUrl.lastIndexOf("/")+1);
        boolean check = BurpExtender.urlRepeatMap.check(requestUrlRoot);
        // 过滤没必要进行扫描的域名
        if (requestDomain.toLowerCase().contains("firefox")
                || requestDomain.toLowerCase().contains("mozilla")
                || requestDomain.toLowerCase().contains("google.com")
                || requestDomain.toLowerCase().contains("wappalyzer.com")
                || requestDomain.toLowerCase().contains("fofa.so")
                || requestDomain.toLowerCase().contains("shodan.io")
                || requestDomain.toLowerCase().contains("github.com")
                || check || !method.equals("GET")
        ) {
            return null;
        }
        BurpExtender.urlRepeatMap.add(requestUrl);
        List<IPassiveScanner> passiveScannerList = new ArrayList<>();
        passiveScannerList.add(new ActuatorLeakScanner(BurpExtender.callbacks, baseRequestResponse));
        passiveScannerList.add(new BackupLeakScanner(BurpExtender.callbacks, baseRequestResponse));
        passiveScannerList.add(new GitLeakScanner(BurpExtender.callbacks, baseRequestResponse));
        passiveScannerList.add(new SVNLeakScanner(BurpExtender.callbacks, baseRequestResponse));
        passiveScannerList.add(new SwaggerLeakScanner(BurpExtender.callbacks, baseRequestResponse));
        passiveScannerList.add(new WsdlLeakScanner(BurpExtender.callbacks, baseRequestResponse));
        BurpExtender.queueDispatcherService.addData(passiveScannerList);
        return null;
    }

    /**
     * The Scanner invokes this method for each insertion point that is actively
     * scanned. Extensions may issue HTTP requests as required to carry out
     * active scanning, and should use the
     * <code>IScannerInsertionPoint</code> object provided to build scan
     * requests for particular payloads.
     * <b>Note:</b>
     * Scan checks should submit raw non-encoded payloads to insertion points,
     * and the insertion point has responsibility for performing any data
     * encoding that is necessary given the nature and location of the insertion
     * point.
     *
     * @param baseRequestResponse The base HTTP request / response that should
     *                            be actively scanned.
     * @param insertionPoint      An <code>IScannerInsertionPoint</code> object that
     *                            can be queried to obtain details of the insertion point being tested, and
     *                            can be used to build scan requests for particular payloads.
     * @return A list of <code>IScanIssue</code> objects, or <code>null</code>
     * if no issues are identified.
     */
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    /**
     * The Scanner invokes this method when the custom Scanner check has
     * reported multiple issues for the same URL path. This can arise either
     * because there are multiple distinct vulnerabilities, or because the same
     * (or a similar) request has been scanned more than once. The custom check
     * should determine whether the issues are duplicates. In most cases, where
     * a check uses distinct issue names or descriptions for distinct issues,
     * the consolidation process will simply be a matter of comparing these
     * features for the two issues.
     *
     * @param existingIssue An issue that was previously reported by this
     *                      Scanner check.
     * @param newIssue      An issue at the same URL path that has been newly
     *                      reported by this Scanner check.
     * @return An indication of which issue(s) should be reported in the main
     * Scanner results. The method should return <code>-1</code> to report the
     * existing issue only, <code>0</code> to report both issues, and
     * <code>1</code> to report the new issue only.
     */
    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
