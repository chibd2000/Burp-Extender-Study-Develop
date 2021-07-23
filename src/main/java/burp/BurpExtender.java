package burp;


import burp.core.scanner.active.bugscanner.AWVScanner;
import burp.core.scanner.active.jwtscanner.JWTNoneScanner;
import burp.core.scanner.active.shiroscanner.SHIROScanner;
import burp.ui.AwvsMultiTaskDlg;
import burp.ui.Tags;
import burp.utils.DomainNameRepeat;

import javax.swing.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IContextMenuFactory{

    public static String NAME = "AWVXrayScanner";
    public static String VERSION = "1.0";
    public static IBurpExtenderCallbacks callbacks;
    public static Tags tags;

    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    public DomainNameRepeat<String, Integer> domainNameRepeat;

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
        this.callbacks = callbacks;
        this.callbacks.setExtensionName("AWVXrayScanner");
        this.callbacks.registerContextMenuFactory(this);
        this.tags = new Tags(callbacks, NAME);

        // 下面的为成员属性
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.getBanner();
        this.domainNameRepeat = DomainNameRepeat.getDomainNameMap();

    }

    public void getBanner(){
        this.stdout.println("===================================");
        this.stdout.println(String.format("%s 插件加载成功", NAME));
        this.stdout.println(String.format("版本: %s", VERSION));
        this.stdout.println("author: chibd2000");
        this.stdout.println("github: https://github.com/chibd2000");
        this.stdout.println("===================================");
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

        JMenu bugScanner = new JMenu("Send To AWVXrayScanner");

        JMenuItem awvsScanner = new JMenuItem("awvsScanner");
        awvsScanner.addActionListener(new AWVScanner(this.callbacks, invocation.getSelectedMessages()[0]));
        bugScanner.add(awvsScanner);

        JMenuItem jwtScanner = new JMenuItem("jwtScanner");
        jwtScanner.addActionListener(new JWTNoneScanner(this.callbacks, invocation.getSelectedMessages()[0]));
        bugScanner.add(jwtScanner);

        JMenuItem shiroScanner = new JMenuItem("shiroScanner");
        shiroScanner.addActionListener(new SHIROScanner(this.callbacks, invocation.getSelectedMessages()[0]));
        bugScanner.add(shiroScanner);

        JMenuItem awvsMultiTaskDlg = new JMenuItem("awvsMultiDlg");
        awvsMultiTaskDlg.addActionListener(new AwvsMultiTaskDlg());
        bugScanner.add(awvsMultiTaskDlg);

        jMenuItemList.add(bugScanner);
        return jMenuItemList;
    }

}
