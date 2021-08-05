package burp.ui;

import burp.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class Tags extends AbstractTableModel implements ITab, IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;

    private String tagName;
    private JSplitPane mjSplitPane;
    private List<TablesData> Udatas = new ArrayList<TablesData>();
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;
    private Tags.URLTable Utable;
    private JScrollPane UscrollPane;
    private JSplitPane HjSplitPane;
    private JTabbedPane Ltable;
    private JTabbedPane Rtable;

    public Tags(IBurpExtenderCallbacks callbacks, String name) {
        this.callbacks = callbacks;
        this.tagName = name;

        // 创建用户界面
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // 主分隔面板
                mjSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // 任务栏面板
                Utable = new Tags.URLTable(Tags.this);
                UscrollPane = new JScrollPane(Utable);

                // 请求与响应界面的分隔面板规则
                HjSplitPane = new JSplitPane();
                HjSplitPane.setDividerLocation(0.5D);

                // 请求的面板
                Ltable = new JTabbedPane();
                HRequestTextEditor = Tags.this.callbacks.createMessageEditor(Tags.this, false);
                Ltable.addTab("Request", HRequestTextEditor.getComponent());

                // 响应的面板
                Rtable = new JTabbedPane();
                HResponseTextEditor = Tags.this.callbacks.createMessageEditor(Tags.this, false);
                Rtable.addTab("Response", HResponseTextEditor.getComponent());

                // 自定义程序UI组件
                HjSplitPane.add(Ltable, "left");
                HjSplitPane.add(Rtable, "right");

                mjSplitPane.add(UscrollPane, "left");
                mjSplitPane.add(HjSplitPane, "right");

                Tags.this.callbacks.customizeUiComponent(mjSplitPane);

                // 将自定义选项卡添加到Burp的UI
                Tags.this.callbacks.addSuiteTab(Tags.this);
            }
        });
    }

    @Override
    public String getTabCaption() {
        return this.tagName;
    }

    @Override
    public Component getUiComponent() {
        return mjSplitPane;
    }

    @Override
    public int getRowCount() {
        return this.Udatas.size();
    }

    @Override
    public int getColumnCount() {
        return 7;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "scannerName";
            case 2:
                return "url";
            case 3:
                return "statusCode";
            case 4:
                return "issue";
            case 5:
                return "startTime";
            case 6:
                return "endTime";
        }
        return null;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Tags.TablesData datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return datas.id;
            case 1:
                return datas.scannerName;
            case 2:
                return datas.url;
            case 3:
                return datas.statusCode;
            case 4:
                return datas.issue;
            case 5:
                return datas.startTime;
            case 6:
                return datas.endTime;
        }
        return null;
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    /**
     * 新增任务至任务栏面板
     */
    public int add(String scannerName, String url, String statusCode, String issue, IHttpRequestResponse requestResponse) {
        synchronized (this.Udatas) {
            Date d = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String startTime = sdf.format(d);

            int id = this.Udatas.size();
            this.Udatas.add(
                    new TablesData(
                            id,
                            scannerName,
                            url,
                            statusCode,
                            issue,
                            requestResponse,
                            startTime,
                            startTime
                    )
            );
            fireTableRowsInserted(id, id);
            return id;
        }
    }

    /**
     * 更新任务状态至任务栏面板，这里主要就是为了更新endTime
     */
    public int update(int id, String scannerName,  String url, String statusCode,
                      String issue, IHttpRequestResponse requestResponse) {
        Tags.TablesData dataEntry = Tags.this.Udatas.get(id);
        String startTime = dataEntry.startTime;

        Date d = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String endTime = sdf.format(d);

        synchronized (this.Udatas) {
            this.Udatas.set(
                    id,
                    new TablesData(
                            id,
                            scannerName,
                            url,
                            statusCode,
                            issue,
                            requestResponse,
                            startTime,
                            endTime
                    )
            );
            fireTableRowsUpdated(id, id);
            return id;
        }
    }

    /**
     * 自定义Table
     */
    public class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        /**
         *  changeSelection改变选中每个项目，随之展示对应的request和response数据包
         *  */
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            TablesData dataEntry = Tags.this.Udatas.get(convertRowIndexToModel(row));
            try {
                HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
                HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
                currentlyDisplayedItem = dataEntry.requestResponse;
            }catch (Exception ex){
                ex.printStackTrace();
            }finally {
                super.changeSelection(row, col, toggle, extend);
            }
        }
    }

    /**
     * 界面显示数据存储模块
     */
    public static class TablesData {
        final int id;
        final String scannerName;
        final String url;
        final String statusCode;
        final String issue;
        final IHttpRequestResponse requestResponse;
        final String startTime;
        final String endTime;

        public TablesData(int id, String scannerName, String url, String statusCode, String issue,IHttpRequestResponse requestResponse, String startTime, String endTime) {
            this.id = id;
            this.scannerName = scannerName;
            this.url = url;
            this.statusCode = statusCode;
            this.issue = issue;
            this.requestResponse = requestResponse;
            this.startTime = startTime;
            this.endTime = endTime;
        }
    }
}
