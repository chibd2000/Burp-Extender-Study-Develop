package burp.core.service;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.core.scanner.BaseScanner;
import burp.core.scanner.active.IActiveScanner;
import burp.core.scanner.passive.IPassiveScanner;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.PrintWriter;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;

public class QueueDispatcherService{
    // LinkedBlockingQueue 构造的时候若没有指定大小，则默认大小为Integer.MAX_VALUE
    private final LinkedBlockingQueue<List<IPassiveScanner>> tasks = new LinkedBlockingQueue<>();

    // 类似于一个线程总管 保证所有的任务都在队列之中
    private ExecutorService service = Executors.newSingleThreadExecutor();

    // 检查服务是否运行
    private volatile boolean running = true;

    //线程状态
    private Future<?> serviceThreadStatus = null;

    //burp
    public IBurpExtenderCallbacks callbacks;
    public PrintWriter stdout;


    public QueueDispatcherService(IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
    }

    @PostConstruct
    public void init() {
        serviceThreadStatus = service.submit(new Thread(new Runnable() {
            @Override
            public void run() {
                while (running) {
                    try {
                        //取出任务来进行执行
                        List<IPassiveScanner> task = tasks.take();
                        try {
                            for (IPassiveScanner iPassiveScanner : task) {
                                iPassiveScanner.run();
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                        running = false;
                    }
                }
            }
        }));
    }

    public boolean addData(List<IPassiveScanner> scanner) {
        if (!running) {
            this.stdout.println("Dispatcher停止运行...");
            return false;
        }

        // 添加任务
        boolean success = tasks.offer(scanner);

        //offer 队列已经满了，无法再加入的情况下
        if (!success) {
            this.stdout.println("添加任务失败...");
        }

        return success;
    }
    
    //判断队列是否有任务   
    public boolean isEmpty() {
        return tasks.isEmpty();
    }

    public boolean checkServiceRun() {
        return running && !service.isShutdown() && !serviceThreadStatus.isDone();
    }

    public void activeService() {
        running = true;
        if (service.isShutdown()) {
            service = Executors.newSingleThreadExecutor();
            init();
        }
        if (serviceThreadStatus.isDone()) {
            init();
        }
    }

    @PreDestroy
    public void destory() {
        running = false;
        service.shutdownNow();
    }
}
