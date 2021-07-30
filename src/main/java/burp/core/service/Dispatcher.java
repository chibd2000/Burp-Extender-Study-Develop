package burp.core.service;

import java.util.Queue;

class Dispatcher implements Runnable{
    public Queue<Object> taskQueue;

    public Dispatcher(){

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
        // 循环存储要执行的任务，
        while (true){
            if (taskQueue.isEmpty()){

                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {

                }
            }
        }
    }
}
