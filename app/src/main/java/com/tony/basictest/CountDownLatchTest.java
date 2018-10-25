package com.tony.basictest;

import java.util.concurrent.CountDownLatch;

/**
 * Created by Tony
 * 2018/10/25
 * email: chong.z@verifone.cn
 */
public class CountDownLatchTest {



    public void testCountDownLatch() {
        //CountDownLatch countDown = new CountDownLatch(1);
        CountDownLatch await = new CountDownLatch(1);

        // 依次创建并启动处于等待状态的5个MyRunnable线程
//        for (int i = 0; i < 5; ++i) {
//            new Thread(new MyRunnable(countDown, await)).start();
//        }

        new Thread(new MyRunnable(await)).start();
        System.out.println("开始等待");
        //countDown.countDown();
        try {
            await.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.out.println("Bingo!");
    }

    private class MyRunnable implements Runnable {

        private CountDownLatch countDown = null;
        private final CountDownLatch await;

        private MyRunnable(CountDownLatch countDown, CountDownLatch await) {
            this.countDown = countDown;
            this.await = await;
        }

        private MyRunnable(CountDownLatch await) {
            this.await = await;
        }

        public void run() {
            System.out.println("开始处理费时工作");
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println("费时工作处理完");
            await.countDown();//完成预期工作，发出完成信号...
        }

/*        public void run() {
            try {
                countDown.await();//等待主线程执行完毕，获得开始执行信号...
                System.out.println("处于等待的线程开始自己预期工作......");
                await.countDown();//完成预期工作，发出完成信号...
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }*/
    }
}
